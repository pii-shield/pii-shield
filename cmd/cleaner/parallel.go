package main

import (
	"io"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Line sharding (proof of concept, off by default; see
// docs/poc-line-sharding.md). The scanner works on one line at a time and
// keeps nothing between lines, so lines can be sanitized on several cores as
// long as they are written out in the order they were read.
//
// With PII_WORKERS above 1 the reader hands lines to a parallelSanitizer
// instead of sanitizing them itself. Lines are grouped into batches; each
// batch goes to two queues at once: `work`, from which the workers take
// batches in any order, and `ordered`, from which a single writer takes them
// in the order they were read and waits for each one to be rendered. Both
// queues are bounded, so a reader that is faster than the workers blocks
// instead of filling memory.
//
// A batch is sent as soon as a worker is free, so a quiet stream moves one
// line at a time with no added delay. While every worker is busy the batch
// grows, up to maxBatchLines or maxBatchBytes, which keeps the per-line cost
// of the queues low exactly when throughput matters. A batch left waiting
// when the input pauses is sent by a timer after batchLinger.

const (
	maxBatchLines = 256
	maxBatchBytes = 64 * 1024
	// batchLinger bounds how long a line may wait for its batch to fill
	// while every worker is busy.
	batchLinger = 5 * time.Millisecond
	// queuedBatchesPerWorker sizes the two queues; with maxBatchBytes it
	// bounds the lines held in memory.
	queuedBatchesPerWorker = 4
	// maxPooledOutput keeps a batch buffer grown by one huge line from
	// staying in the pool.
	maxPooledOutput = 1024 * 1024
	maxWorkers      = 256
)

// parseWorkers reads PII_WORKERS: empty is 1 (lines are sanitized one at a
// time by the reader, as before), "auto" is one worker per available CPU,
// anything else is a count. ok is false for a value that could not be read,
// and 1 is returned with it.
func parseWorkers(raw string) (int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 1, true
	}
	if strings.EqualFold(raw, "auto") {
		return runtime.GOMAXPROCS(0), true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 1, false
	}
	return min(n, maxWorkers), true
}

// lineBatch is a run of consecutive input lines and, once a worker is done
// with it, the bytes to write for them.
type lineBatch struct {
	lines []string
	size  int    // bytes in lines
	out   []byte // sanitized lines, each with its newline
	flush bool   // a stream marker is inside: push dst out after writing
	// done carries the worker's "rendered" signal to the writer. It has room
	// for one signal so the batch can go back to the pool and be used again.
	done chan struct{}
	// ack is set only on a barrier, a batch with no lines that drain puts in
	// the ordered queue; the writer closes it when it gets there.
	ack chan struct{}
}

// parallelSanitizer sanitizes lines on several goroutines and writes the
// result to dst in input order. It is passed to the read loops in place of
// the output writer: processLine hands it the line, and a stream marker
// written to it (Write, then Flush) waits for the lines before it, so the
// marker lands where it would have with one line at a time.
//
// submit, Write and Flush must come from one goroutine, the reader. Close
// may come from another (the signal handler).
type parallelSanitizer struct {
	dst            io.Writer
	metricsEnabled bool
	failPolicy     string
	workers        int

	mu     sync.Mutex // guards cur and closed, and orders sends on the queues
	cur    *lineBatch // the batch being filled, nil when empty
	closed bool
	linger *time.Timer

	work     chan *lineBatch
	ordered  chan *lineBatch
	inFlight atomic.Int32 // batches sent and not yet rendered
	pool     sync.Pool

	writerDone chan struct{}
}

func newParallelSanitizer(dst io.Writer, workers int, metricsEnabled bool, failPolicy string) *parallelSanitizer {
	queue := workers * queuedBatchesPerWorker
	p := &parallelSanitizer{
		dst:            dst,
		metricsEnabled: metricsEnabled,
		failPolicy:     failPolicy,
		workers:        workers,
		work:           make(chan *lineBatch, queue),
		ordered:        make(chan *lineBatch, queue),
		writerDone:     make(chan struct{}),
	}
	p.pool.New = func() any {
		return &lineBatch{done: make(chan struct{}, 1)}
	}
	p.linger = time.AfterFunc(time.Hour, p.sendPending)
	p.linger.Stop()
	for range workers {
		go p.workLoop()
	}
	go p.writeLoop()
	return p
}

// submit queues one input line.
func (p *parallelSanitizer) submit(text string) {
	p.mu.Lock()
	if p.closed {
		// The process is shutting down. Wait for the queued lines, then
		// sanitize this one in place, so it is still written after them.
		p.mu.Unlock()
		<-p.writerDone
		processLine(text, p.metricsEnabled, p.failPolicy, p.dst)
		return
	}
	if p.cur == nil {
		p.cur = p.pool.Get().(*lineBatch)
	}
	b := p.cur
	b.lines = append(b.lines, text)
	b.size += len(text)
	switch {
	case len(b.lines) >= maxBatchLines, b.size >= maxBatchBytes, int(p.inFlight.Load()) < p.workers:
		p.sendLocked()
	case len(b.lines) == 1:
		p.linger.Reset(batchLinger)
	}
	p.mu.Unlock()
}

// sendLocked puts the current batch in both queues. The sends block while the
// queues are full, which is the back-pressure on the reader; the workers and
// the writer never take mu, so they always make room.
func (p *parallelSanitizer) sendLocked() {
	b := p.cur
	if b == nil {
		return
	}
	p.cur = nil
	p.inFlight.Add(1)
	p.ordered <- b
	p.work <- b
}

// sendPending is the linger timer: it sends a batch that did not fill.
func (p *parallelSanitizer) sendPending() {
	p.mu.Lock()
	if !p.closed {
		p.sendLocked()
	}
	p.mu.Unlock()
}

func (p *parallelSanitizer) workLoop() {
	for b := range p.work {
		for _, text := range b.lines {
			line, marker := sanitizeLine(text, p.metricsEnabled, p.failPolicy)
			b.out = append(b.out, line...)
			b.out = append(b.out, '\n')
			if marker {
				b.flush = true
			}
		}
		p.inFlight.Add(-1)
		b.done <- struct{}{}
	}
}

func (p *parallelSanitizer) writeLoop() {
	defer close(p.writerDone)
	for b := range p.ordered {
		if b.ack != nil {
			close(b.ack)
			continue
		}
		<-b.done
		_, _ = p.dst.Write(b.out)
		if b.flush {
			if f, ok := p.dst.(flusher); ok {
				_ = f.Flush()
			}
		}
		p.recycle(b)
	}
}

func (p *parallelSanitizer) recycle(b *lineBatch) {
	clear(b.lines) // drop the references to the input lines
	b.lines = b.lines[:0]
	b.size = 0
	b.flush = false
	if cap(b.out) > maxPooledOutput {
		b.out = nil
	} else {
		b.out = b.out[:0]
	}
	p.pool.Put(b)
}

// drain returns when every line submitted so far has been written to dst.
func (p *parallelSanitizer) drain() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		<-p.writerDone
		return
	}
	p.sendLocked()
	ack := make(chan struct{})
	p.ordered <- &lineBatch{ack: ack}
	p.mu.Unlock()
	<-ack
}

// Write writes raw bytes (a stream marker) to dst after the lines submitted
// before it.
func (p *parallelSanitizer) Write(b []byte) (int, error) {
	p.drain()
	return p.dst.Write(b)
}

// Flush waits for the lines submitted so far and pushes dst out.
func (p *parallelSanitizer) Flush() error {
	p.drain()
	if f, ok := p.dst.(flusher); ok {
		return f.Flush()
	}
	return nil
}

// Close writes out every line submitted so far and stops the workers. It
// does not close dst. A line submitted after Close is sanitized by the
// caller. Close is safe to call more than once.
func (p *parallelSanitizer) Close() {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.linger.Stop()
		p.sendLocked()
		close(p.work)
		close(p.ordered)
	}
	p.mu.Unlock()
	<-p.writerDone
}
