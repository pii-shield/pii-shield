package main

import (
	"bufio"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	// defaultFlushInterval bounds how long a sanitized line may sit in the
	// output buffer before it is written out.
	defaultFlushInterval = 50 * time.Millisecond
	outputBufferSize     = 64 * 1024
)

// outputWriter is the sanitized stream's writer. processLine used to write
// every line with its own fmt.Fprintln on os.Stdout, one write(2) per line,
// which was 12-25% of the CLI's wall time (AG-2026-10-24-02). Lines now go
// through a 64 KiB buffer that is flushed when full, every interval by a
// timer, by Flush (a stream marker calls it, so a DROP/WARN reaches the
// reader at once) and by Close on every shutdown path. After Close the
// writer passes every write straight through, so a line sanitized while
// the process is draining (the metrics server has a shutdown grace) is
// never left behind in a buffer when os.Exit runs. An interval of zero
// disables the buffer: every write goes to dst as before.
type outputWriter struct {
	mu     sync.Mutex
	dst    io.Writer
	buf    *bufio.Writer // nil when unbuffered
	closed bool
	stop   chan struct{}
	done   chan struct{}
}

func newOutputWriter(dst io.Writer, interval time.Duration) *outputWriter {
	o := &outputWriter{dst: dst}
	if interval <= 0 {
		return o
	}
	o.buf = bufio.NewWriterSize(dst, outputBufferSize)
	o.stop = make(chan struct{})
	o.done = make(chan struct{})
	go o.run(interval)
	return o
}

func (o *outputWriter) run(interval time.Duration) {
	defer close(o.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = o.Flush()
		case <-o.stop:
			return
		}
	}
}

func (o *outputWriter) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.buf == nil || o.closed {
		return o.dst.Write(p)
	}
	return o.buf.Write(p)
}

// Flush writes out whatever is buffered.
func (o *outputWriter) Flush() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.flushLocked()
}

func (o *outputWriter) flushLocked() error {
	if o.buf == nil || o.buf.Buffered() == 0 {
		return nil
	}
	return o.buf.Flush()
}

// Close flushes, stops the timer and switches the writer to write-through.
// It is safe to call more than once.
func (o *outputWriter) Close() error {
	o.mu.Lock()
	err := o.flushLocked()
	wasClosed := o.closed
	o.closed = true
	o.mu.Unlock()
	if o.buf != nil && !wasClosed {
		close(o.stop)
		<-o.done
	}
	return err
}

// parseFlushInterval reads PII_OUTPUT_FLUSH_INTERVAL: empty is the default,
// "0" turns the buffer off, anything else is a Go duration. ok is false for
// a value that could not be read, and the default is returned with it.
func parseFlushInterval(raw string) (time.Duration, bool) {
	if raw == "" {
		return defaultFlushInterval, true
	}
	if raw == "0" {
		return 0, true
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		return defaultFlushInterval, false
	}
	return d, true
}

type flusher interface {
	Flush() error
}

// writeMarker writes a stream marker ([PII_SHIELD_DROP: …], [PII_SHIELD_WARN:
// …]) and pushes it out at once when out buffers, so the reader learns of a
// dropped line or a broken stream without waiting for the flush timer.
func writeMarker(out io.Writer, marker string) {
	_, _ = fmt.Fprintln(out, marker)
	if f, ok := out.(flusher); ok {
		_ = f.Flush()
	}
}
