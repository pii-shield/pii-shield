// Package stream turns the writes the probe copies out of the kernel back
// into log lines. A process writes a line in one write() most of the
// time, but not always: a runtime may split a long line, join several, or
// hand a writev a line in pieces, so the bytes of each (process, fd) pair
// are kept until a newline closes a line.
package stream

import (
	"bytes"
	"time"
)

// Key names one output stream: a process and one of its descriptors.
type Key struct {
	Tgid uint32
	FD   uint32
}

type pending struct {
	buf  []byte
	seen time.Time
}

// Assembler joins writes into lines. It is not safe for concurrent use;
// the agent feeds it from the one goroutine that reads the ring buffer.
type Assembler struct {
	// MaxLine caps the bytes kept for one stream without a newline. When
	// it is reached the buffer is emitted as a line and Overflows counts
	// it, so a process that never writes a newline cannot grow the agent.
	MaxLine int
	// OnLine receives every completed line, without its newline.
	OnLine func(line string)

	// Overflows counts buffers emitted because they reached MaxLine.
	Overflows uint64

	streams map[Key]*pending
}

// DefaultMaxLine matches the sidecar's line buffer limit.
const DefaultMaxLine = 1 << 20

// New returns an Assembler delivering lines to onLine.
func New(onLine func(string)) *Assembler {
	return &Assembler{MaxLine: DefaultMaxLine, OnLine: onLine, streams: map[Key]*pending{}}
}

// Push adds one write and emits every line it completes. A write that
// ends in a newline and finds no pending bytes is passed on without a
// copy, which is the common case.
func (a *Assembler) Push(k Key, data []byte, now time.Time) {
	p := a.streams[k]
	if p == nil || len(p.buf) == 0 {
		// Fast path: whole lines, nothing pending.
		for len(data) > 0 {
			i := bytes.IndexByte(data, '\n')
			if i < 0 {
				break
			}
			a.OnLine(string(data[:i]))
			data = data[i+1:]
		}
		if len(data) == 0 {
			return
		}
		if p == nil {
			p = &pending{}
			a.streams[k] = p
		}
	}
	p.seen = now
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			p.buf = append(p.buf, data...)
			break
		}
		p.buf = append(p.buf, data[:i]...)
		a.OnLine(string(p.buf))
		p.buf = p.buf[:0]
		data = data[i+1:]
	}
	if len(p.buf) >= a.MaxLine {
		a.Overflows++
		a.OnLine(string(p.buf))
		p.buf = p.buf[:0]
	}
	if len(p.buf) == 0 {
		delete(a.streams, k)
	}
}

// FlushIdle emits the pending bytes of every stream that has not been
// written to for idle, as a line: a process that writes a prompt or a
// final line without a newline is still counted, and a process that
// exited leaves nothing behind.
func (a *Assembler) FlushIdle(now time.Time, idle time.Duration) {
	for k, p := range a.streams {
		if now.Sub(p.seen) >= idle {
			if len(p.buf) > 0 {
				a.OnLine(string(p.buf))
			}
			delete(a.streams, k)
		}
	}
}

// Pending is the number of streams holding an unfinished line.
func (a *Assembler) Pending() int { return len(a.streams) }
