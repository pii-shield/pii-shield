package stream

import (
	"strings"
	"testing"
	"time"
)

func collect() (*Assembler, *[]string) {
	var lines []string
	a := New(func(l string) { lines = append(lines, l) })
	return a, &lines
}

func TestWholeLinesPassStraightThrough(t *testing.T) {
	a, lines := collect()
	now := time.Now()
	a.Push(Key{1, 1}, []byte("one\ntwo\n"), now)
	a.Push(Key{1, 2}, []byte("err\n"), now)
	if got := strings.Join(*lines, "|"); got != "one|two|err" {
		t.Errorf("lines = %q", got)
	}
	if a.Pending() != 0 {
		t.Errorf("pending streams = %d, want 0", a.Pending())
	}
}

func TestSplitWritesAreJoinedPerStream(t *testing.T) {
	a, lines := collect()
	now := time.Now()
	a.Push(Key{1, 1}, []byte("pass"), now)
	a.Push(Key{2, 1}, []byte("other process\n"), now)
	a.Push(Key{1, 2}, []byte("stderr half"), now)
	a.Push(Key{1, 1}, []byte("word=hunter2\nnext"), now)
	a.Push(Key{1, 2}, []byte(" done\n"), now)
	if got := strings.Join(*lines, "|"); got != "other process|password=hunter2|stderr half done" {
		t.Errorf("lines = %q", got)
	}
	if a.Pending() != 1 {
		t.Errorf("pending streams = %d, want 1 (the 'next' of pid 1 fd 1)", a.Pending())
	}
	a.Push(Key{1, 1}, []byte("\n"), now)
	if (*lines)[len(*lines)-1] != "next" || a.Pending() != 0 {
		t.Errorf("after the newline: last = %q, pending = %d", (*lines)[len(*lines)-1], a.Pending())
	}
}

func TestMaxLineEmitsAndCounts(t *testing.T) {
	a, lines := collect()
	a.MaxLine = 16
	now := time.Now()
	a.Push(Key{1, 1}, []byte("0123456789"), now)
	a.Push(Key{1, 1}, []byte("abcdef"), now) // reaches 16 without a newline
	if len(*lines) != 1 || (*lines)[0] != "0123456789abcdef" || a.Overflows != 1 {
		t.Errorf("lines = %q, overflows = %d", *lines, a.Overflows)
	}
	if a.Pending() != 0 {
		t.Errorf("pending = %d after an overflow, want 0", a.Pending())
	}
	// A single oversized write with no newline is emitted at once.
	a.Push(Key{1, 1}, []byte(strings.Repeat("x", 40)), now)
	if len(*lines) != 2 || a.Overflows != 2 {
		t.Errorf("lines = %d, overflows = %d", len(*lines), a.Overflows)
	}
}

func TestFlushIdleCountsUnfinishedLines(t *testing.T) {
	a, lines := collect()
	t0 := time.Now()
	a.Push(Key{1, 1}, []byte("no newline yet"), t0)
	a.Push(Key{2, 1}, []byte("fresh"), t0.Add(time.Second))
	a.FlushIdle(t0.Add(2*time.Second), 2*time.Second)
	if got := strings.Join(*lines, "|"); got != "no newline yet" {
		t.Errorf("flushed = %q, want only the idle stream", got)
	}
	if a.Pending() != 1 {
		t.Errorf("pending = %d, want the fresh stream kept", a.Pending())
	}
	a.FlushIdle(t0.Add(time.Hour), 2*time.Second)
	if (*lines)[len(*lines)-1] != "fresh" || a.Pending() != 0 {
		t.Errorf("second flush: %q, pending %d", *lines, a.Pending())
	}
}

func TestEmptyWriteChangesNothing(t *testing.T) {
	a, lines := collect()
	a.Push(Key{1, 1}, nil, time.Now())
	a.Push(Key{1, 1}, []byte(""), time.Now())
	if len(*lines) != 0 || a.Pending() != 0 {
		t.Errorf("lines = %q, pending = %d", *lines, a.Pending())
	}
}
