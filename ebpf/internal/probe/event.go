// Package probe loads the eBPF program of the audit agent and reads the
// writes it copies out of the kernel. The loader (probe_linux.go) and the
// bpf2go output build on Linux only; this file is the part every platform
// shares, so the record layout can be tested anywhere.
package probe

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// HeaderSize is the fixed part of a ring buffer record (struct event_hdr
// in probe.c); Len bytes of data follow it.
const HeaderSize = 16

// MaxData mirrors MAX_DATA in probe.c: the most of one write the kernel
// copies out before it cuts and flags the record.
const MaxData = 8192

// Flags set by the kernel side on a record.
const (
	// FlagTruncated: the write was longer than MaxData and was cut.
	FlagTruncated uint32 = 1
	// FlagIOVCut: a writev had more iovecs than the kernel side copies.
	FlagIOVCut uint32 = 2
)

// Event is one write (or one iovec of a writev) by a watched process.
type Event struct {
	Tgid  uint32
	FD    uint32
	Flags uint32
	Data  []byte
}

// Truncated reports whether the kernel side cut the write short, either
// the write itself or the iovec list it came from.
func (e Event) Truncated() bool { return e.Flags&(FlagTruncated|FlagIOVCut) != 0 }

var errShort = errors.New("record shorter than its header")

// ParseEvent decodes one ring buffer record. Data aliases rec.
func ParseEvent(rec []byte) (Event, error) {
	if len(rec) < HeaderSize {
		return Event{}, fmt.Errorf("%w: %d bytes", errShort, len(rec))
	}
	n := binary.LittleEndian.Uint32(rec[8:12])
	if int(n) > len(rec)-HeaderSize {
		return Event{}, fmt.Errorf("record claims %d data bytes, has %d", n, len(rec)-HeaderSize)
	}
	return Event{
		Tgid:  binary.LittleEndian.Uint32(rec[0:4]),
		FD:    binary.LittleEndian.Uint32(rec[4:8]),
		Flags: binary.LittleEndian.Uint32(rec[12:16]),
		Data:  rec[HeaderSize : HeaderSize+int(n)],
	}, nil
}
