package probe

import (
	"encoding/binary"
	"testing"
)

func record(tgid, fd, flags uint32, data string) []byte {
	rec := make([]byte, HeaderSize+len(data))
	binary.LittleEndian.PutUint32(rec[0:], tgid)
	binary.LittleEndian.PutUint32(rec[4:], fd)
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(data))) //nolint:gosec // test data
	binary.LittleEndian.PutUint32(rec[12:], flags)
	copy(rec[HeaderSize:], data)
	return rec
}

func TestParseEvent(t *testing.T) {
	ev, err := ParseEvent(record(4242, 2, FlagTruncated, "password=hunter2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Tgid != 4242 || ev.FD != 2 || string(ev.Data) != "password=hunter2\n" || !ev.Truncated() {
		t.Errorf("event = %+v", ev)
	}
	ev, err = ParseEvent(record(1, 1, 0, ""))
	if err != nil || len(ev.Data) != 0 || ev.Truncated() {
		t.Errorf("empty write: %+v, %v", ev, err)
	}
	if ev, err := ParseEvent(record(1, 1, FlagIOVCut, "x")); err != nil || !ev.Truncated() {
		t.Errorf("iov cut must count as truncated: %+v, %v", ev, err)
	}
}

func TestParseEventRejectsBadRecords(t *testing.T) {
	if _, err := ParseEvent(make([]byte, HeaderSize-1)); err == nil {
		t.Error("a record shorter than the header must be refused")
	}
	rec := record(1, 1, 0, "abc")
	binary.LittleEndian.PutUint32(rec[8:], 100) // claims more data than present
	if _, err := ParseEvent(rec); err == nil {
		t.Error("a record claiming more data than it carries must be refused")
	}
}
