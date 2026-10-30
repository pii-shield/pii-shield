//go:build linux

package probe

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Config selects the writes the kernel side copies out: the tasks of the
// agent's pid namespace (PidNSDev, PidNSIno from SelfPidNS) but the agent
// itself, or one tgid of that namespace. Tgids are as the namespace sees
// them, the numbers the agent and the pod know.
type Config struct {
	PidNSDev   uint64
	PidNSIno   uint64
	SelfTgid   uint32
	TargetTgid uint32
}

// Probe is the loaded program, its tracepoint and the ring buffer reader.
type Probe struct {
	objs probeObjects
	link link.Link
	rd   *ringbuf.Reader
}

// SelfPidNS returns the device and inode of the agent's pid namespace, the
// pair bpf_get_ns_current_pid_tgid wants.
func SelfPidNS() (dev, ino uint64, err error) {
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/pid", &st); err != nil {
		return 0, 0, fmt.Errorf("stat /proc/self/ns/pid: %w", err)
	}
	return uint64(st.Dev), st.Ino, nil //nolint:unconvert // Dev is int32 on some platforms
}

// Load sets the configuration constants, loads the program into the
// kernel and attaches it to the sys_enter raw tracepoint.
func Load(cfg Config) (*Probe, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock rlimit: %w", err)
	}
	spec, err := loadProbe()
	if err != nil {
		return nil, fmt.Errorf("load program spec: %w", err)
	}
	for name, v := range map[string]any{
		"cfg_pidns_dev":   cfg.PidNSDev,
		"cfg_pidns_ino":   cfg.PidNSIno,
		"cfg_self_tgid":   cfg.SelfTgid,
		"cfg_target_tgid": cfg.TargetTgid,
	} {
		vs, ok := spec.Variables[name]
		if !ok {
			return nil, fmt.Errorf("program has no variable %s", name)
		}
		if err := vs.Set(v); err != nil {
			return nil, fmt.Errorf("set %s: %w", name, err)
		}
	}
	p := &Probe{}
	if err := spec.LoadAndAssign(&p.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("load program: %+v", ve)
		}
		return nil, fmt.Errorf("load program: %w", err)
	}
	p.link, err = link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_enter", Program: p.objs.SysEnter})
	if err != nil {
		_ = p.objs.Close()
		return nil, fmt.Errorf("attach raw tracepoint sys_enter: %w", err)
	}
	p.rd, err = ringbuf.NewReader(p.objs.Events)
	if err != nil {
		_ = p.link.Close()
		_ = p.objs.Close()
		return nil, fmt.Errorf("ring buffer reader: %w", err)
	}
	return p, nil
}

// Read blocks for the next record. After Close it returns ringbuf.ErrClosed.
func (p *Probe) Read() (Event, error) {
	rec, err := p.rd.Read()
	if err != nil {
		return Event{}, err
	}
	return ParseEvent(rec.RawSample)
}

// Drops is the number of records the ring buffer had no room for, summed
// over the CPUs.
func (p *Probe) Drops() (uint64, error) {
	var perCPU []uint64
	if err := p.objs.Drops.Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, n := range perCPU {
		total += n
	}
	return total, nil
}

// Close detaches the program and releases the maps; a pending Read returns.
func (p *Probe) Close() error {
	err := p.rd.Close()
	if e := p.link.Close(); err == nil {
		err = e
	}
	if e := p.objs.Close(); err == nil {
		err = e
	}
	return err
}

// Pid is the agent's own tgid, for Config.SelfTgid.
func Pid() uint32 { return uint32(os.Getpid()) } //nolint:gosec // a pid fits
