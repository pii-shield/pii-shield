//go:build ignore

// The eBPF side of the audit agent (#96): a raw tracepoint on sys_enter
// that copies what a process in the pod writes to stdout or stderr into a
// ring buffer. It reads, it never writes to the process: the agent only
// counts what the scanner would have redacted. Nothing here depends on
// tracefs, so the agent needs no hostPath; the kernel's BTF
// (/sys/kernel/btf/vmlinux) resolves the pt_regs fields at load time.

#include "types.h"
#include "bpf_core_read.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// MAX_DATA is the most of one write() the kernel copies out; a longer
// write is cut and flagged. 8 KiB covers a log line; the agent counts cuts.
#define MAX_DATA 8192
// MAX_IOV is how many iovecs of a writev() are copied, one event each.
#define MAX_IOV 8

#define FLAG_TRUNCATED 1
#define FLAG_IOV_CUT 2

// Minimal pt_regs for CO-RE: only the fields the syscall arguments live in,
// relocated against the running kernel's BTF (field names must match it).
#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	unsigned long r15, r14, r13, r12, bp, bx, r11, r10, r9, r8;
	unsigned long ax, cx, dx, si, di, orig_ax, ip, cs, flags, sp, ss;
} __attribute__((preserve_access_index));
#define SYS_write 1
#define SYS_writev 20
#define SYSCALL_ARG1(r) BPF_CORE_READ(r, di)
#define SYSCALL_ARG2(r) BPF_CORE_READ(r, si)
#define SYSCALL_ARG3(r) BPF_CORE_READ(r, dx)
#elif defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			__u64 regs[31];
			__u64 sp;
			__u64 pc;
			__u64 pstate;
		};
	};
	__u64 orig_x0;
} __attribute__((preserve_access_index));
#define SYS_write 64
#define SYS_writev 66
#define SYSCALL_ARG1(r) BPF_CORE_READ(r, regs[0])
#define SYSCALL_ARG2(r) BPF_CORE_READ(r, regs[1])
#define SYSCALL_ARG3(r) BPF_CORE_READ(r, regs[2])
#else
#error "unsupported target architecture: build with bpf2go -target amd64,arm64"
#endif

struct bpf_raw_tracepoint_args {
	__u64 args[0];
};

struct bpf_pidns_info {
	__u32 pid;
	__u32 tgid;
};

struct iovec {
	void *iov_base;
	unsigned long iov_len;
};

// event_hdr is what the agent reads first from each ring buffer record;
// len bytes of data follow it. The Go side (event.go) mirrors the layout.
struct event_hdr {
	__u32 tgid;
	__u32 fd;
	__u32 len;
	__u32 flags;
};

struct scratch {
	struct event_hdr hdr;
	__u8 data[MAX_DATA];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// One scratch buffer per CPU: the write is copied here, then handed to the
// ring buffer with its real length, so a short line costs a short record.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scratch);
} scratch SEC(".maps");

// drops counts records the ring buffer had no room for, per CPU.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

// Set by the agent before the program is loaded (ebpf.VariableSpec.Set).
// Either a pid namespace (dev and inode of /proc/self/ns/pid: every task
// in it except the agent is watched, the pod's case) or one target tgid
// (the --exec case). The agent's own tgid is always skipped.
volatile const __u64 cfg_pidns_dev = 0;
volatile const __u64 cfg_pidns_ino = 0;
volatile const __u32 cfg_self_tgid = 0;
volatile const __u32 cfg_target_tgid = 0;

static __always_inline void emit(__u32 tgid, __u32 fd, const void *buf, __u64 count, __u32 flags)
{
	__u32 zero = 0;
	struct scratch *s = bpf_map_lookup_elem(&scratch, &zero);
	if (!s)
		return;

	__u32 n;
	if (count > MAX_DATA) {
		n = MAX_DATA;
		flags |= FLAG_TRUNCATED;
	} else {
		n = count;
	}

	s->hdr.tgid = tgid;
	s->hdr.fd = fd;
	s->hdr.len = n;
	s->hdr.flags = flags;
	if (n > 0 && bpf_probe_read_user(s->data, n, buf))
		return;

	if (bpf_ringbuf_output(&events, s, sizeof(struct event_hdr) + n, 0)) {
		__u64 *d = bpf_map_lookup_elem(&drops, &zero);
		if (d)
			(*d)++;
	}
}

SEC("raw_tracepoint/sys_enter")
int sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	long id = ctx->args[1];
	if (id != SYS_write && id != SYS_writev)
		return 0;

	struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
	__u64 fd = SYSCALL_ARG1(regs);
	if (fd != 1 && fd != 2)
		return 0;

	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (tgid == cfg_self_tgid)
		return 0;
	if (cfg_target_tgid) {
		if (tgid != cfg_target_tgid)
			return 0;
	} else if (cfg_pidns_ino) {
		struct bpf_pidns_info ns = {};
		if (bpf_get_ns_current_pid_tgid(cfg_pidns_dev, cfg_pidns_ino, &ns, sizeof(ns)))
			return 0;
	}

	const void *buf = (const void *)SYSCALL_ARG2(regs);
	__u64 count = SYSCALL_ARG3(regs);

	if (id == SYS_write) {
		emit(tgid, fd, buf, count, 0);
		return 0;
	}

	// writev: one event per iovec, the agent joins them in order.
	const struct iovec *iov = buf;
	__u64 iovcnt = count;
#pragma unroll
	for (int i = 0; i < MAX_IOV; i++) {
		if (i >= iovcnt)
			break;
		struct iovec v;
		if (bpf_probe_read_user(&v, sizeof(v), &iov[i]))
			break;
		__u32 flags = 0;
		if (i == MAX_IOV - 1 && iovcnt > MAX_IOV)
			flags = FLAG_IOV_CUT;
		emit(tgid, fd, v.iov_base, v.iov_len, flags);
	}
	return 0;
}
