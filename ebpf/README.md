# PII-Shield eBPF audit agent

The agent of #96 watches what the processes of a pod write to stdout and
stderr through an eBPF program on the `write` and `writev` syscalls, runs
the scanner over the lines and counts what redaction would have changed.
It never touches the stream: the application's logs reach the container
runtime exactly as written, the agent is not in their path, and a crash of
the agent costs nothing but the counts. It is the read-only audit of #32
without a sidecar in the way, and it is **observation only**: eBPF cannot
rewrite what a process writes in any way the kernel supports for
production, so there is no eBPF redaction and none is planned.

Status: milestone 3.0, issue #96: the module, the program, the agent, a
smoke on a real kernel in CI, the image `ghcr.io/pii-shield/pii-shield-ebpf`,
the operator's `injectionMode: ebpf`, which injects it (operator README,
"Audit mode"), and the user docs ([docs/ebpf-audit.md](../docs/ebpf-audit.md)).

## What it needs

- Linux 5.8 or newer with BTF (`/sys/kernel/btf/vmlinux`): the program is
  CO-RE and resolves `pt_regs` against the running kernel at load time.
  Ubuntu 20.04 HWE and newer, GKE COS and EKS AL2023 qualify.
- `CAP_BPF` and `CAP_PERFMON` (or root). No tracefs, no hostPath: the hook
  is a raw tracepoint attached through the `bpf` syscall.
- To watch a pod: `shareProcessNamespace: true`, so the agent and the
  application share a pid namespace. The program copies the writes of
  every task in that namespace except the agent; `--exec` watches one
  command instead.

## Run

```bash
cd ebpf && go build -o pii-shield-ebpf ./cmd/pii-shield-ebpf
sudo ./pii-shield-ebpf --listen 127.0.0.1:9090 --exec sh -c 'echo "password=hunter2hunter2"; echo ok; sleep 5'
curl -s 127.0.0.1:9090/metrics | grep piishield_audit
```

Flags: `--listen` (`PII_METRICS_LISTEN`, default `:9090`, serves `/metrics`
and `/healthz`), `--stats-interval` (`PII_STATS_LOG_INTERVAL`, default
`1h`, the `PII-Shield audit: …` summary in the log), `--flush-idle` (an
unfinished line idle this long is counted, default `2s`), `--target-tgid`
(one process instead of the namespace), `--exec command…` (start the
command, watch it, exit with it; its stdout and stderr are the agent's).
The scanner reads the usual `PII_*` variables.

Counters: `piishield_audit_lines_total{result="clean"|"would_redact"}`,
`piishield_audit_findings_total{type}`, `piishield_audit_mode` (the same
as the sidecar's audit mode; `piishield_redaction_events_total` stays at
zero), `piishield_processed_bytes_total`, and the agent's own
`piishield_ebpf_events_total{result="ok"|"truncated"|"overflow"}` (a write
longer than 8 KiB or a `writev` with more than 8 iovecs is cut and counted
as `truncated`; a stream that reaches 1 MiB without a newline is counted
as a line and as `overflow`) and `piishield_ebpf_dropped_records` (records
the 16 MiB ring buffer had no room for; the audit undercounts by at most
that many writes), and `piishield_ebpf_attached` (1 once the program is
attached).

`/healthz` answers only after the program is attached, so a startup probe
on it holds the application until nothing it writes can be missed. When
the program cannot be loaded (an old kernel, no BTF, a capability
missing), the agent watching a pid namespace does not exit: it logs why,
serves `/healthz` and the counters at zero with `piishield_ebpf_attached
0`, and waits, so a pod is never held back by its audit agent. With
`--exec` or `--target-tgid` a load error is fatal.

What it does not see: writes to files and sockets, `sendmsg`, memory-mapped
output, and anything a process writes before the agent attached (`--exec`
starts the command stopped and continues it after the attach, so nothing
of it is missed). The counters hold the fact of a finding and its
detector, never the value.

## Image

```bash
docker build -t pii-shield-ebpf -f ebpf/Dockerfile .        # from the repository root
docker run --rm --privileged --pid=host pii-shield-ebpf --listen :9090   # watches the host's pid namespace
```

Distroless, one static binary, root (the capabilities the agent needs are
not kept by a non-root user across exec; the operator grants `BPF`,
`PERFMON` and `SYS_RESOURCE` and drops everything else). The release
publishes it next to the other images; `scripts/smoke-ebpf-image.sh` copies
the binary out of the image and runs the kernel smoke with it.

## Develop

`internal/probe/probe.c` is the kernel side; `bpf2go` compiles it for
amd64 and arm64 into `probe_*_bpfel.go` and `.o` files that are committed,
so `go build` needs no clang. After a change:

```bash
cd ebpf && BPF2GO_CC=/opt/homebrew/opt/llvm/bin/clang PATH=/opt/homebrew/opt/llvm/bin:$PATH go generate ./internal/probe/
```

(Apple's clang has no BPF target; Homebrew's `llvm` does, and `llvm-strip`
must be on the path.) CI rebuilds with the runner's clang and compares the
generated Go, builds the agent and runs `scripts/smoke-ebpf-agent.sh` on
the runner's kernel. The loader and `cmd/pii-shield-ebpf` build on Linux
only; the line assembly, the audit counters and the record parsing are
plain Go with tests on any platform (`go test -race ./...`). The module
takes `pkg/scanner` and `pkg/metrics` from the root module through
`replace … => ../`, so an image is built from the repository root.
