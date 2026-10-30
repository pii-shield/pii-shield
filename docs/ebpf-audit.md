# eBPF Audit Agent

The eBPF audit agent watches what the processes of a pod write to `stdout` and `stderr`, runs the PII-Shield scanner over the lines, and counts what redaction would have changed. It never changes the stream. The application's logs reach the container runtime exactly as written, the agent is not in their path, and if the agent crashes the logs flow on and only the counts are lost.

Status: **experimental, observation only** (milestone 3.0, issue #96). Use it to measure what the rules would hide on real traffic before you choose a redacting mode. It is not a redaction control and must not be presented as one.

## Why there is no eBPF redaction

An eBPF program can read a process's `write` buffer before the kernel hands it to the pipe the container runtime reads. It cannot rewrite it in any way the kernel supports for production. The only helper that writes to a process's memory, `bpf_probe_write_user`, is marked experimental, and the kernel logs a warning when a program that uses it is loaded, because it can corrupt the process's memory. PII-Shield does not ship that. Redaction of a pod's logs stays with the file sidecar, and `stdout` redaction without application changes is the command-wrapper mode of [stdout-stderr-interception-design.md](stdout-stderr-interception-design.md), a separate piece of work.

## How it works

```text
application process  --write(1|2, buf)-->  kernel  -->  pipe  -->  container runtime  -->  node log file
                                              |
                                  raw tracepoint sys_enter
                                  (copies up to 8 KiB, read only)
                                              |
                                        ring buffer
                                              |
                     pii-shield-ebpf: lines -> scanner -> audit counters
```

- A raw tracepoint on `sys_enter` keeps `write` and `writev` calls on file descriptors 1 and 2.
- It keeps only tasks in the agent's own pid namespace, and drops the agent itself. In a pod with `shareProcessNamespace: true` that namespace holds the application containers.
- It copies up to 8 KiB of each write into a 16 MiB ring buffer. A `writev` gives one record per iovec, up to 8.
- The agent joins the records of each process and descriptor into lines and runs the scanner in audit mode. It exports the same counters as the sidecar's `PII_MODE=audit`.
- The program is CO-RE: it is compiled once and relocated against the running kernel's BTF at load time. It needs no tracefs and no hostPath.

## Requirements

| Requirement | Why |
| --- | --- |
| Linux 5.8 or newer | Ring buffer (5.8) and `bpf_get_ns_current_pid_tgid` (5.7). |
| BTF at `/sys/kernel/btf/vmlinux` | CO-RE relocation of `pt_regs`. Ubuntu 20.04 HWE and newer, GKE Container-Optimized OS, EKS Amazon Linux 2023 and Docker Desktop ship it. |
| `amd64` or `arm64` nodes | The program is built for these two. |
| `CAP_BPF`, `CAP_PERFMON` | Load the program and attach the tracepoint. |
| `CAP_SYS_RESOURCE` | Raise the memlock limit on kernels before 5.11. |
| Root in the agent container | A non-root user does not keep added capabilities across exec. |
| `shareProcessNamespace: true` on the pod | The agent watches its own pid namespace. The operator sets it. |

Neither the `restricted` nor the `baseline` Pod Security Standard admits the agent. `baseline` allows adding only a fixed list of capabilities, and `BPF`, `PERFMON` and `SYS_RESOURCE` are not on it; `restricted` also forbids running as root. A namespace that runs the agent needs the `privileged` level or an exemption in your admission policy.

## Run it with the operator

```yaml
apiVersion: core.pii-shield.io/v1alpha1
kind: PiiPolicy
metadata:
  name: default
  namespace: payments
spec:
  injectionMode: ebpf
  auditMode: true          # required: the agent only observes
  saltSecretKeyRef: { name: pii-shield-salt, key: salt }
  sensitiveKeys: [password, token, geheim]
```

Label the workload with `pii-shield.io/inject: "true"` as for any other mode. The webhook adds the agent as a native sidecar from the chart's `sidecar.ebpfImage` image (`ghcr.io/pii-shield/pii-shield-ebpf`), shares the pod's pid namespace, and grants the three capabilities with everything else dropped. Every pod admitted this way gets a warning that its logs are not redacted. The API server rejects `injectionMode: ebpf` without `auditMode: true`.

The counters are on port 9090 of the agent container, named `pii-metrics`:

- `piishield_audit_lines_total{result="clean"|"would_redact"}` and `piishield_audit_findings_total{type}`, the same as the sidecar's audit mode. `piishield_redaction_events_total` stays at zero.
- `piishield_audit_mode`, 1 while the agent runs.
- `piishield_ebpf_events_total{result="ok"|"truncated"|"overflow"}`: records read, records cut at 8 KiB or at 8 iovecs, and streams that reached 1 MiB without a newline.
- `piishield_ebpf_dropped_records`: records the ring buffer had no room for. The audit undercounts by at most that many writes.
- `piishield_ebpf_attached`: 1 once the program is attached, 0 when it could not be loaded.

If the program cannot be loaded (an old kernel, no BTF, a capability missing), the agent does not crash: it logs why, answers `/healthz`, and exports the audit counters at zero with `piishield_ebpf_attached 0`. A pod is never held back by its audit agent, and `PIIShieldAuditSeesNoLines` fires for it.

The agent also logs a `PII-Shield audit: …` summary every hour. The operator chart's `PIIShieldAuditWouldRedact` and `PIIShieldAuditSeesNoLines` alerts work on these counters as they do for the sidecar. The [operational runbooks](operational-runbooks.md) say what to do with the numbers.

## Run it on a host

```bash
docker build -t pii-shield-ebpf -f ebpf/Dockerfile .      # from the repository root
docker run --rm --privileged --pid=host -p 9090:9090 pii-shield-ebpf
```

With `--pid=host` the agent watches every process on the host. To watch one command, run the binary with `--exec`:

```bash
sudo ./pii-shield-ebpf --listen 127.0.0.1:9090 --exec ./my-service --port 8080
```

The command starts stopped, the probe attaches, and the command continues. Nothing it writes is missed, and the agent exits with it.

## What it does not see

- Writes to files and sockets, `sendmsg`, `splice`, and output a process writes through memory-mapped files. A process that logs to a file is the file sidecar's case.
- More than 8 KiB of one write, and more than 8 iovecs of one `writev`. Both are counted as `truncated`.
- Anything written before the agent attached. In a pod this does not happen: the agent's `/healthz` answers only once the program is attached, and a startup probe on it holds the application containers until then. With `--target-tgid` on a host, the process's earlier output is missed; `--exec` starts the command stopped and misses nothing.
- Values. The counters record that a line would change and which detector fired, never the value found. To see a false positive, read the application's own logs for that period.

## Security notes

The agent runs as root with `CAP_BPF` and `CAP_PERFMON`. Together they let a process load tracing programs that read memory of any process on the node, not only of its pod. That is more than a log sidecar needs, and it is the price of watching `stdout` without being in its path.

The agent's own code reads only the tasks of its pid namespace, but the capability does not limit it to that. Treat the agent image as node-level trusted code:

- Pin the image by digest.
- Run it only in namespaces where you would accept a node-level agent.
- Prefer the file sidecar wherever the application can write to a file.

See the [threat model](threat-model.md) for the full picture.

## Develop and test

The module is `ebpf/`, with its own README. CI runs the unit tests, rebuilds the program with clang and compares the generated Go. It builds the agent and the image and loads the program into the runner's kernel with `scripts/smoke-ebpf-agent.sh` and `scripts/smoke-ebpf-image.sh`. `tests/deployments/operator-ebpf/run.sh` runs the whole path in a local kind cluster: operator, policy, injection, untouched application logs, and counters.
