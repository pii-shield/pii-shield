# Sidecar Failure Modes

This document defines expected behavior for the PII-Shield sidecar file mode.

PII-Shield sidecar file mode watches a configured application log file, sanitizes each line, and writes sanitized output to the sidecar `stdout`. Downstream log collectors should ingest the sidecar output, not the original application log file.

## Failure Policy

`PII_FAIL_POLICY` controls behavior when line processing fails.

| Value | Behavior | Recommended use |
| --- | --- | --- |
| `open` | Keep log flow alive where possible. If processing panics, emit the original line. | Availability-first environments. |
| `closed` | Drop failed lines and emit a marker instead. | Compliance-sensitive environments where leaking raw logs is worse than losing a line. |

Default: `open`.

For production compliance rollouts, prefer `PII_FAIL_POLICY=closed` after validating that alerting catches sanitizer errors and dropped lines.

## Sidecar Process Crash

Expected behavior:

- Kubernetes restarts the sidecar according to pod restart behavior.
- The sidecar keeps no read offset. A restarted sidecar reads the application log file from its first line again, so nothing written while it was down is lost, and every line it had already emitted is emitted a second time (`TestWatchFileSidecarRestartReplaysFromStart`). Deduplicate downstream on the log line and timestamp, or rotate the file before a planned restart, to keep the duplicates out.
- Downstream log volume may drop while the sidecar is unavailable.

Required production controls:

- Alert on sidecar restarts.
- Alert on missing processed bytes.
- Validate restart behavior in staging.
- Keep rollback instructions available for removing injection labels or rolling back Helm values.

## Backpressure

Expected behavior:

- The sidecar reads and processes lines from the watched file.
- If log production exceeds sanitizer throughput, downstream sanitized output can lag.
- High CPU pressure, very broad custom regex rules, or large log lines can increase latency.

Required production controls:

- Set resource requests and limits intentionally (see the sizing table below).
- Alert on high `piishield_processing_duration_seconds` p95.
- Benchmark representative logs before rollout.
- Avoid broad custom regex rules in high-throughput workloads.

### Sizing the CPU limit

The sanitizer is a single thread, so a CPU limit is a throughput ceiling:
once the application logs faster than the limit allows, the sidecar is
throttled and the sanitized stream falls behind. Measured on one Apple M1
core with 200 000-line corpora (CLI writing to a file, 2.2.8 plus the
October 2026 optimizations), the per-core rate is about 92k lines/s on
plain text logs, 90k on JSON logs and 53k on an nginx access log with a
User-Agent on every line. A server core is usually slower than an M1, so
treat these as upper bounds and measure your own logs with
`benchmark/run_benchmarks.sh`.

| CPU limit | text / JSON logs | access logs |
|-----------|------------------|-------------|
| 50m       | ~4.5k lines/s    | ~2.6k lines/s |
| 100m      | ~9k lines/s      | ~5k lines/s |
| 250m (chart default) | ~22k lines/s | ~13k lines/s |
| 500m      | ~45k lines/s     | ~26k lines/s |
| 1000m     | ~90k lines/s     | ~53k lines/s |

Above 1000m there is no gain. The chart's request (100m) is what the
scheduler reserves; the limit (250m) is where throttling starts. The
operator sets no default: give `PiiPolicy.spec.resources` a limit from this
table.

## Large Or Truncated Lines

Expected behavior:

- Standard stdin mode uses a scanner buffer with an upper bound.
- Oversized lines trigger buffer overflow handling.
- In fail-open mode, PII-Shield emits a warning marker.
- In fail-closed mode, PII-Shield emits a drop marker.

Markers:

```text
[PII_SHIELD_WARN: BUFFER_OVERFLOW, STREAM_BROKEN]
[PII_SHIELD_DROP: BUFFER_OVERFLOW]
```

Required production controls:

- Keep maximum log line sizes reasonable.
- Add tests for application logs that may exceed normal line sizes.
- Alert on sanitizer errors.

## File Rotation

Expected behavior:

- File mode tails the file by polling it every 250 ms and reopens it when it is renamed, removed or truncated. Polling was chosen over inotify/kqueue after a rename rotation was missed in 2 of 8 runs with the notifier on macOS (`TestWatchFileRotationRename` under the race detector); with polling it is followed every time, and the sidecar does not consume an inotify watch on the node.
- Rotation by rename (logrotate's default: the file is moved away and the application opens a new one under the old name) is followed, and every line of both files is sanitized (`TestWatchFileRotationRename`).
- Rotation by copy and truncate (logrotate's `copytruncate`: the file is cut to zero in place) is followed: the sidecar notices the cut and reads the new lines from the start of the file (`TestWatchFileRotationTruncate`). A truncate that is immediately refilled past the sidecar's last read offset within one poll interval cannot be told from ordinary growth and would be read from that offset; keep rotations and bursts apart.
- An application restart that removes and recreates the file is followed the same way (`TestWatchFileAppRestartRecreate`).
- Rotation behavior still depends on how the application and runtime rotate files.

Required production controls:

- Validate rotation behavior for each workload.
- Confirm rotated files do not bypass sanitized output.
- Confirm log collectors ingest sidecar output only.

## Disk Pressure

Expected behavior:

- PII-Shield does not own the application log file lifecycle.
- Disk pressure can affect the application, shared volume, and sidecar together.
- Missing or truncated source logs can lead to missing sanitized output.
- When the reader of the sidecar's stdout goes away (the runtime's log pipe), the next write ends the sidecar process instead of leaving it running with nowhere to put sanitized lines, so the kubelet restarts it (`TestWatchFileDownstreamClosed`). A full disk under the shared volume is not simulated in the test suite: it needs a mounted size-limited filesystem.

Required production controls:

- Monitor pod/container disk pressure.
- Keep log rotation and retention bounded.
- Validate behavior under synthetic disk pressure before broad rollout.

## Fail-Open And Fail-Closed Selection

Use fail-open when:

- application availability is more important than strict log-loss control;
- logs are not the only compliance control;
- the deployment is still in staging or early controlled rollout.

Use fail-closed when:

- raw log leakage is unacceptable;
- dropped log lines are preferable to unsanitized output;
- alerting and incident response are ready.

## Test Coverage Expectations

Minimum test coverage for production-hardening:

- [x] fail-open buffer overflow behavior;
- [x] fail-closed buffer overflow behavior;
- [x] file rotation behavior (`TestWatchFileRotationRename`, `TestWatchFileRotationTruncate` in `cmd/cleaner/failure_modes_test.go`);
- [x] sidecar restart behavior (`TestWatchFileSidecarRestartReplaysFromStart`: replays from the first line, no loss, duplicates);
- [x] application restart behavior (`TestWatchFileAppRestartRecreate`);
- [ ] disk pressure behavior: only the closed-stdout half (`TestWatchFileDownstreamClosed`); a full shared volume is not simulated;
- [x] downstream collector bypass checks (`assert_app_container_silent` in `tests/deployments/shared/scripts/common.sh`, run on every replay pod of the operator paths: the application container's own log stream must carry no access-log line, so a collector reading container streams sees sanitized lines only).
