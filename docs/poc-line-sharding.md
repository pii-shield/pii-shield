# Proof of concept: sanitizing lines on several cores

Status: proof of concept, off by default. Measured on 2026-11-11.

## Question

The sanitizer is a single thread, so one core is its throughput ceiling
(about 85k–100k lines/s on the machine used here; see the sizing table in
[sidecar-failure-modes.md](sidecar-failure-modes.md)). A faster regex engine
does not move that ceiling: a CPU profile of the access-log benchmark has no
samples in `regexp` at all, the time goes to the tokenizer and the entropy
checks. Can the CLI use more cores instead, without changing its output?

## Answer

Yes. With `PII_WORKERS=N` the CLI sanitizes lines on N goroutines and writes
them in input order. Throughput grows almost in step with the number of
cores, and the output is byte for byte the same as with one thread.

| Corpus | `main` | unset | 2 workers | 3 workers | 4 workers | `auto` |
| --- | --- | --- | --- | --- | --- | --- |
| Mixed text and JSON, 500k lines, 72.6 MiB | 85k lines/s | 85k | 169k (×2.0) | 248k (×2.9) | 334k (×3.9) | 335k (×3.9) |
| nginx access log, 300k lines, 32.6 MiB | 98k lines/s | 100k | 195k (×2.0) | 291k (×3.0) | 366k (×3.7) | 375k (×3.8) |

The CLI read stdin and wrote to `/dev/null`; median of 5 runs; 4 vCPUs
(Intel Xeon 2.30GHz, cloud VM), Go 1.27.3. Every run's output was compared
with the output of `main` under the same `PII_SALT`: identical in all of
them. "unset" is this branch without `PII_WORKERS`: the default path is not
slower than `main`.

Other measurements on the mixed corpus:

| | unset | 4 workers |
| --- | --- | --- |
| Pinned to one core (`taskset -c 0`) | 5.58 s | 5.59 s |
| Peak memory (RSS) | 17.0 MiB | 22.8 MiB |
| One line in, one line out on a quiet stream, median | 75 µs | 138 µs |

So workers cost nothing when there is only one core to use, and a quiet
stream is not held back waiting for a batch to fill.

## How it works

The code is in `cmd/cleaner/parallel.go`.

The scanner already allowed this: `ScanAndRedact` works on one line, keeps
nothing between lines, and reads its configuration from one atomic snapshot.
What was missing is the order of the output.

- The reader groups lines into batches. Each batch goes into two bounded
  queues at once: `work`, which the workers read in any order, and
  `ordered`, which one writer reads in input order. The writer waits for
  each batch to be rendered before it writes it.
- A batch is sent as soon as a worker is free, so at low load every line
  travels alone. While all workers are busy the batch grows, up to 256
  lines or 64 KiB. A batch left waiting when the input pauses is sent by a
  timer after 5 ms.
- Both queues are bounded (4 batches per worker). A reader that is faster
  than the workers, or a destination that does not take the output, blocks
  the reader instead of filling memory.
- A stream marker (`[PII_SHIELD_DROP: …]`, `[PII_SHIELD_WARN: …]`) keeps its
  place: one made by a worker is written with its batch and flushed at once;
  one written by the reader waits for the lines before it.
- On shutdown the lines still with the workers are written out before the
  output buffer is closed.

Without `PII_WORKERS` (or with `1`) none of this runs: the reader sanitizes
each line itself, as before.

## What was checked

Tests in `cmd/cleaner/parallel_test.go`, all run with the race detector:

- the output equals the one-thread output for 2, 3 and 8 workers, including
  a line larger than a whole batch and empty lines;
- audit mode writes the stream back unchanged;
- a line that panics the scanner is passed on (fail-open) or replaced by a
  DROP marker (fail-closed) in its own place;
- a marker is flushed at once and stays in order;
- the timer sends a batch that did not fill;
- a blocked destination stops the reader within the queue bound;
- `Close` drains the queues, and a line that arrives after it is still
  sanitized;
- the whole CLI on stdin gives the same output for unset, `4` and `auto`.

By hand, with 4 workers, compared with `main`: file mode and pipe (FIFO)
mode ended by SIGTERM, and a line over the 10 MiB buffer under a closed fail
policy. The output was identical in each case.

## Limits, and what is left before this could ship

1. **It only helps above one core.** The chart's default CPU limit for the
   sidecar is 250m. Under a limit of one core or less the workers give
   nothing. The gain is for a sidecar that is given two or more cores, which
   today is wasted ("above 1000m there is no gain" in the sizing table).
2. **Memory with very long lines.** The queues are bounded by batch count.
   A batch closes at 64 KiB, but one line can be up to 10 MiB, so many huge
   lines in a row can hold several of them in memory at once, where one
   thread holds one. The chart's memory limit is 30Mi. The queue needs a
   bound in bytes before this is safe at that limit.
3. **Adaptive threshold.** `PII_ADAPTIVE_THRESHOLD` learns its baseline
   from the first lines in the order they are scanned. With it on,
   `PII_WORKERS` is ignored at start and a log line says so. A config file
   reload that turns it on later is not caught.
4. **Not measured:** more than 4 cores (the reader is still one thread and
   becomes the ceiling at some point); a real cgroup CPU limit between one
   and several cores, as opposed to pinning to one core; throughput in file
   mode, where the `tail` library hands over one line at a time.
5. **The setting is an environment variable only.** It is not in
   `CONFIGURATION.md`, `PiiPolicy` or the charts, and the sizing table still
   describes one thread. The WASM SDKs are not touched: they sanitize one
   call at a time.

## Try it

```bash
go build -o pii-shield ./cmd/cleaner
PII_WORKERS=auto ./pii-shield < app.log > sanitized.log   # or a number
go test -race ./cmd/cleaner -run 'Parallel|MainWorkers'
go test ./cmd/cleaner -run '^$' -bench BenchmarkLinePipeline
```

`auto` is one worker per CPU that Go sees (`GOMAXPROCS`).
