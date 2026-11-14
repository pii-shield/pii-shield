# PII-Shield Manual Testing Guide

Follow these steps to locally test the features of PII-Shield Sidecar and SDKs.

## 1. Local Scrape for Prometheus Metrics

Test the Observability Layer locally without setting up an entire Kubernetes cluster.

1. Build and run the sidecar mapping the metrics port. The process exits when its input ends and takes the metrics server with it, so the `sleep` keeps the input open for a minute while you scrape:
   ```bash
   export PII_METRICS_ENABLED=true
   export PII_METRICS_PORT=9090
   (echo '{"user": "lena", "token": "abc123secretXYZ", "cc": "4111111111111111"}'; sleep 60) | go run ./cmd/cleaner
   ```
2. While it runs, open a separate terminal and fetch the RED (Rate, Errors, Duration) metrics exposed:
   ```bash
   curl -s http://localhost:9090/metrics | grep pii
   ```
   You should see `piishield_processed_bytes_total` increasing and `piishield_redaction_events_total` counting the masked occurrences!

   The same server exposes a health endpoint for readiness/liveness probes when the sidecar runs long-lived:
   ```bash
   curl -s http://localhost:9090/healthz
   ```
   `PII_METRICS_PORT` must be an integer between 1 and 65535; an invalid value logs an error and disables the metrics server while log sanitization keeps running (fail-open).

## 2. Triggering Fail-Open Policy

Test the architectural safeguards to ensure the Sidecar acts as a robust pipe when exhausted.

1. Configure the sidecar to fail OPEN:
   ```bash
   export PII_FAIL_POLICY=open
   ```
2. Feed it one line longer than the 10 MiB line limit:
   ```bash
   python3 -c "import sys; sys.stdout.write('A' * (10*1024*1024 + 1) + '\n')" | go run ./cmd/cleaner | cut -c1-80
   ```
3. The oversized line is not written out, because it could not be scanned. In its place the sidecar prints `[PII_SHIELD_WARN: BUFFER_OVERFLOW, STREAM_BROKEN]`, reports `Error reading standard input: bufio.Scanner: token too long` on stderr and exits with status 1. "Open" means the reader is told the stream broke and can decide what to do; it does not mean unscanned data passes through.

   A line that makes the scanner itself fail (a panic while scanning) is the other case: under `open` that one line is written out unchanged and the stream continues.

## 3. Triggering Fail-Closed Policy

For extremely strict environments, dropping the log is preferred over leaking.

1. Configure the sidecar to fail CLOSED:
   ```bash
   export PII_FAIL_POLICY=closed
   ```
2. Pass the same oversized line as in section 2.
3. The sidecar drops the line and prints `[PII_SHIELD_DROP: BUFFER_OVERFLOW]` in its place, with the same stderr message and exit status 1. `[PII_SHIELD_DROP: FATAL_ERROR]` is the marker for the other case, a line the scanner failed on: under `closed` that line is replaced by the marker and the stream continues.

## 4. Run SDK Local Environments

You can compile the WebAssembly kernel and directly interact with Python or Node!

1. Build the WASM core:
   ```bash
   GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o pii-shield-wasi.wasm cmd/wasm-ffi/main.go
   ```
2. **Node.js**:
   ```bash
   cd sdks/node
   node test.js
   ```
3. **Python**:
   ```bash
   cd sdks/python
   python3 -m venv venv
   source venv/bin/activate
   pip install wasmtime
   python test.py
   ```

For the automated tests (unit, fuzz, smoke, operator, deployment matrix), see [docs/testing.md](docs/testing.md).
