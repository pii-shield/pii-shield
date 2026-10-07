# PII-Shield Manual Testing Guide

Follow these steps to locally test the features of PII-Shield Sidecar and SDKs.

## 1. Local Scrape for Prometheus Metrics

Test the Observability Layer locally without setting up an entire Kubernetes cluster.

1. Build and run the sidecar mapping the metrics port:
   ```bash
   export PII_METRICS_ENABLED=true
   export PII_METRICS_PORT=9090
   echo '{"user": "aragossa", "token": "abc123secretXYZ", "cc": "4111111111111111"}' | go run ./cmd/cleaner
   ```
2. Once the log is processed, open a separate terminal and fetch the RED (Rate, Errors, Duration) metrics exposed:
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
2. Trigger an Out-Of-Memory limit or an artificial buffer overflow by feeding an abnormally large flat string without newlines (greater than the 10MB bufio limit).
3. The sidecar should catch the `bufio.ErrTooLong` or `panic`, log a warning, and output the original data seamlessly without breaking the pipeline.

## 3. Triggering Fail-Closed Policy

For extremely strict environments, dropping the log is preferred over leaking.

1. Configure the sidecar to fail CLOSED:
   ```bash
   export PII_FAIL_POLICY=closed
   ```
2. Pass the exact same large invalid payload. 
3. The sidecar should swallow the broken string and instead print `[PII_SHIELD_DROP: FATAL_ERROR]`.

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
