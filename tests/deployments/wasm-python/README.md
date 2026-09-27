# Python WASM SDK test

Installs `pii-shield-wasi` and streams `notes/log_example/access.log` through the SDK,
**inside a Linux container** (see "Why Docker" below). Requires Docker.

```bash
tests/deployments/wasm-python/run.sh
```

Sanitized logs are written to `/tmp/pii-shield-sanitized/wasm-python`.

The redaction program is [`redact.py`](redact.py); it runs in `python:3.11-slim` (override
with `PII_PY_IMAGE`). The fixture is mounted read-only at `/fixture` and the output dir at
`/out`.

## Why Docker

The test runs in a Linux container so its result does not depend on the host's Python
build. It was moved there because on macOS the SDK was killed with `Killed: 9` (SIGKILL)
right after loading the WASM module, before any `redact` call.

Root cause (found 2026-09-27): on macOS, wasmtime catches wasm traps by setting Mach
exception ports on the thread that first calls into wasm (the SDK's `_initialize` call).
Apple-signed interpreters (`/usr/bin/python3`, the Xcode / Command Line Tools
Python 3.9) guard that port, and the kernel kills the process with
`EXC_GUARD` / `GUARD_TYPE_MACH_PORT` / `SET_EXCEPTION_BEHAVIOR` (see the `.ips` crash
report). Every wasmtime release from 12 to 49 behaves the same way; interpreters that are
not Apple-signed (Homebrew, python.org, pyenv) never hit it, and Node was never affected.

The SDK now sets `Config.macos_use_mach_ports = False` on macOS (the option exists in
wasmtime 45.0.0 and later, which is the SDK's minimum), so wasmtime uses POSIX signal
handlers and the SDK runs natively on any macOS Python. The published package gets this
from the first release after 2.2.4; this runner installs the published package, so it
stays in the container.
