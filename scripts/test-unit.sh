#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "Running root module unit tests..."
# cmd/wasm and cmd/wasm-ffi build only with GOOS=wasip1 (//go:build wasm),
# so go list ./... already leaves them out.
go test -v ./...

echo "Running operator unit tests..."
(cd "${ROOT_DIR}/operator" && go test ./api/... ./internal/...)

echo "All unit tests passed!"
