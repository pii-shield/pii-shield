# Image of the eBPF audit agent (ghcr.io/pii-shield/pii-shield-ebpf).
#
# Build it from the repository root, not from ebpf/: the ebpf module takes
# pkg/scanner and pkg/metrics from the root module through a replace
# directive (ebpf/go.mod: replace … => ../), so both modules must be in
# the context.
#
#   docker build -t pii-shield-ebpf -f ebpf/Dockerfile .
#
# The BPF objects are committed (bpf2go output), so the build needs no
# clang; the builder cross-compiles on the build platform (pure Go, no
# cgo). The final image is distroless and runs as root: the agent needs
# the BPF, PERFMON and SYS_RESOURCE capabilities, which a non-root user
# does not keep across exec, and the operator grants exactly those and
# drops the rest (no privileged flag, no hostPath).
FROM --platform=$BUILDPLATFORM golang:1.27.3 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
COPY ebpf/go.mod ebpf/go.sum ./ebpf/
RUN --mount=type=cache,target=/go/pkg/mod cd ebpf && go mod download

COPY pkg ./pkg
COPY ebpf ./ebpf
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    cd ebpf && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /pii-shield-ebpf ./cmd/pii-shield-ebpf

FROM gcr.io/distroless/static:latest
COPY --from=builder /pii-shield-ebpf /pii-shield-ebpf
EXPOSE 9090
ENTRYPOINT ["/pii-shield-ebpf"]
