# Image of the rule server (ghcr.io/pii-shield/pii-shield-rules).
#
# Build it from the repository root, not from rules/: the rules module takes
# pkg/scanner from the root module through a replace directive (rules/go.mod:
# replace … => ../), so both modules must be in the context.
#
#   docker build -t pii-shield-rules -f rules/Dockerfile .
#
# The builder runs on the build platform and cross-compiles for the target
# (the binary has no cgo: modernc.org/sqlite is pure Go), so a multi-arch
# build does not emulate the Go toolchain. The module and build caches are
# BuildKit cache mounts, so a rebuild downloads and compiles only what changed.
FROM --platform=$BUILDPLATFORM golang:1.27.3 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
COPY rules/go.mod rules/go.sum ./rules/
RUN --mount=type=cache,target=/go/pkg/mod cd rules && go mod download

COPY pkg ./pkg
COPY rules ./rules
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    cd rules && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /rules-server ./cmd/rules-server

# The database lives in /data; distroless has no shell to create it, so the
# directory comes from the builder already owned by the nonroot user.
RUN mkdir -p /data && chown 65532:65532 /data

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /rules-server /rules-server
COPY --from=builder --chown=65532:65532 /data /data
ENV RULES_DB=/data/rules.db
VOLUME /data
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/rules-server"]
