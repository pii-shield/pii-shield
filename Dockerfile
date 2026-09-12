# Stage 1: Build
FROM golang:1.27.1-alpine AS builder

WORKDIR /app

# Cache dependencies
COPY go.mod ./
# COPY go.sum ./ # Uncomment if go.sum exists
# RUN go mod download 

COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o pii-shield ./cmd/cleaner

# Stage 2: Run
FROM scratch

WORKDIR /

# Copy binary from builder
COPY --from=builder /app/pii-shield /pii-shield

USER 65532:65532

# Sidecar works as a pipe
ENTRYPOINT ["/pii-shield"]
