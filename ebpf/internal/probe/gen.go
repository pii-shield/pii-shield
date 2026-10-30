package probe

// The C program is compiled by bpf2go into probe_*_bpfel.go and the .o
// files next to them, which are committed, so `go build` needs no clang.
// Regenerate after a change to probe.c; BPF2GO_CC names the clang to use
// (Apple's clang has no BPF target, Homebrew's llvm does). This file has
// no build tag so that `go generate` finds the directive on any platform.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -tags linux probe probe.c -- -I headers
