module github.com/pii-shield/pii-shield/ebpf

go 1.26.9

toolchain go1.27.3

require (
	github.com/cilium/ebpf v0.22.0
	github.com/pii-shield/pii-shield/v2 v2.0.0
	github.com/prometheus/client_golang v1.25.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.72.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/pii-shield/pii-shield/v2 => ../
