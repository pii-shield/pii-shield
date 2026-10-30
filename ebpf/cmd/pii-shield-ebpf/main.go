//go:build linux

// pii-shield-ebpf is the audit agent of #96: it watches what the processes
// of a pod write to stdout and stderr through an eBPF program on the write
// syscalls, runs the scanner over the lines and counts what redaction
// would have changed. It never touches the stream: the application's logs
// reach the runtime as they were written, and a crash of the agent costs
// nothing but the counts.
//
// In a pod (shareProcessNamespace) it watches every process in its pid
// namespace but itself. With --exec it starts a command and watches only
// that process, which is how the CI smoke and a developer run it.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/pii-shield/pii-shield/ebpf/internal/audit"
	"github.com/pii-shield/pii-shield/ebpf/internal/probe"
	"github.com/pii-shield/pii-shield/ebpf/internal/stream"
)

func main() {
	listen := flag.String("listen", envOr("PII_METRICS_LISTEN", ":9090"), "address of /metrics and /healthz (PII_METRICS_LISTEN)")
	statsInterval := flag.Duration("stats-interval", envDuration("PII_STATS_LOG_INTERVAL", time.Hour), "how often the audit summary is logged (PII_STATS_LOG_INTERVAL)")
	flushIdle := flag.Duration("flush-idle", 2*time.Second, "an unfinished line idle this long is counted as a line")
	targetTgid := flag.Uint("target-tgid", 0, "watch one process instead of the pid namespace")
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "usage: pii-shield-ebpf [flags] [--exec command args...]\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	log.SetOutput(os.Stderr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --exec: the command's stdout and stderr are the agent's own, so its
	// lines still reach whoever reads them; the probe sees the command's
	// writes to them, not the agent's.
	var child *exec.Cmd
	if args := flag.Args(); len(args) > 0 {
		if args[0] == "--exec" {
			args = args[1:]
		}
		if len(args) == 0 {
			log.Fatal("--exec needs a command")
		}
		child = exec.Command(args[0], args[1:]...) //nolint:gosec // the operator's own command line
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	}

	cfg := probe.Config{SelfTgid: probe.Pid(), TargetTgid: uint32(*targetTgid)} //nolint:gosec // flag range
	if child != nil {
		// The probe must be in place before the command's first write, so
		// the command is started stopped and continued after the attach.
		child.SysProcAttr = &syscall.SysProcAttr{}
		if err := child.Start(); err != nil {
			log.Fatalf("start %s: %v", child.Path, err)
		}
		if err := child.Process.Signal(syscall.SIGSTOP); err != nil {
			log.Fatalf("stop %s: %v", child.Path, err)
		}
		cfg.TargetTgid = uint32(child.Process.Pid) //nolint:gosec // a pid fits
	} else if cfg.TargetTgid == 0 {
		dev, ino, err := probe.SelfPidNS()
		if err != nil {
			log.Fatal(err)
		}
		cfg.PidNSDev, cfg.PidNSIno = dev, ino
	}

	p, err := probe.Load(cfg)
	if err != nil {
		log.Fatalf("eBPF: %v (kernel 5.8+ with BTF and CAP_BPF, CAP_PERFMON are required)", err)
	}
	defer func() { _ = p.Close() }()
	switch {
	case child != nil:
		log.Printf("pii-shield-ebpf: watching stdout and stderr of pid %d (%s); lines are counted, never changed", child.Process.Pid, child.Path)
	case cfg.TargetTgid != 0:
		log.Printf("pii-shield-ebpf: watching stdout and stderr of pid %d; lines are counted, never changed", cfg.TargetTgid)
	default:
		log.Printf("pii-shield-ebpf: watching stdout and stderr of every process in this pid namespace; lines are counted, never changed")
	}

	auditor := audit.New()
	asm := stream.New(auditor.Line)

	srv := &http.Server{Addr: *listen, Handler: metricsMux(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("metrics server: %v", err)
		}
	}()

	if child != nil {
		if err := child.Process.Signal(syscall.SIGCONT); err != nil {
			log.Fatalf("continue %s: %v", child.Path, err)
		}
		go func() {
			err := child.Wait()
			// Give the ring buffer a moment to deliver the last writes.
			time.Sleep(200 * time.Millisecond)
			if err != nil {
				log.Printf("%s exited: %v", child.Path, err)
			}
			stop()
		}()
	}

	// Read records until the context ends; a timer flushes idle lines,
	// logs the summary and refreshes the drop count.
	go func() {
		ticker := time.NewTicker(*flushIdle)
		defer ticker.Stop()
		summary := time.NewTicker(*statsInterval)
		defer summary.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				flushCh <- struct{}{}
			case <-summary.C:
				log.Print(auditor.Summary())
				if n, err := p.Drops(); err == nil {
					audit.DropsTotal.Set(float64(n))
				}
			}
		}
	}()

	events := make(chan probe.Event, 1024)
	go func() {
		defer close(events)
		for {
			ev, err := p.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("ring buffer: %v", err)
				continue
			}
			events <- ev
		}
	}()

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-flushCh:
			asm.FlushIdle(time.Now(), *flushIdle)
		case ev := <-events:
			result := "ok"
			if ev.Truncated() {
				result = "truncated"
			}
			audit.EventsTotal.WithLabelValues(result).Inc()
			before := asm.Overflows
			asm.Push(stream.Key{Tgid: ev.Tgid, FD: ev.FD}, ev.Data, time.Now())
			if asm.Overflows != before {
				audit.EventsTotal.WithLabelValues("overflow").Inc()
			}
		}
	}

	// Drain what the kernel already delivered, then count the unfinished
	// lines and log the final summary.
	_ = p.Close()
	for ev := range events {
		asm.Push(stream.Key{Tgid: ev.Tgid, FD: ev.FD}, ev.Data, time.Now())
	}
	asm.FlushIdle(time.Now().Add(*flushIdle), *flushIdle)
	if n, err := p.Drops(); err == nil && n > 0 {
		log.Printf("ring buffer dropped %d records; the audit undercounts by at most that many writes", n)
	}
	log.Print(auditor.Summary())

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

var flushCh = make(chan struct{}, 1)

func metricsMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	return mux
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}
