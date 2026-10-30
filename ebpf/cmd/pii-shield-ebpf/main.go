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
	"runtime"
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
	execFlag := flag.Bool("exec", false, "run the rest of the command line as a command and watch only it; exit with it")
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
	if args := flag.Args(); *execFlag || len(args) > 0 {
		if len(args) == 0 {
			log.Fatal("--exec needs a command")
		}
		child = exec.Command(args[0], args[1:]...) //nolint:gosec // the operator's own command line
		child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	}

	dev, ino, err := probe.SelfPidNS()
	if err != nil {
		log.Fatal(err)
	}
	cfg := probe.Config{PidNSDev: dev, PidNSIno: ino, SelfTgid: probe.Pid(), TargetTgid: uint32(*targetTgid)} //nolint:gosec // flag range
	if child != nil {
		// The probe must be in place before the command's first write, so
		// the command is traced: it stops in the kernel right after exec,
		// before its first instruction, and is detached after the attach.
		// ptrace calls must come from the thread that started the child.
		runtime.LockOSThread()
		child.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
		if err := child.Start(); err != nil {
			log.Fatalf("start %s: %v", child.Path, err)
		}
		var ws syscall.WaitStatus
		if _, err := syscall.Wait4(child.Process.Pid, &ws, 0, nil); err != nil || !ws.Stopped() {
			log.Fatalf("waiting for %s to stop at exec: %v (status %v)", child.Path, err, ws)
		}
		cfg.TargetTgid = uint32(child.Process.Pid) //nolint:gosec // a pid fits
	}

	p, err := probe.Load(cfg)
	if err != nil {
		if child != nil || cfg.TargetTgid != 0 {
			log.Fatalf("eBPF: %v (kernel 5.8+ with BTF and CAP_BPF, CAP_PERFMON are required)", err)
		}
		// In a pod the agent is a native sidecar the application waits
		// for: crashing here would hold the application back (a restart
		// loop never passes the startup probe). Fail open instead: serve
		// /healthz and the counters at zero, so the pod starts, the audit
		// alert on a sidecar that sees no lines fires, and
		// piishield_ebpf_attached says why.
		failOpen(ctx, *listen, err)
		return
	}
	defer func() { _ = p.Close() }()
	audit.Attached.Set(1)
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
		if err := syscall.PtraceDetach(child.Process.Pid); err != nil {
			log.Fatalf("continue %s: %v", child.Path, err)
		}
		runtime.UnlockOSThread()
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

// failOpen keeps the agent up without a probe: it logs why the program did
// not load, exports the audit series at zero with piishield_ebpf_attached
// 0, answers /healthz, and waits for the pod to stop.
func failOpen(ctx context.Context, listen string, loadErr error) {
	log.Printf("eBPF program not loaded, the agent watches nothing and counts nothing: %v (kernel 5.8+ with BTF and CAP_BPF, CAP_PERFMON are required); the pod's logs are not affected", loadErr)
	audit.New()
	audit.Attached.Set(0)
	srv := &http.Server{Addr: listen, Handler: metricsMux(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("metrics server: %v", err)
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

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
