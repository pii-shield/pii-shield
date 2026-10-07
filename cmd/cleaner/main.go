package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/nxadm/tail"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/pii-shield/pii-shield/v2/pkg/metrics"
	"github.com/pii-shield/pii-shield/v2/pkg/scanner"
)

func main() {
	metricsEnabled := os.Getenv("PII_METRICS_ENABLED") == "true"

	// Optional periodic value-metrics summary in the logs (STR-2.2). Opt-in via
	// PII_STATS_LOG_INTERVAL so default log output is unchanged.
	statsInterval := parseStatsInterval(os.Getenv("PII_STATS_LOG_INTERVAL"))
	if raw := os.Getenv("PII_STATS_LOG_INTERVAL"); raw != "" && statsInterval == 0 {
		log.Printf("Invalid PII_STATS_LOG_INTERVAL %q, stats summary disabled", raw)
	}
	if statsInterval > 0 {
		stats = newStatsCollector()
	}

	// A single callback fans out to metrics and/or the stats summary.
	if metricsEnabled || stats != nil {
		scanner.RedactionCallback = func(strategy string) {
			if metricsEnabled {
				metrics.IncrementRedaction(strategy)
			}
			if stats != nil {
				stats.recordRedaction(strategy)
			}
		}
	}

	var metricsSrv *http.Server
	if metricsEnabled {
		port, err := resolveMetricsPort(os.Getenv("PII_METRICS_PORT"))
		if err != nil {
			// The sidecar's job is sanitizing logs; a bad metrics port must not
			// take the log pipeline down with it (fail-open, matching the
			// non-fatal handling of a metrics listen failure below).
			log.Printf("Invalid PII_METRICS_PORT, metrics server disabled: %v", err)
		} else {
			metricsSrv = newMetricsServer(port)
			go func() {
				log.Printf("Starting Prometheus metrics server on :%s", port)
				if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Printf("Metrics server failed: %v", err)
				}
			}()
		}
	}
	stopMetrics := func() { shutdownMetricsServer(metricsSrv, metricsShutdownGrace) }

	// finalize runs on every shutdown path: emit a last stats summary (if enabled)
	// and drain the metrics server.
	finalize := func() {
		if stats != nil {
			log.Print(stats.summary())
		}
		stopMetrics()
	}

	if stats != nil {
		go func() {
			ticker := time.NewTicker(statsInterval)
			defer ticker.Stop()
			for range ticker.C {
				log.Print(stats.summary())
			}
		}()
	}

	failPolicy := os.Getenv("PII_FAIL_POLICY")
	if failPolicy == "" {
		failPolicy = "open" // Start with fail-open by default
	}

	var watchFile string
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "--watch-file" && i+1 < len(os.Args) {
			watchFile = os.Args[i+1]
			break
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	if watchFile != "" {
		// Smart wait: poll until the target file is created by the main container
		for {
			if _, err := os.Stat(watchFile); err == nil {
				break
			}
			select {
			case <-sigChan:
				finalize()
				os.Exit(0)
			case <-time.After(500 * time.Millisecond):
			}
		}

		// A FIFO (pipe injection mode) cannot be followed with tail: the tail
		// library targets regular growing files and closes its Lines channel as
		// soon as it hits EOF on the empty pipe, so the sidecar exits and
		// crash-loops before any writer connects (the pod never becomes Ready).
		// Read the named pipe directly instead.
		if isNamedPipe(watchFile) {
			go func() {
				<-sigChan
				finalize()
				os.Exit(0)
			}()
			readFIFO(watchFile, metricsEnabled, failPolicy, os.Stdout, nil)
			return
		}

		t, err := tail.TailFile(watchFile, tail.Config{
			Follow:    true,
			ReOpen:    true,
			MustExist: true,
			Logger:    tail.DiscardingLogger,
		})
		if err != nil {
			log.Fatalf("Failed to tail file: %v", err)
		}

		go func() {
			<-sigChan
			if err := t.Stop(); err != nil {
				log.Printf("Failed to stop tail: %v", err)
			}
		}()

		for line := range t.Lines {
			if line.Err != nil {
				continue
			}
			processLine(line.Text, metricsEnabled, failPolicy, os.Stdout)
		}
		finalize()
	} else {
		// Legacy Stdin mode
		reader := bufio.NewScanner(os.Stdin)
		buf := make([]byte, 1024*1024)
		reader.Buffer(buf, 10*1024*1024)

		go func() {
			<-sigChan
			finalize()
			os.Exit(0)
		}()

		for reader.Scan() {
			processLine(reader.Text(), metricsEnabled, failPolicy, os.Stdout)
		}

		if err := reader.Err(); err != nil {
			if metricsEnabled {
				metrics.ErrorsTotal.Inc()
			}
			if err == bufio.ErrTooLong {
				if failPolicy == "closed" {
					fmt.Println("[PII_SHIELD_DROP: BUFFER_OVERFLOW]")
				} else {
					fmt.Println("[PII_SHIELD_WARN: BUFFER_OVERFLOW, STREAM_BROKEN]")
				}
			}
			fmt.Fprintln(os.Stderr, "Error reading standard input:", err)
			finalize()
			os.Exit(1)
		}
		finalize()
	}
}

const (
	defaultMetricsPort   = "9090"
	metricsShutdownGrace = 3 * time.Second
)

// resolveMetricsPort validates the PII_METRICS_PORT value, falling back to the
// default when unset.
func resolveMetricsPort(raw string) (string, error) {
	if raw == "" {
		return defaultMetricsPort, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("must be an integer between 1 and 65535, got %q", raw)
	}
	return raw, nil
}

// newMetricsServer builds the metrics HTTP server on a dedicated mux with
// bounded timeouts. Besides /metrics it exposes /healthz so the CLI can serve
// as a readiness/liveness target when running as a long-lived sidecar.
func newMetricsServer(port string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// shutdownMetricsServer drains in-flight scrapes before the process exits; a
// scrape hanging past the grace period must not block sidecar termination.
func shutdownMetricsServer(srv *http.Server, grace time.Duration) {
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Metrics server shutdown: %v", err)
	}
}

// isNamedPipe reports whether path is a FIFO (pipe injection mode), as opposed
// to a regular file (file injection mode).
func isNamedPipe(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode()&os.ModeNamedPipe != 0
}

// readFIFO continuously sanitizes lines read from a named pipe, writing the
// sanitized stream to out. Opening the FIFO read-only blocks until a writer
// connects, which keeps the sidecar running so the pod reaches Ready. When the
// writer closes the pipe (EOF) the FIFO is reopened to block for the next
// writer.
//
// Closing stop ends the loop after the current writer disconnects; a nil stop
// (the sidecar's own usage, which ends via SIGTERM/SIGINT and the os.Exit
// goroutine installed by the caller) loops forever. Because a pending open
// blocks in the kernel until a writer connects, stop is only observed between
// opens: to guarantee prompt exit a caller closes stop and then opens the FIFO
// for writing to release the pending open. That nudge must be non-blocking
// (O_NONBLOCK) and retried until the loop exits, since a blocking open for
// write would itself hang once the loop has already stopped reading.
func readFIFO(path string, metricsEnabled bool, failPolicy string, out io.Writer, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		if err := streamPipeOnce(path, metricsEnabled, failPolicy, out); err != nil {
			log.Fatalf("Failed to open pipe %s: %v", path, err)
		}
		// Writer closed the pipe; loop to reopen and block for the next writer.
	}
}

// streamPipeOnce opens the FIFO (blocking until a writer connects), sanitizes
// every line into out until the writer closes the pipe (EOF), then returns. It
// returns a non-nil error only if the pipe could not be opened.
func streamPipeOnce(path string, metricsEnabled bool, failPolicy string, out io.Writer) error {
	f, err := os.OpenFile(path, os.O_RDONLY, os.ModeNamedPipe)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	buf := make([]byte, 1024*1024)
	sc.Buffer(buf, 10*1024*1024)

	for sc.Scan() {
		processLine(sc.Text(), metricsEnabled, failPolicy, out)
	}

	if err := sc.Err(); err != nil {
		if metricsEnabled {
			metrics.ErrorsTotal.Inc()
		}
		if err == bufio.ErrTooLong {
			if failPolicy == "closed" {
				_, _ = fmt.Fprintln(out, "[PII_SHIELD_DROP: BUFFER_OVERFLOW]")
			} else {
				_, _ = fmt.Fprintln(out, "[PII_SHIELD_WARN: BUFFER_OVERFLOW, STREAM_BROKEN]")
			}
		}
		fmt.Fprintln(os.Stderr, "Error reading pipe:", err)
	}

	return nil
}

func processLine(text string, metricsEnabled bool, failPolicy string, out io.Writer) {
	// Functional wrapper to catch panics per-line
	func() {
		defer func() {
			if r := recover(); r != nil {
				if metricsEnabled {
					metrics.ErrorsTotal.Inc()
				}
				// Apply Blast Radius Control Policy
				if failPolicy == "closed" {
					_, _ = fmt.Fprintln(out, "[PII_SHIELD_DROP: FATAL_ERROR]")
				} else {
					// Fail-Open: keep the flow alive
					_, _ = fmt.Fprintln(out, text)
				}
			}
		}()

		var start time.Time
		if metricsEnabled {
			start = time.Now()
			metrics.ProcessedBytesTotal.Add(float64(len(text)))
		}
		if stats != nil {
			stats.recordLine(len(text))
		}

		// Core logic
		cleaned := scanner.ScanAndRedact(text)

		if metricsEnabled {
			metrics.ProcessingDuration.Observe(time.Since(start).Seconds())
		}

		// Write back to Stdout for Fluentd/Logstash
		_, _ = fmt.Fprintln(out, cleaned)
	}()
}
