package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pii-shield/pii-shield/v3/pkg/metrics"
	"github.com/pii-shield/pii-shield/v3/pkg/scanner"
)

// defaultPolicyReloadInterval is how often the sidecar looks at
// PII_CONFIG_FILE for a change when PII_CONFIG_RELOAD_SECONDS is unset. A
// ConfigMap mounted into a pod is refreshed by the kubelet about once a
// minute, so ten seconds adds little latency and no load.
const defaultPolicyReloadInterval = 10 * time.Second

// policyReloader applies the policy file at path to the scanner and
// re-applies it whenever the file changes. The environment is laid over the
// file on every load (ApplyEnvOverrides), so a PII_* variable set on the pod
// always wins, and the salt chosen at start is kept across reloads, so the
// tags of a running process never change because the rules did.
//
// A file that fails to parse is rejected whole and the previous config stays
// in force; the rejection is logged and counted. A file that is missing (a
// ConfigMap not created yet, mounted optional) is logged once and polled
// for, with the scanner running on the environment alone meanwhile.
type policyReloader struct {
	path    string
	salt    []byte
	metrics bool

	// seenModTime and seenSize describe the file as last examined, applied
	// or not, so a rejected file is not re-parsed on every tick.
	seenModTime time.Time
	seenSize    int64
	seen        bool

	missingLogged bool
	revision      string

	// stop ends the periodic check started by startPolicyReloader; tests
	// close it, the process never does.
	stop chan struct{}
}

// newPolicyReloader publishes the environment over the defaults, the same
// config package init built, and remembers its salt for later loads.
func newPolicyReloader(path string, metricsEnabled bool) *policyReloader {
	base := scanner.ApplyEnvOverrides(scanner.DefaultConfig())
	scanner.UpdateConfig(base)
	return &policyReloader{path: path, salt: base.Salt, metrics: metricsEnabled}
}

// check loads the file when it changed since the last check and reports
// whether a new config was published.
func (r *policyReloader) check() bool {
	fi, err := os.Stat(r.path)
	if err != nil {
		if !r.missingLogged {
			log.Printf("Policy file %s not readable, running on the environment alone until it appears: %v", r.path, err)
			r.missingLogged = true
		}
		return false
	}
	r.missingLogged = false
	// os.Stat follows symlinks, so the kubelet's atomic ConfigMap update
	// (a swap of the ..data symlink) shows up as a new modification time.
	if r.seen && fi.ModTime().Equal(r.seenModTime) && fi.Size() == r.seenSize {
		return false
	}
	r.seen, r.seenModTime, r.seenSize = true, fi.ModTime(), fi.Size()

	cfg, rev, err := scanner.LoadPolicyFile(r.path)
	if err != nil {
		log.Printf("Policy file %s rejected, keeping the previous config: %v", r.path, err)
		if r.metrics {
			metrics.ConfigReloadErrorsTotal.Inc()
		}
		return false
	}
	cfg.Salt = r.salt
	cfg = scanner.ApplyEnvOverrides(cfg)
	scanner.UpdateConfig(cfg)
	r.revision = rev
	if r.metrics {
		metrics.ConfigReloadsTotal.Inc()
		metrics.ConfigLastReloadTimestamp.SetToCurrentTime()
		metrics.ConfigRevisionInfo.Reset()
		metrics.ConfigRevisionInfo.WithLabelValues(rev).Set(1)
	}
	log.Printf("Policy file %s loaded (revision %q)", r.path, rev)
	return true
}

// run checks the file every interval until stop is closed (a nil stop runs
// for the life of the process).
func (r *policyReloader) run(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			r.check()
		}
	}
}

// parseReloadInterval reads PII_CONFIG_RELOAD_SECONDS: empty means the
// default, 0 disables the periodic check (the file is read once at start),
// anything else is a whole number of seconds.
func parseReloadInterval(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultPolicyReloadInterval, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("must be a whole number of seconds, 0 to disable")
	}
	return time.Duration(n) * time.Second, nil
}

// startPolicyReloader wires PII_CONFIG_FILE into the process: an initial
// load before the first line is read, then the periodic check. It returns
// nil when the variable is unset, and the scanner keeps the config package
// init built from the environment.
func startPolicyReloader(metricsEnabled bool) *policyReloader {
	path := os.Getenv("PII_CONFIG_FILE")
	if path == "" {
		return nil
	}
	interval, err := parseReloadInterval(os.Getenv("PII_CONFIG_RELOAD_SECONDS"))
	if err != nil {
		log.Printf("Invalid PII_CONFIG_RELOAD_SECONDS %q (%v), using %s", os.Getenv("PII_CONFIG_RELOAD_SECONDS"), err, defaultPolicyReloadInterval)
		interval = defaultPolicyReloadInterval
	}
	r := newPolicyReloader(path, metricsEnabled)
	r.stop = make(chan struct{})
	r.check()
	if interval > 0 {
		go r.run(interval, r.stop)
	}
	return r
}
