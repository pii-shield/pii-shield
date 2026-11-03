package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The failure-mode tests of docs/sidecar-failure-modes.md: the sidecar runs
// as a subprocess in --watch-file mode (through the TEST_MAIN_WATCH hook of
// TestMainWatchFileSigterm) on a real file, and the test does to that file
// what a log rotation, an application restart or a sidecar restart does,
// then reads the sanitized output. Every line fed in carries a password, so
// a raw copy of any line in the output is a leak, and the "req N" prefix
// says which lines came out, in which order, and how many times.

const failureModeTimeout = 15 * time.Second

type watchSidecar struct {
	cmd    *exec.Cmd
	out    *lockedBuffer
	stderr *lockedBuffer
}

// startWatchSidecar starts the sidecar on path and returns it running.
func startWatchSidecar(t *testing.T, path string) *watchSidecar {
	t.Helper()
	s := &watchSidecar{out: &lockedBuffer{}, stderr: &lockedBuffer{}}
	s.cmd = exec.Command(os.Args[0], "-test.run=^TestMainWatchFileSigterm$")
	s.cmd.Env = append(os.Environ(), "TEST_MAIN_WATCH=1", "TEST_WATCH_FILE="+path)
	s.cmd.Stdout = s.out
	s.cmd.Stderr = s.stderr
	if err := s.cmd.Start(); err != nil {
		t.Fatalf("start sidecar: %v", err)
	}
	t.Cleanup(func() {
		if s.cmd.ProcessState == nil {
			_ = s.cmd.Process.Kill()
			_ = s.cmd.Wait()
		}
	})
	return s
}

// lines returns the sanitized lines written so far.
func (s *watchSidecar) lines() []string {
	text := strings.TrimRight(s.out.String(), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// waitLines waits until at least n sanitized lines are out and returns them.
func (s *watchSidecar) waitLines(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(failureModeTimeout)
	for {
		got := s.lines()
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited %v for %d sanitized lines, got %d: %q; stderr: %s", failureModeTimeout, n, len(got), got, s.stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// stop sends SIGTERM and waits for a clean exit.
func (s *watchSidecar) stop(t *testing.T) {
	t.Helper()
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("sidecar exit on SIGTERM: %v; stderr: %s", err, s.stderr.String())
		}
	case <-time.After(failureModeTimeout):
		_ = s.cmd.Process.Kill()
		t.Fatal("sidecar did not exit after SIGTERM")
	}
}

// logLine is what the application writes: a request number and a password.
func logLine(i int) string {
	return fmt.Sprintf("req %03d login ok password=Sw0rdf1sh%03dX done", i, i)
}

// appendLines writes the lines from..to (inclusive) to path as an
// application would, appending to the open file.
func appendLines(t *testing.T, path string, from, to int) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("open %s for append: %v", path, err)
	}
	defer f.Close()
	for i := from; i <= to; i++ {
		if _, err := io.WriteString(f, logLine(i)+"\n"); err != nil {
			t.Fatalf("write line %d: %v", i, err)
		}
	}
}

// checkSanitized asserts that out holds exactly the request numbers want, in
// that order, each with its password hidden and no password in the clear.
func checkSanitized(t *testing.T, out []string, want []int) {
	t.Helper()
	if len(out) != len(want) {
		t.Fatalf("got %d lines, want %d: %q", len(out), len(want), out)
	}
	for i, line := range out {
		if strings.Contains(line, "Sw0rdf1sh") {
			t.Errorf("line %d leaks the password: %q", i, line)
		}
		if !strings.Contains(line, "password=[HIDDEN") {
			t.Errorf("line %d has no marker: %q", i, line)
		}
		prefix := fmt.Sprintf("req %03d ", want[i])
		if !strings.HasPrefix(line, prefix) {
			t.Errorf("line %d is %q, want request %03d", i, line, want[i])
		}
	}
}

func seq(from, to int) []int {
	var s []int
	for i := from; i <= to; i++ {
		s = append(s, i)
	}
	return s
}

// TestWatchFileRotationRename: logrotate's default, the file is renamed
// away and the application opens a new one under the old name. The sidecar
// must follow to the new file and hide every line of both.
func TestWatchFileRotationRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := startWatchSidecar(t, path)
	appendLines(t, path, 1, 3)
	s.waitLines(t, 3)

	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	appendLines(t, path, 4, 6)
	out := s.waitLines(t, 6)
	s.stop(t)
	checkSanitized(t, s.lines(), seq(1, 6))
	_ = out
}

// TestWatchFileRotationTruncate: logrotate's copytruncate, the file is
// copied away and cut to zero in place; the application keeps its handle and
// writes on. The sidecar must notice the cut and read the new lines from the
// start of the file.
func TestWatchFileRotationTruncate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := startWatchSidecar(t, path)
	appendLines(t, path, 1, 3)
	s.waitLines(t, 3)

	if err := os.Truncate(path, 0); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	appendLines(t, path, 4, 5)
	s.waitLines(t, 5)
	s.stop(t)
	checkSanitized(t, s.lines(), seq(1, 5))
}

// TestWatchFileAppRestartRecreate: the application restarts and its log
// file is removed and created again (a fresh emptyDir file after a container
// restart). The sidecar must wait for the new file and continue on it.
func TestWatchFileAppRestartRecreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := startWatchSidecar(t, path)
	appendLines(t, path, 1, 3)
	s.waitLines(t, 3)

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	appendLines(t, path, 4, 6)
	s.waitLines(t, 6)
	s.stop(t)
	checkSanitized(t, s.lines(), seq(1, 6))
}

// TestWatchFileSidecarRestartReplaysFromStart pins what a sidecar restart
// does to a file that outlives it (the shared emptyDir does): the sidecar
// keeps no read offset, so the new process reads the file from its first
// line again. Nothing written while it was down is lost, and every line read
// before the restart is emitted a second time. Downstream deduplication, or
// a rotation before the restart, is what keeps the duplicates out.
func TestWatchFileSidecarRestartReplaysFromStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	appendLines(t, path, 1, 3)

	first := startWatchSidecar(t, path)
	first.waitLines(t, 3)
	first.stop(t)
	checkSanitized(t, first.lines(), seq(1, 3))

	appendLines(t, path, 4, 5)
	second := startWatchSidecar(t, path)
	second.waitLines(t, 5)
	second.stop(t)
	checkSanitized(t, second.lines(), seq(1, 5))
}

// TestWatchFileDownstreamClosed: the reader of the sidecar's stdout goes
// away (the container runtime's log pipe, or a collector reading the
// stream). A write to the closed pipe must end the process instead of
// leaving it running with nowhere to put the sanitized lines, so that the
// kubelet restarts it; nothing is written in the clear anywhere.
func TestWatchFileDownstreamClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainWatchFileSigterm$")
	cmd.Env = append(os.Environ(), "TEST_MAIN_WATCH=1", "TEST_WATCH_FILE="+path)
	stderr := &lockedBuffer{}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	// Prove it is up: one line in, its sanitized copy out.
	appendLines(t, path, 1, 1)
	buf := make([]byte, 4096)
	n, err := stdout.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "password=[HIDDEN") {
		t.Fatalf("first line not sanitized: %q, %v; stderr: %s", buf[:n], err, stderr.String())
	}
	// The reader goes away; the next writes hit a closed pipe.
	if err := stdout.Close(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.After(failureModeTimeout)
	for i := 2; ; i++ {
		appendLines(t, path, i, i)
		select {
		case err := <-done:
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("sidecar exited without an error after its stdout closed: %v", err)
			}
			if strings.Contains(stderr.String(), "Sw0rdf1sh") {
				t.Errorf("stderr carries a password: %s", stderr.String())
			}
			return
		case <-deadline:
			t.Fatalf("sidecar kept running %v after its stdout reader closed; stderr: %s", failureModeTimeout, stderr.String())
		case <-time.After(200 * time.Millisecond):
		}
	}
}
