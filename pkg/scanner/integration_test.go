package scanner

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "update golden files")

func TestGolden(t *testing.T) {
	matches, err := filepath.Glob("testdata/*.input")
	if err != nil {
		t.Fatal(err)
	}

	for _, inputPath := range matches {
		name := filepath.Base(inputPath)
		t.Run(name, func(t *testing.T) {
			// FORCE DETERMINISTIC SALT for golden file stability, on the
			// shipped defaults rather than whatever an earlier test left,
			// and restore the previous config afterwards.
			old := activeCfg()
			t.Cleanup(func() { UpdateConfig(old) })
			cfg := campaignConfig()
			cfg.Salt = []byte("integration-test-salt-1234567890")
			UpdateConfig(cfg)

			inputBytes, err := os.ReadFile(inputPath)
			if err != nil {
				t.Fatalf("failed to read input file: %v", err)
			}

			// Run scanner on the entire file content
			// Assuming file contains one log line per line, or we process the whole block.
			// ScanAndRedact processes a single line or string.
			// If input file has multiple lines, we might want to split?
			// Let's assume input file is a multi-line log dump.
			// ScanAndRedact typically handles one line.
			// Ideally we should split by newline and process.

			lines := strings.Split(string(inputBytes), "\n")
			var outputLines []string
			for _, line := range lines {
				if len(line) == 0 {
					outputLines = append(outputLines, "")
					continue
				}
				outputLines = append(outputLines, ScanAndRedact(line))
			}
			got := strings.Join(outputLines, "\n")

			goldenPath := strings.TrimSuffix(inputPath, ".input") + ".golden"

			if *update {
				err := os.WriteFile(goldenPath, []byte(got), 0644)
				if err != nil {
					t.Fatalf("failed to update golden file: %v", err)
				}
			}

			expectedBytes, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("failed to read golden file: %v", err)
			}
			expected := string(expectedBytes)

			if got != expected {
				// Simple diff output
				t.Errorf("Golden mismatch for %s.\nExpected:\n%s\nGot:\n%s", name, expected, got)
				// PRO TIP: Use a diff library or just print length diff
			}
		})
	}
}
