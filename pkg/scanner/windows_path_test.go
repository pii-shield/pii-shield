package scanner

import (
	"testing"
)

func TestReproWindowsPathRedaction(t *testing.T) {
	// The log line reported by the user
	line := `2026-02-08 20:07:02: Running - app\modules\adaptive\jobs\TestingInstanceJob`

	// We expect it NOT to be redacted. Before the fix it came back as
	// `2026-02-08 20:07:02: Running - [HIDDEN:f329a5]`.

	processed := ScanAndRedact(line)

	if processed != line {
		t.Errorf("Expected no redaction, but got:\n%s\nOriginal:\n%s", processed, line)
	}
}
