package webhook

import (
	"os"
	"testing"
)

// TestMain clears the environment the mutator reads at runtime. In a pod
// these come from the operator Deployment; in a developer's shell or a CI
// runner they are leftovers, and each of them alone turned a test red
// (audit 2026-09-25). Tests that need one set it with t.Setenv.
func TestMain(m *testing.M) {
	for _, k := range []string{"STRICT_MODE", "LEGACY_SIDECAR_MODE", "AGENT_SALT_SECRET_NAME", "AGENT_SALT_SECRET_KEY"} {
		_ = os.Unsetenv(k)
	}
	os.Exit(m.Run())
}
