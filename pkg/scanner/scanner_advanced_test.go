package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestScanner_HighEntropySafeData checks if the scanner falsely flags safe high-entropy data.
func TestScanner_HighEntropySafeData(t *testing.T) {
	safeData := []struct {
		name  string
		input string
	}{
		{
			name:  "Minified JS",
			input: `function(a,b){return a.length>b.length?a:b}var x="xkcd";`,
		},
		{
			name:  "Git Object Hash",
			input: "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904",
		},
		{
			name:  "MongoDB ObjectID",
			input: `{"_id": "507f1f77bcf86cd799439011"}`,
		},
		{
			name:  "CSS Map (Partial)",
			input: `{"version":3,"file":"out.js","sourceRoot":"","sources":["foo.js","bar.js"],"names":["src","maps","are","fun"],"mappings":"AAgFA,IAAI,IAAS,GAAG,IAAI,KAAK,CAAC,CAAC,CAAC,CAAC,CAAC,CAAC,CAAC,CAAC,CAAC"}`,
		},
		{
			name:  "Base64 Public Key (SSH)",
			input: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0g+Z",
		},
		{
			name:  "Kubernetes SelfLink",
			input: `selfLink: /api/v1/namespaces/kube-system/pods/coredns-558bd4d5db-t2j6z`,
		},
	}

	// The default config: these used to run at a 3.8 threshold under a
	// "default config" comment, which checked false positives under a looser
	// setting than the one shipped (3.6).
	savedCfg := activeCfg()
	UpdateConfig(campaignConfig())
	defer UpdateConfig(savedCfg)

	for _, tt := range safeData {
		t.Run(tt.name, func(t *testing.T) {
			got := ScanAndRedact(tt.input)
			// WE EXPECT 0 REDACTIONS for this safe data
			if strings.Contains(got, "[HIDDEN:") {
				t.Errorf("False Positive! Safe data was redacted.\nInput: %s\nOutput: %s", tt.input, got)
			}
			// Basic integrity check: Length shouldn't change dramatically (unless redacted)
			// Check for corruption via DeepEqual (handles key reordering and whitespace)
			var inObj, outObj interface{}
			// Try unmarshal both
			errIn := json.Unmarshal([]byte(tt.input), &inObj)
			errOut := json.Unmarshal([]byte(got), &outObj)

			if errIn == nil && errOut == nil {
				// It's JSON. Compare objects.
				// Note: json.Unmarshal might convert numbers to float64.
				// But input/output should match.
				// We can't use reflect.DeepEqual directly if specific types changed?
				// But for SAFE data, nothing should change.
				// Except... int -> float64? json decoding does that by default.
				// But we decode BOTH input and output using default decoder.
				// So they should match.
				// Wait, DeepEqual might fail on formatting details? No, it compares values.

				// Simple fallback: Check string containment of critical values?
				// Or compare length of re-serialized canonical JSON?
				// Canonical: marshal(unmarshal(str))

				canIn, _ := json.Marshal(inObj)
				canOut, _ := json.Marshal(outObj)
				if string(canIn) != string(canOut) {
					t.Errorf("Output data corrupted (object mismatch).\nIn:  %s\nOut: %s", canIn, canOut)
				}
			} else {
				// Not JSON (e.g. Git Hash, Minified JS). Fallback to normalized string check.
				normInput := strings.ReplaceAll(tt.input, " ", "")
				normOutput := strings.ReplaceAll(got, " ", "")
				if normInput != normOutput {
					t.Errorf("Output data corrupted (mismatch).\nIn:  %q\nOut: %q", normInput, normOutput)
				}
			}
		})
	}
}

// TestScanner_JSONIntegrity verifies that JSON structure survives scanning,
// even if values are redacted.
func TestScanner_JSONIntegrity(t *testing.T) {
	inputs := []string{
		`{"user": "alice", "pass": "supersecret123"}`, // Simple
		`{"nested": {"key": "value", "id": 123}}`,     // Nested
		`[{"id": 1}, {"id": 2, "token": "abcdef"}]`,   // Array of objects
		`{"quoted": "he said \"hello\" world"}`,       // Escaped quotes
		`{"empty": ""}`,
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			output := ScanAndRedact(input)

			// 1. Verify it is still valid JSON
			var js interface{}
			if err := json.Unmarshal([]byte(output), &js); err != nil {
				t.Errorf("Scanner broke JSON validity!\nInput:  %s\nOutput: %s\nError:  %v", input, output, err)
			}

			// 2. Verify structure preservation (keys must exist)
			// (Simple string check for keys)
			// e.g. "user" should still be there
			if strings.Contains(input, "\"user\"") && !strings.Contains(output, "\"user\"") {
				t.Errorf("JSON key 'user' vanished from output: %s", output)
			}
		})
	}
}
