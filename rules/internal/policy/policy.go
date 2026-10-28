// Package policy turns a rule set submitted to the server into the file a
// cluster pulls: validated whole with the scanner's own parser, so the
// server rejects exactly what the sidecar would, and written in a canonical
// form with the version number in revision, so the ETag is a hash of the
// bytes every cluster receives.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/pii-shield/pii-shield/v2/pkg/scanner"
)

// MaxBytes bounds a submitted rule set. It matches the operator's limit on
// a remote file, so a set the server accepts is a set every cluster accepts.
const MaxBytes = 256 << 10

// Document is one canonical policy file with its ETag and the scanner
// configuration it parses into (no salt: that stays with the pod).
type Document struct {
	Content []byte
	ETag    string
	Config  scanner.Config
}

// Canonical validates content, a rule set in the SDK init_config format,
// and returns it as the file revision n of the set. The scanner's parser
// decides what is valid, all or nothing. A salt or fail_policy is refused
// outright: they are settings of the pod, and a server that handed them
// out would only have them ignored by the sidecar. Keys are sorted and the
// numbers kept as written, so the same rules always produce the same bytes
// and the same ETag.
func Canonical(content []byte, revision int64) (Document, error) {
	if len(content) > MaxBytes {
		return Document{}, fmt.Errorf("rule set larger than %d bytes", MaxBytes)
	}
	// Decoded into generic values and marshalled again: encoding/json sorts
	// map keys at every level and json.Number keeps 4.20 as written.
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return Document{}, fmt.Errorf("invalid json: %w", err)
	}
	if dec.More() {
		return Document{}, errors.New("invalid json: trailing data after the object")
	}
	if raw == nil {
		return Document{}, errors.New("invalid json: the rule set must be an object, not null")
	}
	for _, k := range []string{"salt", "fail_policy"} {
		if v, ok := raw[k]; ok && v != nil && v != "" {
			return Document{}, fmt.Errorf("%s is not a rule and cannot be served; it comes from the pod spec", k)
		}
		delete(raw, k)
	}
	raw["revision"] = strconv.FormatInt(revision, 10)

	out, err := json.Marshal(raw)
	if err != nil {
		return Document{}, err
	}
	cfg, _, err := scanner.ParsePolicyJSON(out)
	if err != nil {
		return Document{}, err
	}
	return Document{Content: out, ETag: ETag(out), Config: cfg}, nil
}

// ETag returns the strong entity tag of a file: a quoted hash of its bytes.
func ETag(b []byte) string {
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}
