// Package signing defines what a publisher signs when a rule set is
// published, so a cluster can check that the file it pulled is the one a
// trusted person published and not one the server, or anything between
// the server and the cluster, made up.
//
// The key is the publisher's, never the server's: the panel keeps it in the
// browser that created it, a script keeps it in a file. The server stores
// the public half and the signatures, and refuses a signature that does
// not verify, but it cannot produce one. A server that is taken over can
// still refuse to serve, or keep serving the last signed file, but it
// cannot hand a cluster rules nobody signed.
//
// The signed message is a short text statement, not the file itself, so it
// can bind the file to the set it was published to and to a publication
// number that only grows. The operator refuses a statement for another set
// and one with a lower number than the last it accepted, so an old signed
// file cannot be replayed and one set's file cannot be served as another's.
// Rolling back is a new publication of an older revision, with a higher
// number, and is signed like any other.
//
// The operator verifies the same statement in
// operator/internal/remoterules/signature.go; the two must stay in step.
package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Header is the first line of every statement; the version changes if the
// statement ever does.
const Header = "pii-shield-policy-signature-v1"

// KeyPrefix starts the text form of a public key.
const KeyPrefix = "ed25519:"

// Statement is what a publisher signs for one publication.
type Statement struct {
	// Set is "<org>/<set>", the path of the set on the server.
	Set string `json:"set"`
	// Publication numbers the publications of the set from 1; it only grows.
	Publication int64 `json:"publication"`
	// Revision is the version being published.
	Revision int64 `json:"revision"`
	// SHA256 is the hex SHA-256 of the policy file exactly as served.
	SHA256 string `json:"sha256"`
}

// Text returns the bytes that are signed: five lines, each ending in a
// newline, in this order.
func (s Statement) Text() string {
	return Header + "\n" +
		"set: " + s.Set + "\n" +
		"publication: " + strconv.FormatInt(s.Publication, 10) + "\n" +
		"revision: " + strconv.FormatInt(s.Revision, 10) + "\n" +
		"sha256: " + s.SHA256 + "\n"
}

// For returns the statement for publishing content as the revision of set.
func For(set string, publication, revision int64, content []byte) Statement {
	sum := sha256.Sum256(content)
	return Statement{Set: set, Publication: publication, Revision: revision, SHA256: hex.EncodeToString(sum[:])}
}

// ParsePublicKey reads "ed25519:<base64 of the 32-byte key>".
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, KeyPrefix) {
		return nil, fmt.Errorf("public key must start with %q", KeyPrefix)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, KeyPrefix))
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// FormatPublicKey is the inverse of ParsePublicKey.
func FormatPublicKey(k ed25519.PublicKey) string {
	return KeyPrefix + base64.StdEncoding.EncodeToString(k)
}

// KeyID is a short, stable name of a public key: the first 8 bytes of its
// SHA-256 in hex. It is what a signature names and what a cluster reports.
func KeyID(k ed25519.PublicKey) string {
	sum := sha256.Sum256(k)
	return hex.EncodeToString(sum[:8])
}

// ErrBadSignature is returned when a signature does not verify.
var ErrBadSignature = errors.New("signature does not verify")

// Verify checks a base64 signature of the statement with the key.
func Verify(k ed25519.PublicKey, st Statement, sigB64 string) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if !ed25519.Verify(k, []byte(st.Text()), sig) {
		return ErrBadSignature
	}
	return nil
}
