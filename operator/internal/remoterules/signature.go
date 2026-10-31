package remoterules

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Reasons a signature check fails, used as condition reasons.
const (
	ReasonSignatureMissing   = "SignatureMissing"
	ReasonSignatureInvalid   = "SignatureInvalid"
	ReasonSignatureUntrusted = "SignatureUntrusted"
	ReasonSignatureReplayed  = "SignatureReplayed"
	ReasonSignatureConfig    = "SignatureConfig"
)

// statementHeader starts the signed statement. The statement is defined by
// the rule server (rules/internal/signing); the two must stay in step.
const statementHeader = "pii-shield-policy-signature-v1"

const keyPrefix = "ed25519:"

// TrustedKey is a public key from spec.remoteConfig.signature.publicKeys.
type TrustedKey struct {
	ID  string
	Key ed25519.PublicKey
}

// ParseTrustedKeys reads "ed25519:<base64 of 32 bytes>" keys.
func ParseTrustedKeys(keys []string) ([]TrustedKey, error) {
	out := make([]TrustedKey, 0, len(keys))
	for i, s := range keys {
		s = strings.TrimSpace(s)
		if !strings.HasPrefix(s, keyPrefix) {
			return nil, fmt.Errorf("publicKeys[%d] must start with %q", i, keyPrefix)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, keyPrefix))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("publicKeys[%d] is not a base64 Ed25519 public key of %d bytes", i, ed25519.PublicKeySize)
		}
		out = append(out, TrustedKey{ID: KeyID(raw), Key: raw})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("publicKeys is empty")
	}
	return out, nil
}

// KeyID names a key: the first 8 bytes of its SHA-256 in hex.
func KeyID(k ed25519.PublicKey) string {
	sum := sha256.Sum256(k)
	return hex.EncodeToString(sum[:8])
}

// SignatureURL returns the explicit URL or the file's URL with ".sig"
// appended to its path.
func SignatureURL(fileURL, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	u, err := url.Parse(fileURL)
	if err != nil {
		return "", err
	}
	u.Path += ".sig"
	if u.RawPath != "" {
		u.RawPath += ".sig"
	}
	return u.String(), nil
}

// ExpectedSet returns the explicit set name or derives "<org>/<set>" from a
// rule server URL ending in /v1/<org>/<set>/policy.json.
func ExpectedSet(fileURL, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	u, err := url.Parse(fileURL)
	if err != nil {
		return "", err
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	n := len(parts)
	if n >= 4 && parts[n-4] == "v1" && parts[n-1] == "policy.json" {
		return parts[n-3] + "/" + parts[n-2], nil
	}
	return "", fmt.Errorf("cannot tell the set from %q; set signature.set to the name the statement carries", fileURL)
}

// SignatureFile is the body of a .sig: the statement fields, the key id
// and the base64 signature.
type SignatureFile struct {
	Set         string `json:"set"`
	Publication int64  `json:"publication"`
	Revision    int64  `json:"revision"`
	SHA256      string `json:"sha256"`
	KeyID       string `json:"keyId"`
	Signature   string `json:"signature"`
}

// Verified is a file whose signature checked out.
type Verified struct {
	Publication int64
	KeyID       string
}

// Check verifies body against its signature file. The statement is rebuilt
// from what the operator knows, the set it expects and the hash of the body
// it pulled, and only the publication number and revision are taken from
// the signature file; minPublication is the number of the last file it
// accepted, and a lower one is a replay.
func Check(sigBody, body []byte, set string, keys []TrustedKey, minPublication int64) (Verified, error) {
	var sf SignatureFile
	if err := json.Unmarshal(sigBody, &sf); err != nil {
		return Verified{}, fail(ReasonSignatureInvalid, "signature file: %v", err)
	}
	var key *TrustedKey
	for i := range keys {
		if keys[i].ID == sf.KeyID {
			key = &keys[i]
		}
	}
	if key == nil {
		return Verified{}, fail(ReasonSignatureUntrusted, "signed with key %q, which is not in signature.publicKeys", sf.KeyID)
	}
	sum := sha256.Sum256(body)
	text := statementHeader + "\n" +
		"set: " + set + "\n" +
		"publication: " + strconv.FormatInt(sf.Publication, 10) + "\n" +
		"revision: " + strconv.FormatInt(sf.Revision, 10) + "\n" +
		"sha256: " + hex.EncodeToString(sum[:]) + "\n"
	sig, err := base64.StdEncoding.DecodeString(sf.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key.Key, []byte(text), sig) {
		return Verified{}, fail(ReasonSignatureInvalid, "the signature by key %s does not match this file for set %q, publication %d", sf.KeyID, set, sf.Publication)
	}
	if sf.Publication < minPublication {
		return Verified{}, fail(ReasonSignatureReplayed, "publication %d is older than %d, the last one accepted", sf.Publication, minPublication)
	}
	return Verified{Publication: sf.Publication, KeyID: sf.KeyID}, nil
}

// FetchSignature pulls the signature file with the same credentials as the
// policy file. A 404 means the publication is not signed.
func FetchSignature(ctx context.Context, src Source, sigURL string) ([]byte, error) {
	src.URL = sigURL
	src.ETag = ""
	res, err := Fetch(ctx, src)
	if err != nil {
		return nil, &Error{Reason: ReasonSignatureMissing, Err: fmt.Errorf("signature: %w", err)}
	}
	return res.Body, nil
}
