package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/pii-shield/pii-shield/v3/pkg/scanner"

	"github.com/pii-shield/pii-shield/rules/internal/policy"
	"github.com/pii-shield/pii-shield/rules/internal/store"
)

// MaxPreviewLines bounds the log lines of one preview request.
const MaxPreviewLines = 200

// maxPreviewBody bounds a preview request: a rule set plus the lines.
const maxPreviewBody = policy.MaxBytes + 512<<10

// previewSalt is the salt of every preview. It is public by design: a
// preview shows where a rule fires and how a line looks afterwards, and
// its hashes must not be mistaken for a cluster's, whose salt the server
// never sees.
var previewSalt = []byte("pii-shield-rules-preview-salt-not-a-cluster-salt")

const previewNote = "hashes are computed with a preview salt and match no cluster"

// draftRequest carries the rule set of a validate or preview call. Content
// is the draft in the SDK init_config format; a preview without one runs
// the set's published version.
type draftRequest struct {
	Content json.RawMessage `json:"content"`
}

type previewRequest struct {
	draftRequest
	// Lines are the log lines to scan, at most MaxPreviewLines.
	Lines []string `json:"lines"`
	// Text is the same input as one string split on newlines, for a
	// textarea or a curl with a file; one of Lines and Text is set.
	Text *string `json:"text"`
}

// validateResponse reports a draft that the sidecar would accept, with the
// effective settings after defaults so the author sees what a cluster will
// run, not only what the draft spells out.
type validateResponse struct {
	OK                   bool    `json:"ok"`
	Bytes                int     `json:"bytes"`
	EntropyThreshold     float64 `json:"entropyThreshold"`
	ConfidenceThreshold  float64 `json:"confidenceThreshold"`
	MinSecretLength      int     `json:"minSecretLength"`
	SensitiveKeys        int     `json:"sensitiveKeys"`
	SensitiveKeyPatterns int     `json:"sensitiveKeyPatterns"`
	CustomRegexes        int     `json:"customRegexes"`
	SafeRegexes          int     `json:"safeRegexes"`
	DisableBigramCheck   bool    `json:"disableBigramCheck"`
	AdaptiveThreshold    bool    `json:"adaptiveThreshold"`
	EntityTypeLabels     bool    `json:"entityTypeLabels"`
}

type previewLine struct {
	In      string `json:"in"`
	Out     string `json:"out"`
	Changed bool   `json:"changed"`
}

type previewResponse struct {
	// Source names the rules that ran: "draft" or "published".
	Source string `json:"source"`
	// Revision is the published revision when Source is "published".
	Revision int64         `json:"revision,omitempty"`
	Lines    []previewLine `json:"lines"`
	Changed  int           `json:"changed"`
	Note     string        `json:"note"`
}

// validate runs the checks of a version create on a draft without storing
// anything: canonical form, size, the scanner's parser. The answer is the
// same 422 a create would give, so the panel has one error shape, or the
// effective settings of an accepted draft.
func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.set(w, r); !ok {
		return
	}
	var req draftRequest
	if !s.decode(w, r, &req) {
		return
	}
	doc, ok := s.draft(w, req)
	if !ok {
		return
	}
	s.json(w, http.StatusOK, summarize(doc))
}

func summarize(doc policy.Document) validateResponse {
	c := doc.Config
	return validateResponse{
		OK:                   true,
		Bytes:                len(doc.Content),
		EntropyThreshold:     c.EntropyThreshold,
		ConfidenceThreshold:  c.ConfidenceThreshold,
		MinSecretLength:      c.MinSecretLength,
		SensitiveKeys:        len(c.SensitiveKeys),
		SensitiveKeyPatterns: len(c.SensitiveKeyPatterns),
		CustomRegexes:        len(c.CustomRegexes),
		SafeRegexes:          len(c.SafeRegexes),
		DisableBigramCheck:   c.DisableBigramCheck,
		AdaptiveThreshold:    c.AdaptiveThreshold,
		EntityTypeLabels:     c.EntityTypeLabels,
	}
}

// preview scans up to MaxPreviewLines log lines with a draft rule set, or
// with the published version when no draft is sent, on a scanner built
// for this request alone (scanner.NewScanner), so nothing touches the
// process-wide configuration and two previews never see each other's
// rules. The salt is a fixed preview salt; the response says so.
func (s *Server) preview(w http.ResponseWriter, r *http.Request) {
	set, ok := s.set(w, r)
	if !ok {
		return
	}
	var req previewRequest
	if !s.decodeLimit(w, r, &req, maxPreviewBody) {
		return
	}
	lines, ok := s.previewLines(w, req)
	if !ok {
		return
	}

	resp := previewResponse{Source: "draft", Note: previewNote}
	var cfg scanner.Config
	if hasDraft(req.Content) {
		doc, ok := s.draft(w, req.draftRequest)
		if !ok {
			return
		}
		cfg = doc.Config
	} else {
		v, err := s.store.Published(r.Context(), set.ID)
		if errors.Is(err, store.ErrNotPublished) {
			s.fail(w, http.StatusNotFound, `nothing published to preview; send "content" with a draft rule set`)
			return
		}
		if err != nil {
			s.internal(w, err)
			return
		}
		cfg, _, err = scanner.ParsePolicyJSON(v.Content)
		if err != nil {
			s.internal(w, fmt.Errorf("stored revision %d no longer parses: %w", v.Revision, err))
			return
		}
		resp.Source, resp.Revision = "published", v.Revision
	}
	cfg.Salt = previewSalt
	if cfg.AdaptiveThreshold {
		// The adaptive mode learns a threshold from the stream it sees,
		// through state shared by the whole process; a preview has no
		// stream and must not learn from another preview.
		cfg.AdaptiveThreshold = false
		resp.Note += "; adaptive_threshold is off in a preview, it learns from a running stream"
	}
	sc := scanner.NewScanner(cfg)

	resp.Lines = make([]previewLine, 0, len(lines))
	for _, in := range lines {
		out := sc.ScanAndRedactText(in)
		changed := out != in
		if changed {
			resp.Changed++
		}
		resp.Lines = append(resp.Lines, previewLine{In: in, Out: out, Changed: changed})
	}
	s.json(w, http.StatusOK, resp)
}

// draft canonicalizes a submitted rule set the way a version create does,
// answering 422 with the scanner's reason when it is refused.
func (s *Server) draft(w http.ResponseWriter, req draftRequest) (policy.Document, bool) {
	if len(req.Content) == 0 {
		s.fail(w, http.StatusBadRequest, `"content" is required: the rule set as a JSON object`)
		return policy.Document{}, false
	}
	doc, err := policy.Canonical(req.Content, 0)
	if err != nil {
		s.fail(w, http.StatusUnprocessableEntity, "rule set rejected: "+err.Error())
		return policy.Document{}, false
	}
	return doc, true
}

// hasDraft reports whether a request carries a rule set; a null is none.
func hasDraft(content json.RawMessage) bool {
	return len(content) > 0 && string(bytes.TrimSpace(content)) != "null"
}

// previewLines takes the lines of a preview from "lines" or "text".
func (s *Server) previewLines(w http.ResponseWriter, req previewRequest) ([]string, bool) {
	lines := req.Lines
	switch {
	case req.Text != nil && lines != nil:
		s.fail(w, http.StatusBadRequest, `send "lines" or "text", not both`)
		return nil, false
	case req.Text != nil:
		lines = strings.Split(strings.TrimSuffix(*req.Text, "\n"), "\n")
	case lines == nil:
		s.fail(w, http.StatusBadRequest, `"lines" (an array of log lines) or "text" is required`)
		return nil, false
	}
	if len(lines) > MaxPreviewLines {
		s.fail(w, http.StatusBadRequest, fmt.Sprintf("at most %d lines per preview, got %d", MaxPreviewLines, len(lines)))
		return nil, false
	}
	return lines, true
}
