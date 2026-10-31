package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/pii-shield/pii-shield/rules/internal/store"
)

// reportSchema is the format the operator's stats channel sends
// (operator/internal/stats.Schema).
const reportSchema = "pii-shield-stats-v1"

// Bounds of a report: it is counters, so anything larger is not one.
const (
	maxReportBody = 64 << 10
	maxReportKeys = 64
	maxKeyLen     = 128
)

// reportBody is the JSON the operator sends; see operator/internal/stats.Report.
type reportBody struct {
	Schema        string           `json:"schema"`
	Cluster       string           `json:"cluster"`
	Policy        string           `json:"policy"`
	From          time.Time        `json:"from"`
	To            time.Time        `json:"to"`
	Mode          string           `json:"mode"`
	PodsReporting int              `json:"podsReporting"`
	PodsTotal     int              `json:"podsTotal"`
	Revisions     map[string]int   `json:"revisions"`
	Remote        *reportRemote    `json:"remote"`
	Lines         int64            `json:"lines"`
	Errors        int64            `json:"errors"`
	Redactions    map[string]int64 `json:"redactions"`
	AuditFindings map[string]int64 `json:"auditFindings"`
}

type reportRemote struct {
	Revision    string `json:"revision"`
	Publication int64  `json:"publication"`
	SignedBy    string `json:"signedBy"`
}

func (b *reportBody) check() error {
	switch {
	case b.Schema != reportSchema:
		return fmt.Errorf("schema must be %q", reportSchema)
	case b.Policy == "" || len(b.Policy) > 253 || len(b.Cluster) > maxKeyLen:
		return errors.New("policy is required (at most 253 characters) and cluster at most 128")
	case b.Mode != "redact" && b.Mode != "audit":
		return errors.New(`mode must be "redact" or "audit"`)
	case b.From.IsZero() || b.To.Before(b.From):
		return errors.New("from and to must be a window, from before to")
	case b.Lines < 0 || b.Errors < 0 || b.PodsReporting < 0 || b.PodsTotal < b.PodsReporting:
		return errors.New("counts must not be negative, and podsReporting not above podsTotal")
	case len(b.Revisions) > maxReportKeys || len(b.Redactions) > maxReportKeys || len(b.AuditFindings) > maxReportKeys:
		return fmt.Errorf("at most %d revisions or detector types", maxReportKeys)
	}
	for _, m := range []map[string]int64{b.Redactions, b.AuditFindings} {
		for k, v := range m {
			if len(k) > maxKeyLen || v < 0 {
				return errors.New("a detector type is too long or its count negative")
			}
		}
	}
	for k, v := range b.Revisions {
		if len(k) > maxKeyLen || v < 0 {
			return errors.New("a revision is too long or its count negative")
		}
	}
	if b.Remote != nil && (len(b.Remote.Revision) > maxKeyLen || len(b.Remote.SignedBy) > maxKeyLen) {
		return errors.New("remote revision or signedBy too long")
	}
	return nil
}

// receiveReport takes a stats report from a cluster's operator, under a
// report token of the set. It is not an audit event: a cluster sends one
// every few minutes.
func (s *Server) receiveReport(w http.ResponseWriter, r *http.Request) {
	acc, ok := s.tokenAccess(w, r, store.KindReport)
	if !ok {
		return
	}
	s.touch(r, acc)
	var b reportBody
	if !s.decodeLimit(w, r, &b, maxReportBody) {
		return
	}
	if err := b.check(); err != nil {
		s.fail(w, http.StatusUnprocessableEntity, "report rejected: "+err.Error())
		return
	}
	rep := store.Report{SetID: acc.Set.ID, TokenID: acc.Token.ID, Cluster: b.Cluster, Policy: b.Policy, From: b.From, To: b.To, Mode: b.Mode,
		PodsReporting: b.PodsReporting, PodsTotal: b.PodsTotal, Revisions: b.Revisions, Lines: b.Lines, Errors: b.Errors,
		Redactions: b.Redactions, AuditFindings: b.AuditFindings}
	if b.Remote != nil {
		rep.RemoteRev, rep.RemotePub, rep.RemoteSigner = b.Remote.Revision, b.Remote.Publication, b.Remote.SignedBy
	}
	if rep.Revisions == nil {
		rep.Revisions = map[string]int{}
	}
	if rep.Redactions == nil {
		rep.Redactions = map[string]int64{}
	}
	if err := s.store.AddReport(r.Context(), rep); err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listClusters answers what the set's clusters reported: per cluster the
// latest report and the sums over ?hours= (default 24, at most 2160), with
// the set's published revision and latest publication to compare against.
func (s *Server) listClusters(w http.ResponseWriter, r *http.Request) {
	set, ok := s.set(w, r)
	if !ok {
		return
	}
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > int(store.ReportRetention/time.Hour) {
			s.fail(w, http.StatusBadRequest, "hours must be between 1 and 2160")
			return
		}
		hours = n
	}
	clusters, err := s.store.Clusters(r.Context(), set.ID, time.Now().Add(-time.Duration(hours)*time.Hour))
	if err != nil {
		s.internal(w, err)
		return
	}
	out := map[string]any{"clusters": clusters, "hours": hours, "publishedRevision": set.PublishedRevision}
	if pub, err := s.store.LatestPublication(r.Context(), set.ID); err == nil {
		out["publication"] = pub.Seq
	}
	s.json(w, http.StatusOK, out)
}
