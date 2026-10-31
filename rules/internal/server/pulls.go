package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/pii-shield/pii-shield/rules/internal/store"
)

// listPulls answers GET .../pulls?days=30: the set's daily pull counts per
// token, newest day first, up to the 90 days kept.
func (s *Server) listPulls(w http.ResponseWriter, r *http.Request) {
	set, ok := s.set(w, r)
	if !ok {
		return
	}
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > int(store.PullRetention/(24*time.Hour)) {
			s.fail(w, http.StatusBadRequest, "days must be between 1 and 90")
			return
		}
		days = n
	}
	pulls, err := s.store.Pulls(r.Context(), set.ID, days)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.json(w, http.StatusOK, map[string]any{"days": days, "pulls": pulls})
}

// withPullCounts fills each token's pulls of today and of the last seven
// days (UTC) from the daily counts.
func (s *Server) withPullCounts(r *http.Request, setID int64, tokens []store.Token) ([]store.Token, error) {
	pulls, err := s.store.Pulls(r.Context(), setID, 7)
	if err != nil {
		return nil, err
	}
	today := time.Now().UTC().Format("2006-01-02")
	index := map[int64]int{}
	for i := range tokens {
		index[tokens[i].ID] = i
	}
	for _, p := range pulls {
		i, ok := index[p.TokenID]
		if !ok {
			continue
		}
		tokens[i].PullsWeek += p.Pulls
		if p.Day == today {
			tokens[i].PullsToday += p.Pulls
		}
	}
	return tokens, nil
}
