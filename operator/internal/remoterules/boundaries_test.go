package remoterules

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A pull makes at most five requests: the first one and four redirects. The
// cap keeps a hostile or misconfigured source from walking the operator
// through an endless chain.
func TestFetchRedirectCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/r/"))
		if n == 0 {
			_, _ = w.Write([]byte(`{"revision":"1"}`))
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/r/%d", n-1), http.StatusFound)
	}))
	defer srv.Close()
	ctx := context.Background()

	res, err := Fetch(ctx, Source{URL: srv.URL + "/r/4", AllowInsecure: true})
	if err != nil || string(res.Body) != `{"revision":"1"}` {
		t.Errorf("four redirects must be followed: %q, %v", res.Body, err)
	}
	if _, err := Fetch(ctx, Source{URL: srv.URL + "/r/5", AllowInsecure: true}); err == nil || !strings.Contains(err.Error(), "too many redirects") {
		t.Errorf("a fifth redirect must be refused, got %v", err)
	}
}

// Every 2xx answer to a report is success, 200 and 299 included, and the
// first code past the range is not.
func TestPostStatusRange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		w.WriteHeader(code)
	}))
	defer srv.Close()
	for code, ok := range map[int]bool{200: true, 204: true, 299: true, 300: false, 400: false} {
		err := Post(context.Background(), Source{URL: fmt.Sprintf("%s/%d", srv.URL, code), AllowInsecure: true}, []byte(`{}`))
		if (err == nil) != ok {
			t.Errorf("HTTP %d: err = %v, want success = %v", code, err, ok)
		}
	}
}

// The pull interval has a floor, so a policy cannot make the operator hammer
// its source: one second is raised to the minimum, the minimum itself stays.
func TestIntervalFloor(t *testing.T) {
	if got := Interval(1); got != MinInterval {
		t.Errorf("Interval(1) = %v, want the floor %v", got, MinInterval)
	}
	if got := Interval(int32(MinInterval / time.Second)); got != MinInterval {
		t.Errorf("Interval at the floor = %v", got)
	}
	if got := Interval(-5); got != DefaultInterval {
		t.Errorf("Interval(-5) = %v, want the default %v", got, DefaultInterval)
	}
}
