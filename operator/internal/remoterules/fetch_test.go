package remoterules

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func reasonOf(t *testing.T, err error) string {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error %v is not a *remoterules.Error", err)
	}
	return e.Reason
}

func TestFetchSendsHeadersAndReturnsBodyWithETag(t *testing.T) {
	var gotAuth, gotMatch, gotUA string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMatch = r.Header.Get("If-None-Match")
		gotUA = r.Header.Get("User-Agent")
		w.Header().Set("ETag", `"v2"`)
		_, _ = w.Write([]byte(`{"revision":"2"}`))
	}))
	defer srv.Close()

	res, err := Fetch(context.Background(), Source{
		URL:           srv.URL + "/policy.json",
		Authorization: "Bearer t0k3n",
		CABundle:      caPEM(t, srv),
		ETag:          `"v1"`,
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.NotModified || string(res.Body) != `{"revision":"2"}` || res.ETag != `"v2"` {
		t.Errorf("unexpected result %+v", res)
	}
	if gotAuth != "Bearer t0k3n" || gotMatch != `"v1"` || gotUA != userAgent {
		t.Errorf("headers not sent: auth=%q if-none-match=%q ua=%q", gotAuth, gotMatch, gotUA)
	}
}

func TestFetchNotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	res, err := Fetch(context.Background(), Source{URL: srv.URL, AllowInsecure: true, ETag: `"v1"`})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !res.NotModified || res.ETag != `"v1"` {
		t.Errorf("expected NotModified with the old ETag, got %+v", res)
	}
}

func TestFetchRefusesHTTPUnlessAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	_, err := Fetch(context.Background(), Source{URL: srv.URL})
	if reasonOf(t, err) != ReasonInsecureURL {
		t.Errorf("expected InsecureURL, got %v", err)
	}
	if _, err := Fetch(context.Background(), Source{URL: "ftp://x/policy.json", AllowInsecure: true}); reasonOf(t, err) != ReasonInsecureURL {
		t.Errorf("expected InsecureURL for ftp, got %v", err)
	}
	if _, err := Fetch(context.Background(), Source{URL: srv.URL, AllowInsecure: true}); err != nil {
		t.Errorf("http with allowInsecure must work: %v", err)
	}
}

func TestFetchRefusesUnknownCertificateWithoutBundle(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	_, err := Fetch(context.Background(), Source{URL: srv.URL})
	if reasonOf(t, err) != ReasonFetchFailed {
		t.Errorf("a self-signed server without a CA bundle must fail the handshake, got %v", err)
	}
	if _, err := Fetch(context.Background(), Source{URL: srv.URL, AllowInsecure: true}); err != nil {
		t.Errorf("allowInsecure must skip verification: %v", err)
	}
	_, err = Fetch(context.Background(), Source{URL: srv.URL, CABundle: []byte("not pem")})
	if err == nil || !strings.Contains(err.Error(), "no PEM certificate") {
		t.Errorf("a bundle without a certificate must be reported, got %v", err)
	}
}

func TestFetchReportsStatusTooLargeAndTimeout(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/500", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
	mux.HandleFunc("/404", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", MaxBytes+1)))
	})
	mux.HandleFunc("/exact", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", MaxBytes)))
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, path := range []string{"/500", "/404"} {
		_, err := Fetch(context.Background(), Source{URL: srv.URL + path, AllowInsecure: true})
		if reasonOf(t, err) != ReasonFetchFailed || !strings.Contains(err.Error(), "HTTP") {
			t.Errorf("%s: expected FetchFailed with the status, got %v", path, err)
		}
	}
	if _, err := Fetch(context.Background(), Source{URL: srv.URL + "/big", AllowInsecure: true}); reasonOf(t, err) != ReasonTooLarge {
		t.Errorf("expected TooLarge, got %v", err)
	}
	if res, err := Fetch(context.Background(), Source{URL: srv.URL + "/exact", AllowInsecure: true}); err != nil || len(res.Body) != MaxBytes {
		t.Errorf("a body of exactly MaxBytes must be accepted, got %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := Fetch(ctx, Source{URL: srv.URL + "/slow", AllowInsecure: true})
	if reasonOf(t, err) != ReasonFetchFailed {
		t.Errorf("expected FetchFailed on timeout, got %v", err)
	}
}

func TestFetchKeepsRedirectsOnHTTPS(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer secure.Close()

	_, err := Fetch(context.Background(), Source{URL: secure.URL, CABundle: caPEM(t, secure)})
	if reasonOf(t, err) != ReasonFetchFailed || !strings.Contains(err.Error(), "allowInsecure") {
		t.Errorf("a redirect to http:// must be refused, got %v", err)
	}
}

func TestIntervalAndRetry(t *testing.T) {
	if Interval(0) != DefaultInterval || Interval(10) != MinInterval || Interval(120) != 2*time.Minute {
		t.Error("Interval: default, floor or value wrong")
	}
	if Retry(0) != RetryInterval || Retry(45) != 45*time.Second || Retry(600) != RetryInterval {
		t.Error("Retry: cap wrong")
	}
}

func caPEM(t *testing.T, srv *httptest.Server) []byte {
	t.Helper()
	cert := srv.Certificate()
	if cert == nil {
		t.Fatal("test server has no certificate")
	}
	if _, err := x509.ParseCertificate(cert.Raw); err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
