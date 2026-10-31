// Package remoterules pulls a policy file from the HTTPS source named by
// spec.remoteConfig. It is a plain conditional GET: If-None-Match with the
// ETag of the last good copy, an optional Authorization header from a
// Secret, an optional CA bundle, a timeout and a size limit. Nothing about
// the cluster is sent, and the source needs nothing but a web server.
package remoterules

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// MaxBytes bounds the remote file. The controller keeps two copies in
	// the policy's ConfigMap (the file as fetched and the merged rendering),
	// and a ConfigMap holds 1 MiB in all, so the limit is a quarter of that.
	MaxBytes = 256 << 10
	// Timeout bounds one pull, connection and body included.
	Timeout = 10 * time.Second
	// DefaultInterval is used when intervalSeconds is unset.
	DefaultInterval = 5 * time.Minute
	// MinInterval is the CRD minimum, repeated here for the controller.
	MinInterval = 30 * time.Second
	// RetryInterval caps the wait after a failed pull.
	RetryInterval = time.Minute

	userAgent = "pii-shield-operator"
)

// Reasons a pull fails, used as condition reasons.
const (
	ReasonInsecureURL = "InsecureURL"
	ReasonFetchFailed = "FetchFailed"
	ReasonTooLarge    = "TooLarge"
)

// Error says why a pull failed.
type Error struct {
	Reason string
	Err    error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func fail(reason, format string, args ...any) error {
	return &Error{Reason: reason, Err: fmt.Errorf(format, args...)}
}

// Source describes one pull.
type Source struct {
	URL string
	// Authorization is sent as the whole Authorization header when set.
	Authorization string
	// CABundle is a PEM bundle that replaces the system roots when set.
	CABundle []byte
	// AllowInsecure permits http:// and skips certificate verification.
	AllowInsecure bool
	// ETag of the last good copy; sent as If-None-Match when set.
	ETag string
}

// Result is a successful pull: either a new body or NotModified.
type Result struct {
	Body        []byte
	ETag        string
	NotModified bool
}

// Fetch performs one pull. A 200 returns the body and its ETag, a 304
// returns NotModified, anything else is an *Error.
func Fetch(ctx context.Context, src Source) (Result, error) {
	if err := checkURL(src.URL, src.AllowInsecure); err != nil {
		return Result{}, err
	}
	transport, err := newTransport(src)
	if err != nil {
		return Result{}, err
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return checkURL(req.URL.String(), src.AllowInsecure)
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return Result{}, fail(ReasonFetchFailed, "build request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	if src.Authorization != "" {
		req.Header.Set("Authorization", src.Authorization)
	}
	if src.ETag != "" {
		req.Header.Set("If-None-Match", src.ETag)
	}

	resp, err := client.Do(req)
	if err != nil {
		return Result{}, fail(ReasonFetchFailed, "GET %s: %w", src.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		if src.ETag == "" {
			return Result{}, fail(ReasonFetchFailed, "GET %s: 304 Not Modified without an If-None-Match", src.URL)
		}
		return Result{ETag: src.ETag, NotModified: true}, nil
	default:
		return Result{}, fail(ReasonFetchFailed, "GET %s: HTTP %d", src.URL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBytes+1))
	if err != nil {
		return Result{}, fail(ReasonFetchFailed, "GET %s: read body: %w", src.URL, err)
	}
	if len(body) > MaxBytes {
		return Result{}, fail(ReasonTooLarge, "GET %s: body larger than %d bytes", src.URL, MaxBytes)
	}
	return Result{Body: body, ETag: resp.Header.Get("ETag")}, nil
}

func checkURL(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fail(ReasonFetchFailed, "invalid url %q: %w", raw, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if allowInsecure {
			return nil
		}
		return fail(ReasonInsecureURL, "url %q is not https:// and allowInsecure is not set", raw)
	default:
		return fail(ReasonInsecureURL, "url %q: unsupported scheme", raw)
	}
}

func newTransport(src Source) (*http.Transport, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(src.CABundle) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(src.CABundle) {
			return nil, fail(ReasonFetchFailed, "caBundleSecretRef holds no PEM certificate")
		}
		tlsCfg.RootCAs = pool
	}
	if src.AllowInsecure {
		tlsCfg.InsecureSkipVerify = true // #nosec G402 -- opted in by spec.remoteConfig.allowInsecure
	}
	return &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     tlsCfg,
		TLSHandshakeTimeout: Timeout,
		MaxIdleConns:        1,
	}, nil
}

// Interval returns the pull interval for intervalSeconds.
func Interval(seconds int32) time.Duration {
	if seconds <= 0 {
		return DefaultInterval
	}
	d := time.Duration(seconds) * time.Second
	if d < MinInterval {
		return MinInterval
	}
	return d
}

// Retry returns the wait after a failed pull: the interval, capped.
func Retry(seconds int32) time.Duration {
	if d := Interval(seconds); d < RetryInterval {
		return d
	}
	return RetryInterval
}

// Post sends body as JSON to src.URL under the same rules as a pull: https
// only unless AllowInsecure, the Authorization header and CA bundle of the
// source, the timeout, no redirects to http. The stats channel sends its
// reports with it. Any answer but 2xx is an error.
func Post(ctx context.Context, src Source, body []byte) error {
	if err := checkURL(src.URL, src.AllowInsecure); err != nil {
		return err
	}
	transport, err := newTransport(src)
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   Timeout,
		Transport: transport,
		// A redirect would turn the POST into a GET; refuse it instead.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, src.URL, bytes.NewReader(body))
	if err != nil {
		return fail(ReasonFetchFailed, "build request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	if src.Authorization != "" {
		req.Header.Set("Authorization", src.Authorization)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fail(ReasonFetchFailed, "POST %s: %w", src.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fail(ReasonFetchFailed, "POST %s: HTTP %d", src.URL, resp.StatusCode)
	}
	return nil
}
