// rules-server serves rule sets to clusters: a PiiPolicy with
// spec.remoteConfig pulls GET /v1/<org>/<set>/policy.json with a read-only
// token, and the management API publishes versions. One binary for many
// organizations with sign-in, or for one team (--single-tenant).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/pii-shield/pii-shield/rules/internal/mail"
	"github.com/pii-shield/pii-shield/rules/internal/server"
	"github.com/pii-shield/pii-shield/rules/internal/store"
)

func main() {
	listen := flag.String("listen", envOr("RULES_LISTEN", ":8080"), "address to listen on")
	dbPath := flag.String("db", envOr("RULES_DB", "rules.db"), "path of the SQLite database, or a postgres:// URL for several server processes")
	singleTenant := flag.Bool("single-tenant", os.Getenv("RULES_SINGLE_TENANT") == "true", "serve one organization without a login (self-hosted, behind your own access control)")
	policyRate := flag.Float64("policy-rate", 1, "policy.json pulls allowed per token per second (burst 10)")
	baseURL := flag.String("base-url", os.Getenv("RULES_BASE_URL"), "public address of this server, for the links in mail; required with RULES_SMTP_ADDR")
	signup := flag.Bool("signup", envOr("RULES_SIGNUP", "open") == "open", "let a new e-mail address create an organization by signing in (RULES_SIGNUP=open|invite)")
	trustProxy := flag.Bool("trust-proxy", os.Getenv("RULES_TRUST_PROXY") == "true", "read the client address from X-Forwarded-For")
	metricsListen := flag.String("metrics-listen", os.Getenv("RULES_METRICS_LISTEN"), "address for the Prometheus /metrics endpoint, such as 127.0.0.1:9091; empty turns it off")
	accessLog := flag.Bool("access-log", os.Getenv("RULES_ACCESS_LOG") != "false", "log one line per request (RULES_ACCESS_LOG=false turns it off)")
	insecureCookies := flag.Bool("insecure-cookies", os.Getenv("RULES_INSECURE_COOKIES") == "true", "session cookie without the Secure flag, for plain http on localhost")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	adminToken := os.Getenv("RULES_ADMIN_TOKEN")

	var mailer mail.Mailer
	if addr := os.Getenv("RULES_SMTP_ADDR"); addr != "" {
		mailer = mail.SMTP{Addr: addr, Username: os.Getenv("RULES_SMTP_USER"), Password: os.Getenv("RULES_SMTP_PASSWORD"), From: os.Getenv("RULES_MAIL_FROM")}
		if os.Getenv("RULES_MAIL_FROM") == "" {
			fmt.Fprintln(os.Stderr, "rules-server: RULES_SMTP_ADDR is set, so RULES_MAIL_FROM is required")
			os.Exit(2)
		}
		if *baseURL == "" {
			fmt.Fprintln(os.Stderr, "rules-server: RULES_SMTP_ADDR is set, so RULES_BASE_URL (--base-url) is required: the sign-in links in mail are built from it and never from the request's Host header")
			os.Exit(2)
		}
	} else if !*singleTenant {
		mailer = mail.Log{Logger: log}
		log.Warn("no RULES_SMTP_ADDR: sign-in links are written to this log instead of being mailed; set RULES_SMTP_ADDR, RULES_SMTP_USER, RULES_SMTP_PASSWORD, RULES_MAIL_FROM and RULES_BASE_URL for a server other people reach")
		if *baseURL == "" {
			*baseURL = localBaseURL(*listen)
			log.Warn("no RULES_BASE_URL: the sign-in links in the log point to " + *baseURL + "; set RULES_BASE_URL to the address people open")
		}
	}
	if *singleTenant && adminToken == "" {
		log.Warn("single-tenant without RULES_ADMIN_TOKEN: the panel and the management API are open to anyone who reaches this address")
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Error("open database", "db", safeDSN(*dbPath), "err", err)
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv, err := server.New(ctx, st, server.Config{
		AdminToken:   adminToken,
		SingleTenant: *singleTenant,
		PolicyRate:   *policyRate,
		Logger:       log,

		BaseURL:         *baseURL,
		Mailer:          mailer,
		Signup:          *signup,
		TrustProxy:      *trustProxy,
		InsecureCookies: *insecureCookies,
		AccessLog:       *accessLog,
	})
	if err != nil {
		log.Error("start", "err", err)
		os.Exit(1)
	}
	log.Info("rules-server listening", "addr", *listen, "db", safeDSN(*dbPath), "postgres", store.IsPostgres(*dbPath), "singleTenant", *singleTenant, "adminToken", adminToken != "",
		"signup", *signup, "smtp", os.Getenv("RULES_SMTP_ADDR") != "", "baseURL", *baseURL)
	if *metricsListen != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", server.MetricsHandler())
		go func() {
			if err := server.ListenAndServe(ctx, *metricsListen, mux); err != nil {
				log.Error("metrics listener", "addr", *metricsListen, "err", err)
			}
		}()
		log.Info("metrics on " + *metricsListen + "/metrics")
	}
	if err := server.ListenAndServe(ctx, *listen, srv); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

// localBaseURL is the address of a server on this machine listening on
// listen (":8080", "127.0.0.1:9000", "[::1]:8080"), for the links a
// laptop copy writes to its log.
func localBaseURL(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return "http://localhost:8080"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port)
}

// safeDSN is the --db value for the log: a Postgres URL without its
// password.
func safeDSN(dsn string) string {
	if !store.IsPostgres(dsn) {
		return dsn
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return "postgres://(unparsable)"
	}
	return u.Redacted()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
