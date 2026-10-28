// rules-server serves rule sets to clusters: a PiiPolicy with
// spec.remoteConfig pulls GET /v1/<org>/<set>/policy.json with a read-only
// token, and the management API publishes versions. One binary for the
// hosted service and for a self-hosted copy (--single-tenant).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pii-shield/pii-shield/rules/internal/mail"
	"github.com/pii-shield/pii-shield/rules/internal/server"
	"github.com/pii-shield/pii-shield/rules/internal/store"
)

func main() {
	listen := flag.String("listen", envOr("RULES_LISTEN", ":8080"), "address to listen on")
	dbPath := flag.String("db", envOr("RULES_DB", "rules.db"), "path of the SQLite database")
	singleTenant := flag.Bool("single-tenant", os.Getenv("RULES_SINGLE_TENANT") == "true", "serve one organization without a login (self-hosted, behind your own access control)")
	policyRate := flag.Float64("policy-rate", 1, "policy.json pulls allowed per token per second (burst 10)")
	baseURL := flag.String("base-url", os.Getenv("RULES_BASE_URL"), "public address of this server, for the links in mail (default: the request's host)")
	signup := flag.Bool("signup", envOr("RULES_SIGNUP", "open") == "open", "let a new e-mail address create an organization by signing in (RULES_SIGNUP=open|invite)")
	trustProxy := flag.Bool("trust-proxy", os.Getenv("RULES_TRUST_PROXY") == "true", "read the client address and scheme from X-Forwarded-For and X-Forwarded-Proto")
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
	} else if !*singleTenant {
		mailer = mail.Log{Logger: log}
		log.Warn("no RULES_SMTP_ADDR: sign-in links are written to this log instead of being mailed; set RULES_SMTP_ADDR, RULES_SMTP_USER, RULES_SMTP_PASSWORD and RULES_MAIL_FROM for a server other people reach")
	}
	if *singleTenant && adminToken == "" {
		log.Warn("single-tenant without RULES_ADMIN_TOKEN: the panel and the management API are open to anyone who reaches this address")
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Error("open database", "path", *dbPath, "err", err)
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
	})
	if err != nil {
		log.Error("start", "err", err)
		os.Exit(1)
	}
	log.Info("rules-server listening", "addr", *listen, "db", *dbPath, "singleTenant", *singleTenant, "adminToken", adminToken != "",
		"signup", *signup, "smtp", os.Getenv("RULES_SMTP_ADDR") != "", "baseURL", *baseURL)
	if err := server.ListenAndServe(ctx, *listen, srv); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
