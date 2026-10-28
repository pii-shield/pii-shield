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

	"github.com/pii-shield/pii-shield/rules/internal/server"
	"github.com/pii-shield/pii-shield/rules/internal/store"
)

func main() {
	listen := flag.String("listen", envOr("RULES_LISTEN", ":8080"), "address to listen on")
	dbPath := flag.String("db", envOr("RULES_DB", "rules.db"), "path of the SQLite database")
	singleTenant := flag.Bool("single-tenant", os.Getenv("RULES_SINGLE_TENANT") == "true", "serve one organization without a login (self-hosted, behind your own access control)")
	policyRate := flag.Float64("policy-rate", 1, "policy.json pulls allowed per token per second (burst 10)")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	adminToken := os.Getenv("RULES_ADMIN_TOKEN")
	if adminToken == "" && !*singleTenant {
		fmt.Fprintln(os.Stderr, "rules-server: set RULES_ADMIN_TOKEN for the management API, or run with --single-tenant behind your own access control")
		os.Exit(2)
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
	})
	if err != nil {
		log.Error("start", "err", err)
		os.Exit(1)
	}
	log.Info("rules-server listening", "addr", *listen, "db", *dbPath, "singleTenant", *singleTenant, "adminToken", adminToken != "")
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
