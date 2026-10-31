// Package storetest gives tests a fresh database for the store: a SQLite
// file in the test's temporary directory, or, when RULES_TEST_POSTGRES
// holds the URL of a Postgres server (any database on it the user may
// create databases from), a new database on that server dropped when the
// test ends. CI runs the suite both ways.
package storetest

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"path/filepath"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver for Postgres
)

// EnvPostgres names the variable that switches the tests to Postgres.
const EnvPostgres = "RULES_TEST_POSTGRES"

// DSN returns what store.Open takes for a fresh, empty database.
func DSN(t testing.TB) string {
	t.Helper()
	admin := getenv(EnvPostgres)
	if admin == "" {
		return filepath.Join(t.TempDir(), "rules.db")
	}
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("%s: %v", EnvPostgres, err)
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	name := "rules_test_" + hex.EncodeToString(b[:])
	db, err := sql.Open("pgx", admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE DATABASE ` + name); err != nil {
		_ = db.Close()
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		// Runs after the test's own cleanups, which close the store.
		_, _ = db.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`)
		_ = db.Close()
	})
	u.Path = "/" + name
	return u.String()
}
