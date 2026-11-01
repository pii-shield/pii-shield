package mail

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestMessageKeepsHeadersOnOneLine(t *testing.T) {
	m := Message("rules@example.com", "anna@example.com\r\nBcc: eve@example.com", "Sign in\nX: y", "line one\nline two\n")
	head, body, _ := strings.Cut(m, "\r\n\r\n")
	for _, l := range strings.Split(head, "\r\n") {
		if strings.HasPrefix(l, "Bcc") || strings.HasPrefix(l, "X:") {
			t.Errorf("injected header survived: %q", l)
		}
	}
	if !strings.Contains(head, "To: anna@example.com  Bcc: eve@example.com") || !strings.Contains(head, "Subject: Sign in X: y") {
		t.Errorf("headers: %q", head)
	}
	if body != "line one\r\nline two\r\n" || !strings.Contains(head, "Content-Type: text/plain; charset=utf-8") {
		t.Errorf("body %q head %q", body, head)
	}
}

func TestSMTPRefusesWithoutFromOrAddress(t *testing.T) {
	if err := (SMTP{Addr: "localhost:25"}).Send(context.Background(), "a@b", "s", "b"); err == nil || !strings.Contains(err.Error(), "From") {
		t.Errorf("no From: %v", err)
	}
	if err := (SMTP{Addr: "localhost", From: "r@b"}).Send(context.Background(), "a@b", "s", "b"); err == nil || !strings.Contains(err.Error(), "address") {
		t.Errorf("bad addr: %v", err)
	}
}

func TestEnvelopeFromTakesTheBareAddress(t *testing.T) {
	for in, want := range map[string]string{
		"PII-Shield rules <rules@example.com>": "rules@example.com",
		"rules@example.com":                    "rules@example.com",
		"<rules@example.com>":                  "rules@example.com",
	} {
		if got, err := envelopeFrom(in); err != nil || got != want {
			t.Errorf("envelopeFrom(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := envelopeFrom("not an address"); err == nil {
		t.Error("envelopeFrom accepted a value with no address")
	}
}

func TestLogMailerWritesTheBody(t *testing.T) {
	var sb strings.Builder
	l := Log{Logger: slog.New(slog.NewTextHandler(&sb, nil))}
	if err := l.Send(context.Background(), "a@b", "s", "https://x/auth/verify?token=abc"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "token=abc") || !strings.Contains(sb.String(), "to=a@b") {
		t.Errorf("log: %s", sb.String())
	}
	_ = os.Stderr
}
