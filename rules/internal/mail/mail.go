// Package mail sends the magic-link messages of the panel: over SMTP with
// the usual settings, or into the log when no SMTP is configured, for a
// self-hosted copy whose operator reads the link in the log.
package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	netmail "net/mail"
	"net/smtp"
	"strings"
	"time"
)

// Mailer delivers one plain-text message.
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

// Log writes the message into the log instead of sending it. The link in
// the body is the credential, so this is for a copy whose log is as
// private as its database.
type Log struct{ Logger *slog.Logger }

// Send logs the message.
func (l Log) Send(_ context.Context, to, subject, body string) error {
	l.Logger.Warn("mail not sent: no SMTP configured, the message follows", "to", to, "subject", subject, "body", body)
	return nil
}

// SMTP sends through one SMTP server with PLAIN authentication. Port 465
// opens TLS at once; any other port starts clear and upgrades with
// STARTTLS, which is required when a password is set, so a password never
// crosses the network in clear.
type SMTP struct {
	Addr     string // host:port
	Username string
	Password string
	From     string
	Timeout  time.Duration
}

// Send delivers the message.
func (m SMTP) Send(ctx context.Context, to, subject, body string) error {
	if m.From == "" {
		return errors.New("mail: From address is not set")
	}
	sender, err := envelopeFrom(m.From)
	if err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(m.Addr)
	if err != nil {
		return fmt.Errorf("mail: SMTP address: %w", err)
	}
	timeout := m.Timeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var conn net.Conn
	dialer := &net.Dialer{}
	if port == "465" {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}).DialContext(ctx, "tcp", m.Addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", m.Addr)
	}
	if err != nil {
		return fmt.Errorf("mail: connect %s: %w", m.Addr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("mail: %w", err)
	}
	defer func() { _ = c.Close() }()

	if port != "465" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
				return fmt.Errorf("mail: starttls: %w", err)
			}
		} else if m.Password != "" {
			return errors.New("mail: the server offers no STARTTLS and a password is set; refusing to send it in clear")
		}
	}
	if m.Username != "" || m.Password != "" {
		if err := c.Auth(smtp.PlainAuth("", m.Username, m.Password, host)); err != nil {
			return fmt.Errorf("mail: auth: %w", err)
		}
	}
	if err := c.Mail(sender); err != nil {
		return fmt.Errorf("mail: from: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("mail: to: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("mail: %w", err)
	}
	if _, err := w.Write([]byte(Message(m.From, to, subject, body))); err != nil {
		return fmt.Errorf("mail: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mail: %w", err)
	}
	return c.Quit()
}

// envelopeFrom returns the bare address of a From value such as
// "PII-Shield rules <rules@example.com>": MAIL FROM takes the address alone,
// and a server answers 501 to the whole header value.
func envelopeFrom(from string) (string, error) {
	a, err := netmail.ParseAddress(from)
	if err != nil {
		return "", fmt.Errorf("mail: From address %q: %w", from, err)
	}
	return a.Address, nil
}

// Message formats a plain-text message with CRLF line endings. Header
// values are kept to one line, so a crafted address cannot add headers.
func Message(from, to, subject, body string) string {
	line := func(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", line(from))
	fmt.Fprintf(&b, "To: %s\r\n", line(to))
	fmt.Fprintf(&b, "Subject: %s\r\n", line(subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n"))
	return b.String()
}
