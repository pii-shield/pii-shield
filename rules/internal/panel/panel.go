// Package panel is the rule server's web panel: one HTML page, one script
// and one stylesheet embedded in the binary, no build step and no package
// manager, so the panel ships with the server and nothing else is fetched.
package panel

import (
	"embed"
	"net/http"
	"strings"
)

//go:embed index.html app.js style.css verify.html
var files embed.FS

// Handler serves the panel files. Every response carries a strict
// Content-Security-Policy: scripts and styles from this origin only, no
// framing, forms to this origin only.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, ctype := "index.html", "text/html; charset=utf-8"
		switch {
		case r.URL.Path == "/app.js":
			name, ctype = "app.js", "text/javascript; charset=utf-8"
		case r.URL.Path == "/style.css":
			name, ctype = "style.css", "text/css; charset=utf-8"
		case strings.HasPrefix(r.URL.Path, "/auth/verify"):
			name = "verify.html"
		}
		b, err := files.ReadFile(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		h := w.Header()
		h.Set("Content-Type", ctype)
		h.Set("Cache-Control", "no-cache")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		_, _ = w.Write(b)
	})
}
