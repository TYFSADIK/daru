// Package web serves the embedded single-page UI.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed static
var content embed.FS

// assetVersion is a short hash of the main JS bundle. It is computed once at
// startup and appended as a query string (?v=...) to app.js and style.css in
// index.html, so a new deploy can never serve a stale bundle against a new
// API. The hash changes only when the bundle changes.
var assetVersion string

func init() {
	b, err := content.ReadFile("static/app.js")
	if err != nil {
		return
	}
	sum := sha256.Sum256(b)
	assetVersion = hex.EncodeToString(sum[:])[:12]
}

// Handler serves the UI, falling back to index.html for client-side routes.
// It returns an error handler instead of panicking if the embedded tree
// cannot be opened, returns 404 JSON for unknown /api/* and /services/*
// paths instead of the SPA shell, and sets explicit cache headers.
func Handler() http.Handler {
	sub, err := fs.Sub(content, "static")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "web UI unavailable", http.StatusInternalServerError)
		})
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/services/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if path == "index.html" {
			w.Header().Set("Cache-Control", "no-cache")
			serveIndex(w, r, sub)
			return
		}
		if _, err := fs.Stat(sub, path); err != nil {
			// Unknown path that is not an API call: serve the SPA shell.
			w.Header().Set("Cache-Control", "no-cache")
			serveIndex(w, r, sub)
			return
		}
		if r.URL.Query().Get("v") != "" {
			// Versioned asset: immutable for one year.
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=3600")
		}
		fileServer.ServeHTTP(w, r)
	})
}

// serveIndex serves index.html with the asset version injected into the
// script and stylesheet URLs, so the browser fetches the matching bundle.
func serveIndex(w http.ResponseWriter, r *http.Request, sub fs.FS) {
	b, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		http.Error(w, "web UI unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if assetVersion != "" {
		html := string(b)
		html = strings.ReplaceAll(html, `src="app.js"`, `src="app.js?v=`+assetVersion+`"`)
		html = strings.ReplaceAll(html, `href="style.css"`, `href="style.css?v=`+assetVersion+`"`)
		_, _ = w.Write([]byte(html))
		return
	}
	_, _ = w.Write(b)
}
