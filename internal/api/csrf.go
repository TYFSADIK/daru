package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const csrfCookie = "daru_csrf"
const csrfHeader = "X-Daru-CSRF"

// securityHeaders sets the response headers that protect the web UI. HSTS
// is only sent when cookies are Secure, which means TLS is in use.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if s.Secure {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// newCSRFToken returns a fresh random token for the double submit cookie.
func newCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// setCSRFCookie issues a fresh CSRF token cookie. The cookie is readable
// by same origin JavaScript on purpose: the UI reads it and sends it back
// as a header, which a cross origin page cannot do.
func (s *Server) setCSRFCookie(w http.ResponseWriter) (string, error) {
	tok, err := newCSRFToken()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: false,
		Secure:   s.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((12 * time.Hour).Seconds()),
	})
	return tok, nil
}

// ensureCSRFCookie returns the current CSRF token, issuing one when the
// client does not have a usable token yet.
func (s *Server) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil && len(c.Value) >= 20 {
		return c.Value
	}
	tok, err := s.setCSRFCookie(w)
	if err != nil {
		return ""
	}
	return tok
}

// validateCSRF enforces the double submit check plus an Origin and Referer
// check for state changing requests made with a session cookie. Bearer
// token requests are not ambient credentials, so they are exempt from the
// double submit check but still get the Origin check. GET, HEAD and
// OPTIONS requests have no side effects and are exempt.
func (s *Server) validateCSRF(w http.ResponseWriter, r *http.Request, cookieAuth bool) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		if u, err := url.Parse(origin); err != nil || !sameHost(u.Host, r.Host) {
			writeError(w, http.StatusForbidden, "origin not allowed")
			return false
		}
	} else if referer := r.Header.Get("Referer"); referer != "" {
		if u, err := url.Parse(referer); err != nil || !sameHost(u.Host, r.Host) {
			writeError(w, http.StatusForbidden, "referer not allowed")
			return false
		}
	}
	if !cookieAuth {
		return true
	}
	cookie, err := r.Cookie(csrfCookie)
	if err != nil || cookie.Value == "" {
		writeError(w, http.StatusForbidden, "csrf token missing")
		return false
	}
	header := r.Header.Get(csrfHeader)
	if header == "" || len(header) != len(cookie.Value) ||
		subtle.ConstantTimeCompare([]byte(header), []byte(cookie.Value)) != 1 {
		writeError(w, http.StatusForbidden, "csrf token invalid")
		return false
	}
	return true
}

func sameHost(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
