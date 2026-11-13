package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/TYFSADIK/daru/internal/auth"
	"github.com/TYFSADIK/daru/internal/store"
)

// OIDC sign in. GET /api/oidc/login starts the authorization code flow and
// GET /api/oidc/callback finishes it. The state value is kept in ClickHouse
// (shared by every Daru server) with the nonce and PKCE verifier, and is
// also bound to the browser by an HttpOnly cookie, so a callback URL replayed in another browser (login
// CSRF) is refused.

const oidcStateCookie = "daru_oidc_state"

// OIDCSettings configures single sign on. A nil Provider disables it.
type OIDCSettings struct {
	Provider *auth.OIDCProvider
	// AutoCreate creates a Daru account on first sign in. When false, an
	// admin must create the account first, with the same username the
	// provider's claim maps to.
	AutoCreate bool
	// DefaultRole and DefaultIndexAccess apply to auto created accounts.
	// The defaults are the least privileged: role user, no index.
	DefaultRole        string
	DefaultIndexAccess string
}

func (o OIDCSettings) policy() ExternalAccountPolicy {
	return ExternalAccountPolicy{AutoCreate: o.AutoCreate, DefaultRole: o.DefaultRole, DefaultIndexAccess: o.DefaultIndexAccess}
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Server) handleOIDCConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"enabled": s.OIDC.Provider != nil})
}

func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	p := s.OIDC.Provider
	if p == nil {
		writeError(w, http.StatusNotFound, "single sign on is not configured")
		return
	}
	state, err1 := randomString(32)
	nonce, err2 := randomString(32)
	verifier, err3 := randomString(48)
	if err1 != nil || err2 != nil || err3 != nil {
		writeError(w, http.StatusInternalServerError, "could not start sign in")
		return
	}
	// Stored in ClickHouse, so the callback may reach any Daru server.
	if err := s.Store.PutSSOState(r.Context(), store.SSOState{State: state, Kind: "oidc", Nonce: nonce,
		Verifier: verifier, ExpiresAt: time.Now().Add(10 * time.Minute)}); err != nil {
		s.Log.Warn("could not store oidc state", "err", err)
		writeError(w, http.StatusInternalServerError, "could not start sign in")
		return
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure follows DARU_SECURE_COOKIES (plain HTTP on localhost by default)
		Name: oidcStateCookie, Value: state, Path: "/api/oidc/", MaxAge: 600,
		HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, p.AuthCodeURL(state, nonce, verifier), http.StatusFound)
}

// oidcFail ends a failed sign in on the login page with a generic error;
// the detail is logged and audited, never shown.
func (s *Server) oidcFail(w http.ResponseWriter, r *http.Request, user, reason string) {
	s.Log.Warn("oidc sign in failed", "user", user, "reason", reason)
	s.audit(r, "login.oidc_failure", user, "reason", reason)
	s.metrics.loginFailures.Add(1)
	http.Redirect(w, r, "/?sso=failed", http.StatusFound)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	p := s.OIDC.Provider
	if p == nil {
		writeError(w, http.StatusNotFound, "single sign on is not configured")
		return
	}
	// The state cookie is single use whatever happens next.
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/api/oidc/", MaxAge: -1, // #nosec G124 -- Secure follows DARU_SECURE_COOKIES (plain HTTP on localhost by default)
		HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteLaxMode})
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		s.oidcFail(w, r, "", "provider returned error: "+e)
		return
	}
	state := q.Get("state")
	c, err := r.Cookie(oidcStateCookie)
	if state == "" || err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 {
		s.oidcFail(w, r, "", "state missing or not bound to this browser")
		return
	}
	pend, err := s.Store.TakeSSOState(r.Context(), state, "oidc")
	if err != nil {
		s.oidcFail(w, r, "", "state unknown, used, or expired")
		return
	}
	claims, err := p.Exchange(r.Context(), q.Get("code"), pend.Verifier, pend.Nonce)
	if err != nil {
		s.oidcFail(w, r, "", err.Error())
		return
	}
	username, err := p.Username(claims)
	if err != nil {
		s.oidcFail(w, r, claims.Subject, err.Error())
		return
	}
	u, err := s.resolveExternal(r.Context(), r, auth.SourceOIDC, username, claims.Email, "", s.OIDC.policy())
	if err != nil {
		s.oidcFail(w, r, username, reasonOf(err))
		return
	}
	if err := s.startSession(w, r, u, "oidc"); err != nil {
		s.oidcFail(w, r, username, "could not create session")
		return
	}
	s.audit(r, "login.success", username, "method", "oidc")
	http.Redirect(w, r, "/#/search", http.StatusFound)
}
