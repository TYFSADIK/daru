package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"github.com/TYFSADIK/daru/internal/auth"
)

// OIDC sign in. GET /api/oidc/login starts the authorization code flow and
// GET /api/oidc/callback finishes it. The state value is kept server side
// with the nonce and PKCE verifier, and is also bound to the browser by an
// HttpOnly cookie, so a callback URL replayed in another browser (login
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

type oidcPending struct {
	nonce, verifier string
	expires         time.Time
}

type oidcState struct {
	mu      sync.Mutex
	pending map[string]oidcPending
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
	s.oidc.mu.Lock()
	now := time.Now()
	for k, v := range s.oidc.pending {
		if now.After(v.expires) {
			delete(s.oidc.pending, k)
		}
	}
	if len(s.oidc.pending) > 10000 {
		s.oidc.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, "too many sign in attempts in progress")
		return
	}
	s.oidc.pending[state] = oidcPending{nonce: nonce, verifier: verifier, expires: now.Add(10 * time.Minute)}
	s.oidc.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
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
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/api/oidc/", MaxAge: -1,
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
	s.oidc.mu.Lock()
	pend, ok := s.oidc.pending[state]
	delete(s.oidc.pending, state)
	s.oidc.mu.Unlock()
	if !ok || time.Now().After(pend.expires) {
		s.oidcFail(w, r, "", "state unknown or expired")
		return
	}
	claims, err := p.Exchange(r.Context(), q.Get("code"), pend.verifier, pend.nonce)
	if err != nil {
		s.oidcFail(w, r, "", err.Error())
		return
	}
	username, err := p.Username(claims)
	if err != nil {
		s.oidcFail(w, r, claims.Subject, err.Error())
		return
	}
	u, err := s.Auth.GetUser(r.Context(), username)
	if err != nil {
		s.oidcFail(w, r, username, "user lookup failed")
		return
	}
	if u == nil {
		if !s.OIDC.AutoCreate {
			s.oidcFail(w, r, username, "no Daru account for this identity and auto create is off")
			return
		}
		// The account gets a random password nobody knows; it signs in
		// through the provider only, unless an admin sets a password.
		pw, err := randomString(32)
		if err != nil {
			s.oidcFail(w, r, username, "could not create account")
			return
		}
		role := s.OIDC.DefaultRole
		if role == "" {
			role = auth.RoleUser
		}
		if u, err = s.Auth.CreateUserWithAccess(r.Context(), username, pw, role, claims.Email, s.OIDC.DefaultIndexAccess); err != nil {
			s.oidcFail(w, r, username, "could not create account: "+err.Error())
			return
		}
		s.audit(r, "user.create_oidc", username, "role", role, "index_access", s.OIDC.DefaultIndexAccess)
	}
	if u.Disabled {
		s.oidcFail(w, r, username, "account disabled")
		return
	}
	token, err := s.Auth.NewSession(r.Context(), u)
	if err != nil {
		s.oidcFail(w, r, username, "could not create session")
		return
	}
	s.audit(r, "login.success", username, "method", "oidc")
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: s.Secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int((12 * time.Hour).Seconds()),
	})
	if _, err := s.setCSRFCookie(w); err != nil {
		s.Log.Warn("could not issue csrf token", "err", err)
	}
	http.Redirect(w, r, "/#/search", http.StatusFound)
}

// newOIDCState is split out so tests can build a Server without Handler.
func newOIDCState() *oidcState { return &oidcState{pending: map[string]oidcPending{}} }
