package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/TYFSADIK/daru/internal/auth"
	"github.com/TYFSADIK/daru/internal/query"
	"github.com/TYFSADIK/daru/internal/search"
)

// handleHealth is the unauthenticated liveness check. It deliberately
// returns only "ok" and never reveals backend state: ClickHouse health is
// an internal detail, and a degraded answer helps an attacker plan.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if sess, _ := s.session(r); sess != nil {
		status := "ok"
		code := http.StatusOK
		if err := s.Store.Ping(r.Context()); err != nil {
			status, code = "degraded", http.StatusServiceUnavailable
		}
		writeJSON(w, code, map[string]any{"status": status, "time": time.Now().UTC()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if err := readJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	key := clientIP(r) + "|" + req.Username
	if ok, wait := s.loginLimiter.allowed(key); !ok {
		w.Header().Set("Retry-After", time.Duration(wait).String())
		s.audit(r, "login.rate_limited", req.Username, "wait", wait.String())
		writeError(w, http.StatusTooManyRequests, "too many failed logins, try again later")
		return
	}
	user, token, err := s.Auth.Login(r.Context(), req.Username, req.Password, req.TOTP)
	if err != nil && !errors.Is(err, auth.ErrTOTPRequired) && s.LDAP != nil {
		// Not a local account, or a wrong local password: try the
		// directory. resolveExternal refuses LDAP sign in to an account
		// of another source, so a directory user cannot take over a
		// local account with the same name.
		user, token, err = s.ldapLogin(r, req.Username, req.Password, req.TOTP)
	}
	if err != nil {
		if errors.Is(err, auth.ErrTOTPRequired) {
			s.audit(r, "login.totp_required", req.Username)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "totp code required", "totp_required": true})
			return
		}
		s.loginLimiter.recordFailure(key)
		s.metrics.loginFailures.Add(1)
		s.audit(r, "login.failure", req.Username)
		// Generic on purpose: the caller must not learn whether the
		// username exists or whether the TOTP code was wrong.
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	s.loginLimiter.recordSuccess(key)
	s.audit(r, "login.success", req.Username)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((12 * time.Hour).Seconds()),
	})
	if _, err := s.setCSRFCookie(w); err != nil {
		s.Log.Warn("could not issue csrf token", "err", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	username := ""
	if sess, _ := s.session(r); sess != nil {
		username = sess.Username
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.Auth.Logout(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
	if username != "" {
		s.audit(r, "logout", username)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	totp, err := s.Auth.TOTPEnabled(r.Context(), sess.Username)
	if err != nil {
		totp = false
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":     sess.Username,
		"role":         sess.Role,
		"totp_enabled": totp,
	})
}

// handleTOTPEnrol starts TOTP enrolment for the caller's own account. It
// returns the secret and the otpauth URI once; the secret is stored
// server side and TOTP stays disabled until handleTOTPEnable proves the
// authenticator works.
func (s *Server) handleTOTPEnrol(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate totp secret")
		return
	}
	if err := s.Auth.SetTOTPSecret(r.Context(), sess.Username, secret); err != nil {
		s.Log.Warn("totp enrol failed", "err", err)
		writeError(w, http.StatusInternalServerError, "could not start totp enrolment")
		return
	}
	s.audit(r, "totp.enrol", sess.Username)
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":      secret,
		"otpauth_url": auth.TOTPProvisioningURI(secret, sess.Username, "Daru"),
	})
}

// handleTOTPEnable turns TOTP on after the caller proves the enrolled
// authenticator with a current code.
func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &req, 16*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	sess := sessionFrom(r.Context())
	if err := s.Auth.EnableTOTP(r.Context(), sess.Username, req.Code); err != nil {
		s.audit(r, "totp.enable_failure", sess.Username)
		writeError(w, http.StatusBadRequest, "invalid totp code")
		return
	}
	s.audit(r, "totp.enable", sess.Username)
	writeJSON(w, http.StatusOK, map[string]string{"status": "totp enabled"})
}

// handleTOTPDisable turns TOTP off for the caller's own account after a
// current code proves possession of the authenticator.
func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &req, 16*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	sess := sessionFrom(r.Context())
	if !s.isOwnerOrAdmin(r, sess.Username) {
		writeError(w, http.StatusForbidden, "insufficient role")
		return
	}
	if !s.Auth.VerifyTOTPCode(r.Context(), sess.Username, req.Code) {
		s.audit(r, "totp.disable_failure", sess.Username)
		writeError(w, http.StatusBadRequest, "invalid totp code")
		return
	}
	if err := s.Auth.DisableTOTP(r.Context(), sess.Username); err != nil {
		writeError(w, http.StatusInternalServerError, "could not disable totp")
		return
	}
	s.audit(r, "totp.disable", sess.Username)
	writeJSON(w, http.StatusOK, map[string]string{"status": "totp disabled"})
}

func (s *Server) handleCommands(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"commands": query.Commands()})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query    string   `json:"query"`
		Earliest string   `json:"earliest"`
		Latest   string   `json:"latest"`
		MaxRows  int      `json:"max_rows"`
		Indexes  []string `json:"indexes"`
	}
	if err := readJSON(r, &req, 1024*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Query == "" {
		writeError(w, http.StatusBadRequest, "query is required")
		return
	}

	sess := sessionFrom(r.Context())
	indexes, enforced, err := s.SearchScope(r.Context(), sess.Username, req.Indexes)
	if err != nil {
		s.Log.Warn("could not resolve index access for search", "err", err)
		writeError(w, http.StatusInternalServerError, "could not resolve index access")
		return
	}

	s.metrics.searches.Add(1)
	resp, err := s.Search.Run(r.Context(), search.Request{
		Query:            req.Query,
		Earliest:         req.Earliest,
		Latest:           req.Latest,
		Indexes:          indexes,
		IndexesSpecified: enforced,
		MaxRows:          req.MaxRows,
	})
	if err != nil {
		s.metrics.searchErrors.Add(1)
		// The store error is logged server side only. It can contain
		// ClickHouse internals, which are not for the client.
		s.Log.Warn("search failed", "err", err)
		writeError(w, http.StatusBadRequest, "search failed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleListIndexes(w http.ResponseWriter, r *http.Request) {
	indexes, err := s.Store.ListIndexes(r.Context())
	if err != nil {
		s.Log.Warn("could not list indexes", "err", err)
		writeError(w, http.StatusInternalServerError, "could not list indexes")
		return
	}
	// Only list indexes the caller may search; names, counts, and sizes
	// of other indexes are not theirs to see.
	sc, err := s.scopeFor(r.Context(), sessionFrom(r.Context()).Username)
	if err != nil {
		s.Log.Warn("could not resolve index access", "err", err)
		writeError(w, http.StatusInternalServerError, "could not list indexes")
		return
	}
	visible := indexes[:0]
	for _, ix := range indexes {
		if sc.permits(ix.Name) {
			visible = append(visible, ix)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"indexes": visible})
}
