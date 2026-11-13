package api

import (
	"net/http"

	"github.com/TYFSADIK/daru/internal/auth"
)

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.Auth.ListUsers(r.Context())
	if err != nil {
		s.Log.Warn("could not list users", "err", err)
		writeError(w, http.StatusInternalServerError, "could not list users")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
		Email    string `json:"email"`
		// Indexes restricts the new user to these indexes. Omitted means
		// every index; ["*"] also means every index.
		Indexes *[]string `json:"indexes"`
		// AuthSource is how the account signs in: local (default, needs a
		// password), or ldap, oidc, saml (no password; the identity must
		// come from that provider).
		AuthSource string `json:"auth_source"`
	}
	if err := readJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Role == "" {
		req.Role = auth.RoleUser
	}
	access := auth.AllIndexes
	if req.Indexes != nil {
		var err error
		if access, err = auth.FormatIndexAccess(false, *req.Indexes); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.checkIndexesExist(r.Context(), access); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.AuthSource == "" {
		req.AuthSource = auth.SourceLocal
	}
	if !auth.ValidSource(req.AuthSource) {
		writeError(w, http.StatusBadRequest, "auth_source must be local, ldap, oidc, or saml")
		return
	}
	var u *auth.User
	var err error
	if req.AuthSource == auth.SourceLocal {
		u, err = s.Auth.CreateUserWithAccess(r.Context(), req.Username, req.Password, req.Role, req.Email, access)
	} else {
		if req.Password != "" {
			writeError(w, http.StatusBadRequest, "accounts that sign in with "+req.AuthSource+" have no Daru password")
			return
		}
		u, err = s.Auth.CreateExternalAccount(r.Context(), req.Username, req.Role, req.Email, access, req.AuthSource)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not create user")
		return
	}
	s.audit(r, "user.create", sessionFrom(r.Context()).Username, "target", req.Username, "role", req.Role, "auth_source", req.AuthSource)
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

func (s *Server) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	target := r.PathValue("username")
	if err := s.Auth.SetPassword(r.Context(), target, req.Password); err != nil {
		writeError(w, http.StatusBadRequest, "could not update password")
		return
	}
	s.audit(r, "user.password_change", sessionFrom(r.Context()).Username, "target", target)
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleSetRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Role string `json:"role"`
	}
	if err := readJSON(r, &req, 16*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	target := r.PathValue("username")
	if err := s.Auth.SetRole(r.Context(), target, req.Role); err != nil {
		writeError(w, http.StatusBadRequest, "could not update role")
		return
	}
	s.acl.invalidate(target)
	s.audit(r, "user.role_change", sessionFrom(r.Context()).Username, "target", target, "role", req.Role)
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleSetDisabled(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Disabled bool `json:"disabled"`
	}
	if err := readJSON(r, &req, 16*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	target := r.PathValue("username")
	if err := s.Auth.SetDisabled(r.Context(), target, req.Disabled); err != nil {
		writeError(w, http.StatusBadRequest, "could not update account")
		return
	}
	s.acl.invalidate(target)
	s.audit(r, "user.disabled_change", sessionFrom(r.Context()).Username, "target", target, "disabled", req.Disabled)
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleCreateIndex(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string `json:"name"`
		RetentionDays uint32 `json:"retention_days"`
	}
	if err := readJSON(r, &req, 16*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := s.Store.EnsureIndex(r.Context(), req.Name, req.RetentionDays); err != nil {
		writeError(w, http.StatusBadRequest, "could not create index")
		return
	}
	s.audit(r, "index.create", sessionFrom(r.Context()).Username, "index", req.Name)
	writeJSON(w, http.StatusOK, map[string]string{"status": "created"})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.Auth.ListIngestTokens(r.Context())
	if err != nil {
		s.Log.Warn("could not list tokens", "err", err)
		writeError(w, http.StatusInternalServerError, "could not list tokens")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string `json:"name"`
		DefaultIndex string `json:"default_index"`
	}
	if err := readJSON(r, &req, 16*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	owner := sessionFrom(r.Context()).Username
	token, err := s.Auth.CreateIngestToken(r.Context(), req.Name, req.DefaultIndex, owner)
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not create token")
		return
	}
	// The token value is never written to the audit log. Only its name
	// and default index are recorded.
	s.audit(r, "token.create", owner, "name", req.Name, "index", req.DefaultIndex)
	// The token is shown once, here only.
	writeJSON(w, http.StatusOK, map[string]string{"token": token, "name": req.Name})
}

func (s *Server) handleDisableToken(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.Auth.DisableIngestToken(r.Context(), name); err != nil {
		s.Log.Warn("could not disable token", "err", err)
		writeError(w, http.StatusInternalServerError, "could not disable token")
		return
	}
	s.audit(r, "token.disable", sessionFrom(r.Context()).Username, "name", name)
	writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
}

// handleAdminDisableTOTP lets an admin clear TOTP for an account that lost
// its authenticator. This is an admin action and is audited; it does not
// need the user's code, which is the point of the recovery path.
func (s *Server) handleAdminDisableTOTP(w http.ResponseWriter, r *http.Request) {
	target := r.PathValue("username")
	if err := s.Auth.DisableTOTP(r.Context(), target); err != nil {
		writeError(w, http.StatusBadRequest, "could not disable totp")
		return
	}
	s.audit(r, "totp.disable_admin", sessionFrom(r.Context()).Username, "target", target)
	writeJSON(w, http.StatusOK, map[string]string{"status": "totp disabled"})
}
