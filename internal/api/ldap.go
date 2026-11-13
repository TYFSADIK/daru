package api

import (
	"errors"
	"net/http"

	"github.com/TYFSADIK/daru/internal/auth"
)

var errLDAPLogin = errors.New("invalid username or password")

// ldapLogin authenticates against the directory and returns the Daru user
// and a session token. Every failure looks the same to the caller.
func (s *Server) ldapLogin(r *http.Request, username, password, totp string) (*auth.User, string, error) {
	id, err := s.LDAP.Authenticate(username, password)
	if err != nil {
		if !errors.Is(err, auth.ErrLDAPInvalid) {
			s.Log.Warn("ldap authentication error", "user", username, "err", err)
		}
		return nil, "", errLDAPLogin
	}
	u, err := s.resolveExternal(r.Context(), r, auth.SourceLDAP, id.Username, id.Email, id.Role, s.LDAPPolicy)
	if err != nil {
		s.Log.Warn("ldap sign in refused", "user", id.Username, "reason", reasonOf(err))
		s.audit(r, "login.ldap_refused", id.Username, "reason", reasonOf(err))
		return nil, "", errLDAPLogin
	}
	// Daru's own second factor applies to directory accounts that enrolled.
	if on, _, err := s.Auth.TOTPStatus(r.Context(), u.Username); err == nil && on {
		if totp == "" {
			return nil, "", auth.ErrTOTPRequired
		}
		if !s.Auth.VerifyTOTPCode(r.Context(), u.Username, totp) {
			return nil, "", auth.ErrTOTPInvalid
		}
	}
	token, err := s.Auth.NewSession(s.sessionCtx(r, "ldap"), u)
	if err != nil {
		return nil, "", err
	}
	s.audit(r, "login.success", u.Username, "method", "ldap")
	return u, token, nil
}
