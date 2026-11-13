package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/TYFSADIK/daru/internal/auth"
)

// ExternalAccountPolicy decides how an identity verified by LDAP, OIDC, or
// SAML maps to a Daru account.
type ExternalAccountPolicy struct {
	// AutoCreate creates an account on first sign in. When false, an admin
	// creates the account first, with the same username and the matching
	// sign in method.
	AutoCreate bool
	// DefaultRole and DefaultIndexAccess apply to auto created accounts.
	// Empty means role user and no index: the least privilege.
	DefaultRole        string
	DefaultIndexAccess string
}

// errExternal is a refusal whose reason is logged, never shown.
type errExternal struct{ reason string }

func (e errExternal) Error() string { return e.reason }

// resolveExternal maps a verified external identity to an account.
// mappedRole, when not empty, comes from directory or IdP groups and is
// applied on every sign in, so a group change takes effect at next login.
func (s *Server) resolveExternal(ctx context.Context, r *http.Request, source, username, email, mappedRole string, pol ExternalAccountPolicy) (*auth.User, error) {
	u, err := s.Auth.GetUser(ctx, username)
	if err != nil {
		return nil, errExternal{"user lookup failed"}
	}
	if u == nil {
		if !pol.AutoCreate {
			return nil, errExternal{"no Daru account for this identity and auto create is off"}
		}
		role := mappedRole
		if role == "" {
			role = pol.DefaultRole
		}
		if role == "" {
			role = auth.RoleUser
		}
		if u, err = s.Auth.CreateExternalAccount(ctx, username, role, email, pol.DefaultIndexAccess, source); err != nil {
			return nil, errExternal{"could not create account: " + err.Error()}
		}
		s.audit(r, "user.create_"+source, username, "role", role, "index_access", pol.DefaultIndexAccess)
		return u, nil
	}
	if u.Source() != source {
		// A directory or IdP identity must never take over an account of
		// another kind, such as a local admin with the same name.
		return nil, errExternal{fmt.Sprintf("account %q signs in with %s, not %s", username, u.Source(), source)}
	}
	if u.Disabled {
		return nil, errExternal{"account disabled"}
	}
	if mappedRole != "" && mappedRole != u.Role {
		if err := s.Auth.SetRole(ctx, username, mappedRole); err != nil {
			return nil, errExternal{"could not sync role from groups"}
		}
		s.acl.invalidate(username)
		s.audit(r, "user.role_sync", username, "source", source, "role", mappedRole)
		u.Role = mappedRole
	}
	return u, nil
}

// startSession issues the session and CSRF cookies after any sign in.
func (s *Server) startSession(w http.ResponseWriter, u *auth.User) error {
	token, err := s.Auth.NewSession(context.Background(), u)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure follows DARU_SECURE_COOKIES (plain HTTP on localhost by default)
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: s.Secure,
		SameSite: http.SameSiteLaxMode, MaxAge: int((12 * time.Hour).Seconds()),
	})
	if _, err := s.setCSRFCookie(w); err != nil {
		s.Log.Warn("could not issue csrf token", "err", err)
	}
	return nil
}

func reasonOf(err error) string {
	var e errExternal
	if errors.As(err, &e) {
		return e.reason
	}
	return err.Error()
}
