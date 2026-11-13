package auth

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Session is an authenticated login.
// SessionMeta describes where a session signed in from. Callers attach it
// to the context with WithSessionMeta; NewSession stores it.
type SessionMeta struct {
	IP        string
	UserAgent string
	Method    string // local, ldap, oidc, saml
}

type sessionMetaKey struct{}

// WithSessionMeta returns ctx carrying m for NewSession.
func WithSessionMeta(ctx context.Context, m SessionMeta) context.Context {
	return context.WithValue(ctx, sessionMetaKey{}, m)
}

// SessionInfo is one active session, as listed to its owner or an admin.
// ID is a prefix of the token hash: enough to name the session, useless
// as a credential.
type SessionInfo struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Method    string    `json:"method"`
	Current   bool      `json:"current"`
}

// SessionID is the public identifier of a session token.
func SessionID(token string) string { return hashToken(token)[:16] }

type Session struct {
	Token     string    `json:"-"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Login authenticates and creates a session, returning the bearer token.
// totpCode is required when the account has TOTP enabled, and ignored
// otherwise, so accounts without a second factor are unaffected. Password
// verification is bounded by a semaphore, so a burst of login attempts
// cannot exhaust memory through concurrent Argon2id verifications.
func (m *Manager) Login(ctx context.Context, username, password, totpCode string) (*User, string, error) {
	select {
	case m.loginSem <- struct{}{}:
		defer func() { <-m.loginSem }()
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}
	u, err := m.Authenticate(ctx, username, password)
	if err != nil {
		return nil, "", err
	}
	if u.TOTPEnabled {
		if totpCode == "" {
			return nil, "", ErrTOTPRequired
		}
		if !m.VerifyTOTPCode(ctx, username, totpCode) {
			return nil, "", ErrTOTPInvalid
		}
	}
	token, err := m.NewSession(ctx, u)
	if err != nil {
		return nil, "", err
	}
	return u, token, nil
}

// NewSession issues a session for an already authenticated user, such as
// one who signed in through OIDC. Callers must have verified the user's
// identity and that the account is not disabled.
func (m *Manager) NewSession(ctx context.Context, u *User) (string, error) {
	if u == nil || u.Disabled {
		return "", fmt.Errorf("account disabled")
	}
	token, hash, err := NewToken("daru_sess")
	if err != nil {
		return "", err
	}
	expires := time.Now().UTC().Add(m.sessionTTL)
	meta, _ := ctx.Value(sessionMetaKey{}).(SessionMeta)
	ua := meta.UserAgent
	if len(ua) > 300 {
		ua = ua[:300]
	}
	sql := fmt.Sprintf(
		"INSERT INTO sessions (token_hash, username, role, expires_at, ip, user_agent, method) VALUES (%s, %s, %s, %s, %s, %s, %s)",
		q(hash), q(u.Username), q(u.Role), chTime(expires), q(meta.IP), q(ua), q(meta.Method))
	if err := m.st.Exec(ctx, sql); err != nil {
		return "", err
	}
	return token, nil
}

// Validate resolves a bearer token to a session, or returns an error.
func (m *Manager) Validate(ctx context.Context, token string) (*Session, error) {
	if token == "" {
		return nil, fmt.Errorf("no token")
	}
	hash := hashToken(token)
	res, err := m.st.Query(ctx, fmt.Sprintf(
		"SELECT username, role, toString(expires_at), revoked FROM sessions FINAL WHERE token_hash = %s LIMIT 1", q(hash)))
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, fmt.Errorf("invalid session")
	}
	row := res.Rows[0]
	if toInt(row[3]) != 0 {
		return nil, fmt.Errorf("session revoked")
	}
	expires, _ := time.Parse("2006-01-02 15:04:05.999", str(row[2]))
	if time.Now().UTC().After(expires) {
		return nil, fmt.Errorf("session expired")
	}
	// A disabled account invalidates existing sessions.
	u, err := m.GetUser(ctx, str(row[0]))
	if err == nil && (u == nil || u.Disabled) {
		return nil, fmt.Errorf("account disabled")
	}
	role := str(row[1])
	if u != nil {
		role = u.Role // pick up a role change without needing re-login
	}
	return &Session{Token: token, Username: str(row[0]), Role: role, ExpiresAt: expires}, nil
}

// Logout revokes one session.
func (m *Manager) Logout(ctx context.Context, token string) error {
	return m.revoke(ctx, "token_hash = "+q(hashToken(token)))
}

// RevokeAll revokes every session for a user.
func (m *Manager) RevokeAll(ctx context.Context, username string) error {
	return m.revoke(ctx, "username = "+q(username))
}

func (m *Manager) revoke(ctx context.Context, where string) error {
	res, err := m.st.Query(ctx, fmt.Sprintf(
		"SELECT token_hash, username, role, toString(expires_at), toString(created_at), ip, user_agent, method FROM sessions FINAL WHERE %s AND revoked = 0", where))
	if err != nil {
		return err
	}
	for _, row := range res.Rows {
		expires, _ := time.Parse("2006-01-02 15:04:05.999", str(row[3]))
		created, _ := time.Parse("2006-01-02 15:04:05.999", str(row[4]))
		if err := m.st.Exec(ctx, fmt.Sprintf(
			"INSERT INTO sessions (token_hash, username, role, expires_at, created_at, ip, user_agent, method, revoked, revoked_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1, now64(3))",
			q(str(row[0])), q(str(row[1])), q(str(row[2])), chTime(expires), chTime(created),
			q(str(row[5])), q(str(row[6])), q(str(row[7])))); err != nil {
			return err
		}
	}
	return nil
}

// ListSessions returns a user's active sessions, newest first. current is
// the caller's own token, marked in the result; it may be empty.
func (m *Manager) ListSessions(ctx context.Context, username, current string) ([]SessionInfo, error) {
	res, err := m.st.Query(ctx, fmt.Sprintf(
		"SELECT token_hash, toString(created_at), toString(expires_at), ip, user_agent, method FROM sessions FINAL WHERE username = %s AND revoked = 0 AND expires_at > now64(3) ORDER BY created_at DESC LIMIT 200",
		q(username)))
	if err != nil {
		return nil, err
	}
	cur := ""
	if current != "" {
		cur = hashToken(current)
	}
	out := make([]SessionInfo, 0, len(res.Rows))
	for _, row := range res.Rows {
		h := str(row[0])
		if len(h) < 16 {
			continue
		}
		created, _ := time.Parse("2006-01-02 15:04:05.999", str(row[1]))
		expires, _ := time.Parse("2006-01-02 15:04:05.999", str(row[2]))
		out = append(out, SessionInfo{ID: h[:16], CreatedAt: created, ExpiresAt: expires,
			IP: str(row[3]), UserAgent: str(row[4]), Method: str(row[5]), Current: h == cur})
	}
	return out, nil
}

// RevokeSession revokes one of username's sessions by its ID.
func (m *Manager) RevokeSession(ctx context.Context, username, id string) error {
	if len(id) != 16 || strings.Trim(id, "0123456789abcdef") != "" {
		return fmt.Errorf("invalid session id")
	}
	return m.revoke(ctx, fmt.Sprintf("username = %s AND startsWith(token_hash, %s)", q(username), q(id)))
}

// RevokeOthers revokes every session of username except the one for keep.
func (m *Manager) RevokeOthers(ctx context.Context, username, keep string) error {
	return m.revoke(ctx, fmt.Sprintf("username = %s AND token_hash != %s", q(username), q(hashToken(keep))))
}

// PurgeExpired deletes expired and revoked sessions.
func (m *Manager) PurgeExpired(ctx context.Context) error {
	return m.st.Exec(ctx, "DELETE FROM sessions WHERE expires_at < now64(3) OR revoked = 1")
}

func chTime(t time.Time) string {
	return fmt.Sprintf("toDateTime64('%s', 3, 'UTC')", t.UTC().Format("2006-01-02 15:04:05.000"))
}
