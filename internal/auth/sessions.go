package auth

import (
	"context"
	"fmt"
	"time"
)

// Session is an authenticated login.
type Session struct {
	Token     string    `json:"-"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Login authenticates and creates a session, returning the bearer token.
func (m *Manager) Login(ctx context.Context, username, password string) (*User, string, error) {
	u, err := m.Authenticate(ctx, username, password)
	if err != nil {
		return nil, "", err
	}
	token, hash := NewToken("rc_sess")
	expires := time.Now().UTC().Add(m.sessionTTL)
	sql := fmt.Sprintf(
		"INSERT INTO sessions (token_hash, username, role, expires_at) VALUES (%s, %s, %s, %s)",
		q(hash), q(u.Username), q(u.Role), chTime(expires))
	if err := m.st.Exec(ctx, sql); err != nil {
		return nil, "", err
	}
	return u, token, nil
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
		"SELECT token_hash, username, role, toString(expires_at) FROM sessions FINAL WHERE %s AND revoked = 0", where))
	if err != nil {
		return err
	}
	for _, row := range res.Rows {
		expires, _ := time.Parse("2006-01-02 15:04:05.999", str(row[3]))
		if err := m.st.Exec(ctx, fmt.Sprintf(
			"INSERT INTO sessions (token_hash, username, role, expires_at, revoked, revoked_at) VALUES (%s, %s, %s, %s, 1, now64(3))",
			q(str(row[0])), q(str(row[1])), q(str(row[2])), chTime(expires))); err != nil {
			return err
		}
	}
	return nil
}

// PurgeExpired deletes expired and revoked sessions.
func (m *Manager) PurgeExpired(ctx context.Context) error {
	return m.st.Exec(ctx, "DELETE FROM sessions WHERE expires_at < now64(3) OR revoked = 1")
}

func chTime(t time.Time) string {
	return fmt.Sprintf("toDateTime64('%s', 3, 'UTC')", t.UTC().Format("2006-01-02 15:04:05.000"))
}
