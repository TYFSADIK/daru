package auth

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func validUsername(u string) bool {
	if len(u) < 2 || len(u) > 64 {
		return false
	}
	for _, r := range u {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == '@') {
			return false
		}
	}
	return true
}

// CreateUser adds an account.
func (m *Manager) CreateUser(ctx context.Context, username, password, role, email string) (*User, error) {
	username = strings.TrimSpace(username)
	if !validUsername(username) {
		return nil, fmt.Errorf("username must be 2 to 64 characters of letters, digits, or _-.@")
	}
	if !ValidRole(role) {
		return nil, fmt.Errorf("unknown role %q", role)
	}
	if existing, _ := m.GetUser(ctx, username); existing != nil {
		return nil, fmt.Errorf("user %q already exists", username)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	sql := fmt.Sprintf(
		"INSERT INTO users (username, password_hash, role, email, updated_at) VALUES (%s, %s, %s, %s, now64(3))",
		q(username), q(hash), q(role), q(email),
	)
	if err := m.st.Exec(ctx, sql); err != nil {
		return nil, err
	}
	return &User{Username: username, Role: role, Email: email}, nil
}

// GetUser returns an account by username, or nil if not found.
func (m *Manager) GetUser(ctx context.Context, username string) (*User, error) {
	res, err := m.st.Query(ctx, fmt.Sprintf(
		"SELECT id, username, role, email, disabled FROM users FINAL WHERE username = %s LIMIT 1", q(username)))
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, nil
	}
	return rowToUser(res.Rows[0]), nil
}

// ListUsers returns all accounts.
func (m *Manager) ListUsers(ctx context.Context) ([]User, error) {
	res, err := m.st.Query(ctx, "SELECT id, username, role, email, disabled FROM users FINAL ORDER BY username")
	if err != nil {
		return nil, err
	}
	var out []User
	for _, row := range res.Rows {
		out = append(out, *rowToUser(row))
	}
	return out, nil
}

// SetPassword changes a user's password.
func (m *Manager) SetPassword(ctx context.Context, username, password string) error {
	u, err := m.GetUser(ctx, username)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("user %q not found", username)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return m.st.Exec(ctx, fmt.Sprintf(
		"INSERT INTO users (id, username, password_hash, role, email, disabled, updated_at) VALUES (%s, %s, %s, %s, %s, %d, now64(3))",
		q(u.ID), q(u.Username), q(hash), q(u.Role), q(u.Email), b2i(u.Disabled)))
}

// SetRole changes a user's role.
func (m *Manager) SetRole(ctx context.Context, username, role string) error {
	if !ValidRole(role) {
		return fmt.Errorf("unknown role %q", role)
	}
	u, hash, err := m.getFull(ctx, username)
	if err != nil {
		return err
	}
	return m.st.Exec(ctx, fmt.Sprintf(
		"INSERT INTO users (id, username, password_hash, role, email, disabled, updated_at) VALUES (%s, %s, %s, %s, %s, %d, now64(3))",
		q(u.ID), q(u.Username), q(hash), q(role), q(u.Email), b2i(u.Disabled)))
}

// SetDisabled enables or disables an account.
func (m *Manager) SetDisabled(ctx context.Context, username string, disabled bool) error {
	u, hash, err := m.getFull(ctx, username)
	if err != nil {
		return err
	}
	if err := m.st.Exec(ctx, fmt.Sprintf(
		"INSERT INTO users (id, username, password_hash, role, email, disabled, updated_at) VALUES (%s, %s, %s, %s, %s, %d, now64(3))",
		q(u.ID), q(u.Username), q(hash), q(u.Role), q(u.Email), b2i(disabled))); err != nil {
		return err
	}
	if disabled {
		return m.RevokeAll(ctx, username)
	}
	return nil
}

func (m *Manager) getFull(ctx context.Context, username string) (*User, string, error) {
	res, err := m.st.Query(ctx, fmt.Sprintf(
		"SELECT id, username, role, email, disabled, password_hash FROM users FINAL WHERE username = %s LIMIT 1", q(username)))
	if err != nil {
		return nil, "", err
	}
	if len(res.Rows) == 0 {
		return nil, "", fmt.Errorf("user %q not found", username)
	}
	row := res.Rows[0]
	return rowToUser(row), str(row[5]), nil
}

// Authenticate verifies a username and password and returns the user.
func (m *Manager) Authenticate(ctx context.Context, username, password string) (*User, error) {
	u, hash, err := m.getFull(ctx, username)
	if err != nil {
		// Hash a throwaway password so timing does not reveal missing users.
		HashPassword("not-a-real-password")
		return nil, fmt.Errorf("invalid username or password")
	}
	if u.Disabled || !VerifyPassword(password, hash) {
		return nil, fmt.Errorf("invalid username or password")
	}
	return u, nil
}

// CountUsers returns how many accounts exist.
func (m *Manager) CountUsers(ctx context.Context) (int, error) {
	res, err := m.st.Query(ctx, "SELECT count() FROM (SELECT DISTINCT username FROM users FINAL WHERE disabled = 0)")
	if err != nil {
		return 0, err
	}
	if len(res.Rows) == 0 {
		return 0, nil
	}
	return int(toInt(res.Rows[0][0])), nil
}

func rowToUser(row []any) *User {
	return &User{
		ID:       str(row[0]),
		Username: str(row[1]),
		Role:     str(row[2]),
		Email:    str(row[3]),
		Disabled: toInt(row[4]) != 0,
	}
}

func q(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func toInt(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case string:
		var i int64
		fmt.Sscan(n, &i)
		return i
	}
	return 0
}

var _ = time.Now
