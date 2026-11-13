package auth

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ValidUsername reports whether u is an acceptable Daru username.
func ValidUsername(u string) bool { return validUsername(u) }

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

// CreateUser adds an account that may read every index. Use
// CreateUserWithAccess to restrict it at creation.
func (m *Manager) CreateUser(ctx context.Context, username, password, role, email string) (*User, error) {
	return m.CreateUserWithAccess(ctx, username, password, role, email, AllIndexes)
}

// CreateUserWithAccess adds a local (password) account with an IndexAccess
// value built by FormatIndexAccess.
func (m *Manager) CreateUserWithAccess(ctx context.Context, username, password, role, email, indexAccess string) (*User, error) {
	return m.CreateAccount(ctx, username, password, role, email, indexAccess, SourceLocal)
}

// CreateExternalAccount adds an account that signs in through ldap, oidc,
// or saml. It gets a random password nobody knows.
func (m *Manager) CreateExternalAccount(ctx context.Context, username, role, email, indexAccess, source string) (*User, error) {
	if source == SourceLocal {
		return nil, fmt.Errorf("external account needs an external source")
	}
	pw, _, err := NewToken("unusable")
	if err != nil {
		return nil, err
	}
	return m.CreateAccount(ctx, username, pw, role, email, indexAccess, source)
}

// CreateAccount adds an account of any source.
func (m *Manager) CreateAccount(ctx context.Context, username, password, role, email, indexAccess, source string) (*User, error) {
	if !ValidSource(source) {
		return nil, fmt.Errorf("unknown account source %q", source)
	}
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
		"INSERT INTO users (username, password_hash, role, email, index_access, auth_source, updated_at) VALUES (%s, %s, %s, %s, %s, %s, now64(3))",
		q(username), q(hash), q(role), q(email), q(indexAccess), q(source),
	)
	if err := m.st.Exec(ctx, sql); err != nil {
		return nil, err
	}
	return &User{Username: username, Role: role, Email: email, IndexAccess: indexAccess, AuthSource: source}, nil
}

// GetUser returns an account by username, or nil if not found.
func (m *Manager) GetUser(ctx context.Context, username string) (*User, error) {
	res, err := m.st.Query(ctx, fmt.Sprintf(
		"SELECT id, username, role, email, disabled, index_access, auth_source FROM users FINAL WHERE username = %s LIMIT 1", q(username)))
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, nil
	}
	u := rowToUser(res.Rows[0])
	if len(res.Rows[0]) > 5 {
		u.IndexAccess = str(res.Rows[0][5])
	}
	if len(res.Rows[0]) > 6 {
		u.AuthSource = str(res.Rows[0][6])
	}
	return u, nil
}

// ListUsers returns all accounts.
func (m *Manager) ListUsers(ctx context.Context) ([]User, error) {
	res, err := m.st.Query(ctx, "SELECT id, username, role, email, disabled, index_access, auth_source FROM users FINAL ORDER BY username")
	if err != nil {
		return nil, err
	}
	var out []User
	for _, row := range res.Rows {
		u := rowToUser(row)
		if len(row) > 5 {
			u.IndexAccess = str(row[5])
		}
		if len(row) > 6 {
			u.AuthSource = str(row[6])
		}
		out = append(out, *u)
	}
	return out, nil
}

// saveUserRow writes a full user row, preserving TOTP enrolment and index
// access (u.IndexAccess must have come from getFull, or a password change
// would silently widen a restricted user to the column default). Users is
// a ReplacingMergeTree ordered by username, so re-inserting the row is the
// update mechanism.
func (m *Manager) saveUserRow(ctx context.Context, u *User, hash, totpSecret string, totpEnabled bool) error {
	return m.st.Exec(ctx, fmt.Sprintf(
		"INSERT INTO users (id, username, password_hash, role, email, disabled, totp_secret, totp_enabled, index_access, auth_source, updated_at) VALUES (%s, %s, %s, %s, %s, %d, %s, %d, %s, %s, now64(3))",
		q(u.ID), q(u.Username), q(hash), q(u.Role), q(u.Email), b2i(u.Disabled), q(totpSecret), b2i(totpEnabled), q(u.IndexAccess), q(u.Source())))
}

// SetPassword changes a user's password and revokes every existing session,
// so a stolen session does not survive a password change.
func (m *Manager) SetPassword(ctx context.Context, username, password string) error {
	u, hash, totpSecret, totpEnabled, err := m.getFull(ctx, username)
	if err != nil {
		return err
	}
	_ = hash
	newHash, err := HashPassword(password)
	if err != nil {
		return err
	}
	if err := m.saveUserRow(ctx, u, newHash, totpSecret, totpEnabled); err != nil {
		return err
	}
	return m.RevokeAll(ctx, username)
}

// SetRole changes a user's role. A demotion revokes every existing session,
// so a former admin or power user cannot keep acting with the old role.
func (m *Manager) SetRole(ctx context.Context, username, role string) error {
	if !ValidRole(role) {
		return fmt.Errorf("unknown role %q", role)
	}
	u, hash, totpSecret, totpEnabled, err := m.getFull(ctx, username)
	if err != nil {
		return err
	}
	oldRank := roleRank(u.Role)
	u.Role = role
	if err := m.saveUserRow(ctx, u, hash, totpSecret, totpEnabled); err != nil {
		return err
	}
	if roleRank(role) < oldRank {
		return m.RevokeAll(ctx, username)
	}
	return nil
}

// SetIndexAccess sets which indexes a user may search. Searches resolve
// access on each request, so no session needs revoking.
func (m *Manager) SetIndexAccess(ctx context.Context, username, indexAccess string) error {
	u, hash, totpSecret, totpEnabled, err := m.getFull(ctx, username)
	if err != nil {
		return err
	}
	u.IndexAccess = indexAccess
	return m.saveUserRow(ctx, u, hash, totpSecret, totpEnabled)
}

// SetDisabled enables or disables an account.
func (m *Manager) SetDisabled(ctx context.Context, username string, disabled bool) error {
	u, hash, totpSecret, totpEnabled, err := m.getFull(ctx, username)
	if err != nil {
		return err
	}
	u.Disabled = disabled
	if err := m.saveUserRow(ctx, u, hash, totpSecret, totpEnabled); err != nil {
		return err
	}
	if disabled {
		return m.RevokeAll(ctx, username)
	}
	return nil
}

// getFull returns a user plus the password hash and TOTP enrolment, which
// are never exposed in the public User type.
func (m *Manager) getFull(ctx context.Context, username string) (*User, string, string, bool, error) {
	res, err := m.st.Query(ctx, fmt.Sprintf(
		"SELECT id, username, role, email, disabled, password_hash, totp_secret, totp_enabled, index_access, auth_source FROM users FINAL WHERE username = %s LIMIT 1", q(username)))
	if err != nil {
		return nil, "", "", false, err
	}
	if len(res.Rows) == 0 {
		return nil, "", "", false, fmt.Errorf("user %q not found", username)
	}
	row := res.Rows[0]
	u := rowToUser(row)
	u.TOTPEnabled = len(row) > 7 && toInt(row[7]) != 0
	if len(row) > 8 {
		u.IndexAccess = str(row[8])
	}
	if len(row) > 9 {
		u.AuthSource = str(row[9])
	}
	secret := ""
	if len(row) > 6 {
		secret = str(row[6])
	}
	return u, str(row[5]), secret, u.TOTPEnabled, nil
}

// TOTPStatus reports whether TOTP is enabled for a user, plus the stored
// secret for verification. The secret is only used server side, never
// returned to a client except at enrolment time.
func (m *Manager) TOTPStatus(ctx context.Context, username string) (enabled bool, secret string, err error) {
	_, _, secret, enabled, err = m.getFull(ctx, username)
	return enabled, secret, err
}

// TOTPEnabled reports whether TOTP is enabled for a user.
func (m *Manager) TOTPEnabled(ctx context.Context, username string) (bool, error) {
	enabled, _, err := m.TOTPStatus(ctx, username)
	return enabled, err
}

// SetTOTPSecret stores a fresh enrolment secret and leaves TOTP disabled
// until the user proves they hold the authenticator.
func (m *Manager) SetTOTPSecret(ctx context.Context, username, secret string) error {
	if _, err := totpCode(secret, 0); err != nil {
		return fmt.Errorf("invalid totp secret")
	}
	u, hash, _, _, err := m.getFull(ctx, username)
	if err != nil {
		return err
	}
	return m.saveUserRow(ctx, u, hash, secret, false)
}

// EnableTOTP turns TOTP on after the supplied code verifies against the
// stored enrolment secret.
func (m *Manager) EnableTOTP(ctx context.Context, username, code string) error {
	u, hash, secret, _, err := m.getFull(ctx, username)
	if err != nil {
		return err
	}
	if secret == "" {
		return fmt.Errorf("no totp enrolment in progress")
	}
	if !VerifyTOTP(secret, code, time.Now()) {
		return ErrTOTPInvalid
	}
	return m.saveUserRow(ctx, u, hash, secret, true)
}

// VerifyTOTPCode checks a code for a user who already has TOTP enabled.
func (m *Manager) VerifyTOTPCode(ctx context.Context, username, code string) bool {
	enabled, secret, err := m.TOTPStatus(ctx, username)
	if err != nil || !enabled || secret == "" {
		return false
	}
	return VerifyTOTP(secret, code, time.Now())
}

// DisableTOTP turns TOTP off and clears the stored secret.
func (m *Manager) DisableTOTP(ctx context.Context, username string) error {
	u, hash, _, _, err := m.getFull(ctx, username)
	if err != nil {
		return err
	}
	return m.saveUserRow(ctx, u, hash, "", false)
}

// Authenticate verifies a username and password and returns the user.
func (m *Manager) Authenticate(ctx context.Context, username, password string) (*User, error) {
	u, hash, _, _, err := m.getFull(ctx, username)
	if err != nil {
		// Hash a throwaway password so timing does not reveal missing users.
		HashPassword("not-a-real-password")
		return nil, fmt.Errorf("invalid username or password")
	}
	if u.Disabled || !VerifyPassword(password, hash) || u.Source() != SourceLocal {
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
