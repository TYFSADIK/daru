// Package auth provides built-in user accounts, Argon2id password hashing,
// revocable server-side sessions, and ingest tokens. No external identity
// provider is required, so Daru is fully self-hostable.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/TYFSADIK/daru/internal/store"
)

// Roles.
const (
	RoleAdmin = "admin"
	RolePower = "power" // can create saved searches, dashboards, alerts
	RoleUser  = "user"  // can search and view
)

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool {
	return r == RoleAdmin || r == RolePower || r == RoleUser
}

// Manager handles accounts and sessions.
type Manager struct {
	st         *store.Store
	sessionTTL time.Duration
	// loginSem bounds concurrent password verifications. Each Argon2id
	// verification costs 64 MiB, so an unbounded burst of login attempts
	// could exhaust memory even before any password is accepted.
	loginSem chan struct{}
}

// New creates an auth Manager.
func New(st *store.Store) *Manager {
	return &Manager{st: st, sessionTTL: 12 * time.Hour, loginSem: make(chan struct{}, 4)}
}

// ErrTOTPRequired is returned when a password is correct but the account
// has TOTP enabled and no code was supplied.
var ErrTOTPRequired = fmt.Errorf("totp code required")

// ErrTOTPInvalid is returned when a supplied TOTP code does not verify.
var ErrTOTPInvalid = fmt.Errorf("invalid totp code")

// SetSessionTTL overrides the default session lifetime.
func (m *Manager) SetSessionTTL(d time.Duration) {
	if d > 0 {
		m.sessionTTL = d
	}
}

// User is an account without its password hash.
type User struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Role        string `json:"role"`
	Email       string `json:"email"`
	Disabled    bool   `json:"disabled"`
	TOTPEnabled bool   `json:"totp_enabled"`
	// IndexAccess lists the indexes the user may search, comma separated.
	// "*" means every index; an empty string means none. Admins always
	// read every index whatever this says.
	IndexAccess string `json:"index_access"`
	// AuthSource is how the account signs in: "local" (password), or one
	// of "ldap", "oidc", "saml". An external identity can only sign in to
	// an account of its own source, so a directory or IdP user named like
	// a local admin can never take that account over. Accounts of an
	// external source cannot use the local password form.
	AuthSource string `json:"auth_source"`
}

// Account sources.
const (
	SourceLocal = "local"
	SourceLDAP  = "ldap"
	SourceOIDC  = "oidc"
	SourceSAML  = "saml"
)

// ValidSource reports whether s is a known account source.
func ValidSource(s string) bool {
	switch s {
	case SourceLocal, SourceLDAP, SourceOIDC, SourceSAML:
		return true
	}
	return false
}

// Source returns the account source, treating rows written before the
// column existed as local.
func (u *User) Source() string {
	if u.AuthSource == "" {
		return SourceLocal
	}
	return u.AuthSource
}

// AllIndexes is the IndexAccess value granting every index.
const AllIndexes = "*"

// IndexScope returns whether the user may read every index and, if not,
// the set of indexes they may read.
func (u *User) IndexScope() (all bool, allowed map[string]bool) {
	return ParseIndexAccess(u.Role, u.IndexAccess)
}

// ParseIndexAccess interprets a stored IndexAccess value for a role.
func ParseIndexAccess(role, access string) (all bool, allowed map[string]bool) {
	if role == RoleAdmin || strings.TrimSpace(access) == AllIndexes {
		return true, nil
	}
	allowed = map[string]bool{}
	for _, ix := range strings.Split(access, ",") {
		if ix = strings.TrimSpace(ix); ix != "" {
			allowed[ix] = true
		}
	}
	return false, allowed
}

// FormatIndexAccess builds the stored IndexAccess value. all wins over a
// list; names are validated and de-duplicated, and the result is sorted so
// the stored value is stable.
func FormatIndexAccess(all bool, indexes []string) (string, error) {
	if all {
		return AllIndexes, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, ix := range indexes {
		ix = strings.TrimSpace(ix)
		if ix == AllIndexes {
			return AllIndexes, nil
		}
		if !validIndexName(ix) {
			return "", fmt.Errorf("invalid index name %q", ix)
		}
		if !seen[ix] {
			seen[ix] = true
			out = append(out, ix)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ","), nil
}

func validIndexName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// roleRank orders roles so a demotion can be detected.
func roleRank(role string) int {
	switch role {
	case RoleAdmin:
		return 3
	case RolePower:
		return 2
	case RoleUser:
		return 1
	}
	return 0
}

// --- password hashing (Argon2id) ---

type argonParams struct {
	time, memory uint32
	threads      uint8
	keyLen       uint32
}

var defaultArgon = argonParams{time: 2, memory: 64 * 1024, threads: 4, keyLen: 32}

// HashPassword returns an encoded Argon2id hash.
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", fmt.Errorf("password must be at least 8 characters")
	}
	if len(password) > 1024 {
		return "", fmt.Errorf("password is too long")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	p := defaultArgon
	key := argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, p.keyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		p.memory, p.time, p.threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword checks a password against an encoded hash in constant time.
// Argon2 parameters stored in the hash are validated before use, so a
// crafted row in the users table cannot force a huge memory allocation.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var p argonParams
	n, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads)
	if err != nil || n != 3 {
		return false
	}
	if p.time < 1 || p.time > 10 || p.memory < 8*1024 || p.memory > 1024*1024 || p.threads < 1 || p.threads > 16 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// --- tokens ---

// NewToken returns a random URL-safe token and its SHA-256 hash. A failed
// random read is reported instead of silently producing a weak token.
func NewToken(prefix string) (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = prefix + "_" + base64.RawURLEncoding.EncodeToString(b)
	return token, hashToken(token), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// --- TOTP second factor (RFC 4226 HOTP, RFC 6238 TOTP, stdlib only) ---

// GenerateTOTPSecret returns a fresh base32 secret for enrolment. The
// secret is stored server side and shown to the user once, as a QR code
// value or as text to type into an authenticator app.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// TOTPProvisioningURI builds the otpauth URI an authenticator app scans.
func TOTPProvisioningURI(secret, username, issuer string) string {
	return "otpauth://totp/" + issuer + ":" + username +
		"?secret=" + secret + "&issuer=" + issuer + "&algorithm=SHA1&digits=6&period=30"
}

// totpCode computes the 6 digit code for one 30 second counter value.
func totpCode(secret string, counter uint64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1000000), nil
}

// VerifyTOTP checks a 6 digit code against the current time step, allowing
// one step of clock skew either side. Comparison is constant time.
func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	if _, err := strconv.Atoi(code); err != nil {
		return false
	}
	step := uint64(now.Unix() / 30)
	for _, delta := range []int64{-1, 0, 1} {
		want, err := totpCode(secret, uint64(int64(step)+delta))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}
