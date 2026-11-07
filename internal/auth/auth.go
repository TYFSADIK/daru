// Package auth provides built-in user accounts, Argon2id password hashing,
// revocable server-side sessions, and ingest tokens. No external identity
// provider is required, so Basalt is fully self-hostable.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
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
}

// New creates an auth Manager.
func New(st *store.Store) *Manager {
	return &Manager{st: st, sessionTTL: 12 * time.Hour}
}

// SetSessionTTL overrides the default session lifetime.
func (m *Manager) SetSessionTTL(d time.Duration) {
	if d > 0 {
		m.sessionTTL = d
	}
}

// User is an account without its password hash.
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Email    string `json:"email"`
	Disabled bool   `json:"disabled"`
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
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var p argonParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// --- tokens ---

// NewToken returns a random URL-safe token and its SHA-256 hash.
func NewToken(prefix string) (token, hash string) {
	b := make([]byte, 32)
	rand.Read(b)
	token = prefix + "_" + base64.RawURLEncoding.EncodeToString(b)
	return token, hashToken(token)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
