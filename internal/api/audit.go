package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strings"

	"github.com/TYFSADIK/daru/internal/auth"
)

// clientIP returns the peer address without its port. Only the direct peer
// is trusted: X-Forwarded-For is never used, because Daru does not know
// which proxies, if any, sit in front of it.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

// audit records a security relevant event in the server log with the
// acting user and peer address. The log is the audit trail: login, user
// and token administration, and privileged actions all go through here.
func (s *Server) audit(r *http.Request, event, username string, fields ...any) {
	args := []any{"event", event, "user", username, "ip", clientIP(r)}
	args = append(args, fields...)
	s.Log.Info("audit", args...)
}

// auditHash returns the hex SHA-256 of a blob, so large outputs can be
// recorded in the audit log without storing the output itself.
func auditHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// isOwnerOrAdmin reports whether the session in r belongs to owner or to
// an admin. Saved object ownership is enforced in the store layer; this
// helper covers the API side checks in this package.
func (s *Server) isOwnerOrAdmin(r *http.Request, owner string) bool {
	sess := sessionFrom(r.Context())
	if sess == nil {
		return false
	}
	return sess.Role == auth.RoleAdmin || sess.Username == owner
}
