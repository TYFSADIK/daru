package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/TYFSADIK/daru/internal/auth"
	"github.com/TYFSADIK/daru/internal/store"
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
	s.recordAudit(event, username, clientIP(r), fields)
}

// auditOutcome classifies an event name as "ok" or "failure".
func auditOutcome(event string) string {
	for _, w := range []string{"failure", "refused", "rate_limited", "blocked", "denied"} {
		if strings.Contains(event, w) {
			return "failure"
		}
	}
	return "ok"
}

// recordAudit queues an audit event for the stored trail. The server log
// line above is always written; the queue only adds the searchable copy.
func (s *Server) recordAudit(event, actor, ip string, fields []any) {
	if s.Store == nil {
		return
	}
	s.auditOnce.Do(s.startAuditWriter)
	details := map[string]string{}
	for i := 0; i+1 < len(fields); i += 2 {
		details[fmt.Sprint(fields[i])] = fmt.Sprint(fields[i+1])
	}
	ev := store.AuditEvent{Time: time.Now(), Event: event, Actor: actor, IP: ip, Outcome: auditOutcome(event), Details: details}
	select {
	case s.auditCh <- ev:
	default:
		// Never block a request on the audit store. A full queue means
		// ClickHouse is down or slow; the server log still has the event.
		s.metrics.auditDropped.Add(1)
		s.Log.Warn("audit queue full, event kept only in the server log", "event", event)
	}
}

// startAuditWriter starts the goroutine that batch-inserts audit events:
// every second, or as soon as 200 are queued.
func (s *Server) startAuditWriter() {
	s.auditCh = make(chan store.AuditEvent, 5000)
	s.auditDone = make(chan struct{})
	go func() {
		defer close(s.auditDone)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		var batch []store.AuditEvent
		flush := func() {
			if len(batch) == 0 {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := s.Store.InsertAudit(ctx, batch); err != nil {
				s.metrics.auditDropped.Add(uint64(len(batch))) // #nosec G115 -- a slice length is non-negative
				s.Log.Error("could not store audit events; they remain in the server log", "count", len(batch), "err", err)
			}
			batch = batch[:0]
		}
		for {
			select {
			case ev, ok := <-s.auditCh:
				if !ok {
					flush()
					return
				}
				batch = append(batch, ev)
				if len(batch) >= 200 {
					flush()
				}
			case <-tick.C:
				flush()
			}
		}
	}()
}

// FlushAudit stores any queued audit events. Call it once at shutdown,
// after the HTTP server has stopped taking requests.
func (s *Server) FlushAudit(ctx context.Context) {
	if s.auditCh == nil {
		return
	}
	close(s.auditCh)
	select {
	case <-s.auditDone:
	case <-ctx.Done():
	}
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

// handleListAudit returns the stored audit trail, newest first.
// Query: actor, event (exact, or a prefix ending in "."), outcome,
// q (IP or detail text), since and until (RFC 3339), limit.
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AuditFilter{Actor: q.Get("actor"), Event: q.Get("event"), Outcome: q.Get("outcome"), Text: q.Get("q")}
	if f.Outcome != "" && f.Outcome != "ok" && f.Outcome != "failure" {
		writeError(w, http.StatusBadRequest, "outcome must be ok or failure")
		return
	}
	for name, dst := range map[string]*time.Time{"since": &f.Since, "until": &f.Until} {
		if v := q.Get(name); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				writeError(w, http.StatusBadRequest, name+" must be an RFC 3339 time")
				return
			}
			*dst = t
		}
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive number")
			return
		}
		f.Limit = n
	}
	events, err := s.Store.ListAudit(r.Context(), f)
	if err != nil {
		s.Log.Warn("could not list audit events", "err", err)
		writeError(w, http.StatusInternalServerError, "could not read the audit log")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}
