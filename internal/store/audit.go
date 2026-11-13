package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AuditEvent is one record in the security audit trail.
type AuditEvent struct {
	Time    time.Time         `json:"time"`
	Event   string            `json:"event"`
	Actor   string            `json:"actor"`
	IP      string            `json:"ip"`
	Outcome string            `json:"outcome"`
	Details map[string]string `json:"details"`
}

// InsertAudit appends audit events. The table is append-only for the app
// user, so there is no update or delete counterpart.
func (s *Store) InsertAudit(ctx context.Context, events []AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, e := range events {
		details := e.Details
		if details == nil {
			details = map[string]string{}
		}
		outcome := e.Outcome
		if outcome == "" {
			outcome = "ok"
		}
		if err := enc.Encode(map[string]any{
			"time": e.Time.UTC().Format("2006-01-02 15:04:05.000"), "event": e.Event,
			"actor": e.Actor, "ip": e.IP, "outcome": outcome, "details": details,
		}); err != nil {
			return err
		}
	}
	return s.insert(ctx, "INSERT INTO audit_log (time, event, actor, ip, outcome, details) FORMAT JSONEachRow\n"+b.String())
}

// AuditFilter narrows ListAudit. Empty fields match everything.
type AuditFilter struct {
	Actor   string    // exact username
	Event   string    // exact event, or a prefix ending in "." (e.g. "login.")
	Outcome string    // "ok" or "failure"
	Text    string    // substring of the IP or any detail value
	Since   time.Time // inclusive
	Until   time.Time // exclusive
	Limit   int       // default 200, max 5000
}

// ListAudit returns audit events, newest first.
func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]AuditEvent, error) {
	var where []string
	if f.Actor != "" {
		where = append(where, "actor = "+quote(f.Actor))
	}
	if f.Event != "" {
		if strings.HasSuffix(f.Event, ".") {
			where = append(where, "startsWith(event, "+quote(f.Event)+")")
		} else {
			where = append(where, "event = "+quote(f.Event))
		}
	}
	if f.Outcome != "" {
		where = append(where, "outcome = "+quote(f.Outcome))
	}
	if f.Text != "" {
		q := quote(f.Text)
		where = append(where, fmt.Sprintf("(positionCaseInsensitive(ip, %s) > 0 OR arrayExists(v -> positionCaseInsensitive(v, %s) > 0, mapValues(details)))", q, q))
	}
	if !f.Since.IsZero() {
		where = append(where, "time >= "+quote(f.Since.UTC().Format("2006-01-02 15:04:05.000")))
	}
	if !f.Until.IsZero() {
		where = append(where, "time < "+quote(f.Until.UTC().Format("2006-01-02 15:04:05.000")))
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 5000 {
		limit = 5000
	}
	sql := "SELECT toString(time), event, actor, ip, outcome, details FROM audit_log"
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	sql += fmt.Sprintf(" ORDER BY time DESC LIMIT %d", limit)
	res, err := s.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	out := make([]AuditEvent, 0, len(res.Rows))
	for _, row := range res.Rows {
		if len(row) < 6 {
			continue
		}
		t, _ := time.Parse("2006-01-02 15:04:05.000", asString(row[0]))
		details := map[string]string{}
		if m, ok := row[5].(map[string]any); ok {
			for k, v := range m {
				details[k] = asString(v)
			}
		}
		out = append(out, AuditEvent{Time: t, Event: asString(row[1]), Actor: asString(row[2]),
			IP: asString(row[3]), Outcome: asString(row[4]), Details: details})
	}
	return out, nil
}
