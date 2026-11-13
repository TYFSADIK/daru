package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SavedSearch is a reusable query, optionally scheduled as an alert.
type SavedSearch struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Query          string `json:"query"`
	Earliest       string `json:"earliest"`
	Latest         string `json:"latest"`
	Owner          string `json:"owner"`
	IsAlert        bool   `json:"is_alert"`
	Cron           string `json:"cron"`
	Condition      string `json:"condition"`
	Actions        string `json:"actions"`
	Disabled       bool   `json:"disabled"`
	MitreTactic    string `json:"mitre_tactic,omitempty"`
	MitreTechnique string `json:"mitre_technique,omitempty"`
}

// mergeMitreActions stores MITRE tags inside the actions JSON document,
// because saved_searches has no dedicated MITRE columns. Tags set on the
// struct win over tags already in the document.
func mergeMitreActions(actions, tactic, technique string) string {
	if tactic == "" && technique == "" {
		return actions
	}
	doc := map[string]any{}
	if strings.TrimSpace(actions) != "" {
		_ = json.Unmarshal([]byte(actions), &doc)
	}
	if tactic != "" {
		doc["mitre_tactic"] = tactic
	}
	if technique != "" {
		doc["mitre_technique"] = technique
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return actions
	}
	return string(b)
}

func mitreFromActions(actions string) (string, string) {
	if strings.TrimSpace(actions) == "" {
		return "", ""
	}
	var doc struct {
		MitreTactic    string `json:"mitre_tactic"`
		MitreTechnique string `json:"mitre_technique"`
	}
	if err := json.Unmarshal([]byte(actions), &doc); err != nil {
		return "", ""
	}
	return doc.MitreTactic, doc.MitreTechnique
}

// SaveSearch inserts or replaces a saved search. New records get a UUID
// generated here, so the returned id is the id that was stored.
func (s *Store) SaveSearch(ctx context.Context, ss SavedSearch) (string, error) {
	id := ss.ID
	if id == "" {
		id = newUUID()
	}
	actions := mergeMitreActions(ss.Actions, ss.MitreTactic, ss.MitreTechnique)
	sql := fmt.Sprintf(`INSERT INTO saved_searches
		(id, name, query, earliest, latest, owner, is_alert, cron, condition, actions, disabled, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s, %d, %s, %s, %s, %d, now64(3))`,
		quote(id), quote(ss.Name), quote(ss.Query), quote(ss.Earliest), quote(ss.Latest),
		quote(ss.Owner), b(ss.IsAlert), quote(ss.Cron), quote(ss.Condition), quote(actions), b(ss.Disabled))
	if err := s.exec(ctx, sql); err != nil {
		return "", err
	}
	return id, nil
}

// ListSavedSearches returns saved searches, newest first, at most 1000.
func (s *Store) ListSavedSearches(ctx context.Context) ([]SavedSearch, error) {
	res, err := s.Query(ctx, `SELECT toString(id), name, query, earliest, latest, owner,
		is_alert, cron, condition, actions, disabled
		FROM saved_searches FINAL ORDER BY updated_at DESC LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	var out []SavedSearch
	for _, r := range res.Rows {
		if len(r) < 11 {
			continue
		}
		tactic, technique := mitreFromActions(asString(r[9]))
		out = append(out, SavedSearch{
			ID: asString(r[0]), Name: asString(r[1]), Query: asString(r[2]),
			Earliest: asString(r[3]), Latest: asString(r[4]), Owner: asString(r[5]),
			IsAlert: asInt(r[6]) != 0, Cron: asString(r[7]), Condition: asString(r[8]),
			Actions: asString(r[9]), Disabled: asInt(r[10]) != 0,
			MitreTactic: tactic, MitreTechnique: technique,
		})
	}
	return out, nil
}

// EnabledAlerts returns saved searches that are scheduled alerts.
func (s *Store) EnabledAlerts(ctx context.Context) ([]SavedSearch, error) {
	all, err := s.ListSavedSearches(ctx)
	if err != nil {
		return nil, err
	}
	var out []SavedSearch
	for _, ss := range all {
		if ss.IsAlert && !ss.Disabled && ss.Cron != "" {
			out = append(out, ss)
		}
	}
	return out, nil
}

// DeleteSavedSearch removes a saved search by id.
func (s *Store) DeleteSavedSearch(ctx context.Context, id string) error {
	return s.exec(ctx, fmt.Sprintf("DELETE FROM saved_searches WHERE id = %s", quote(id)))
}

// GetSavedSearch returns one saved search by id, or nil when it does not exist.
func (s *Store) GetSavedSearch(ctx context.Context, id string) (*SavedSearch, error) {
	list, err := s.ListSavedSearches(ctx)
	if err != nil {
		return nil, err
	}
	for _, ss := range list {
		if ss.ID == id {
			ss := ss
			return &ss, nil
		}
	}
	return nil, nil
}

// Dashboard holds a dashboard definition (panels as JSON).
type Dashboard struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Definition string `json:"definition"`
	Owner      string `json:"owner"`
}

// SaveDashboard inserts or replaces a dashboard. New records get a UUID
// generated here, so the returned id is the id that was stored.
func (s *Store) SaveDashboard(ctx context.Context, d Dashboard) (string, error) {
	id := d.ID
	if id == "" {
		id = newUUID()
	}
	sql := fmt.Sprintf(
		"INSERT INTO dashboards (id, name, definition, owner, updated_at) VALUES (%s, %s, %s, %s, now64(3))",
		quote(id), quote(d.Name), quote(d.Definition), quote(d.Owner))
	return id, s.exec(ctx, sql)
}

// ListDashboards returns dashboards, at most 1000.
func (s *Store) ListDashboards(ctx context.Context) ([]Dashboard, error) {
	res, err := s.Query(ctx, "SELECT toString(id), name, owner FROM dashboards FINAL ORDER BY updated_at DESC LIMIT 1000")
	if err != nil {
		return nil, err
	}
	var out []Dashboard
	for _, r := range res.Rows {
		if len(r) < 3 {
			continue
		}
		out = append(out, Dashboard{ID: asString(r[0]), Name: asString(r[1]), Owner: asString(r[2])})
	}
	return out, nil
}

// GetDashboard returns one dashboard with its definition.
func (s *Store) GetDashboard(ctx context.Context, id string) (*Dashboard, error) {
	res, err := s.Query(ctx, fmt.Sprintf(
		"SELECT toString(id), name, definition, owner FROM dashboards FINAL WHERE id = %s LIMIT 1", quote(id)))
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 || len(res.Rows[0]) < 4 {
		return nil, nil
	}
	r := res.Rows[0]
	return &Dashboard{ID: asString(r[0]), Name: asString(r[1]), Definition: asString(r[2]), Owner: asString(r[3])}, nil
}

// DeleteDashboard removes a dashboard.
func (s *Store) DeleteDashboard(ctx context.Context, id string) error {
	return s.exec(ctx, fmt.Sprintf("DELETE FROM dashboards WHERE id = %s", quote(id)))
}

// AlertFire records that an alert fired.
type AlertFire struct {
	SearchID    string
	SearchName  string
	ResultCount int64
	Severity    string
	Detail      string
	Delivered   bool // true when every notifier accepted the alert
}

// RecordAlertFire appends to alert history, recording delivery.
func (s *Store) RecordAlertFire(ctx context.Context, f AlertFire) error {
	if f.Severity == "" {
		f.Severity = "medium"
	}
	return s.exec(ctx, fmt.Sprintf(
		"INSERT INTO alert_history (search_id, search_name, result_count, severity, detail, delivered) VALUES (%s, %s, %d, %s, %s, %d)",
		quote(f.SearchID), quote(f.SearchName), f.ResultCount, quote(f.Severity), quote(f.Detail), b(f.Delivered)))
}

// LastAlertFire returns when an alert last fired, or the zero time.
func (s *Store) LastAlertFire(ctx context.Context, searchID string) (time.Time, error) {
	res, err := s.Query(ctx, fmt.Sprintf(
		"SELECT toString(fired_at) FROM alert_history WHERE search_id = %s ORDER BY fired_at DESC LIMIT 1", quote(searchID)))
	if err != nil {
		return time.Time{}, err
	}
	if len(res.Rows) == 0 || len(res.Rows[0]) == 0 {
		return time.Time{}, nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05.000", "2006-01-02 15:04:05", time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, asString(res.Rows[0][0])); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("could not parse fired_at %q", asString(res.Rows[0][0]))
}

// AlertHistoryRow is one past alert firing.
type AlertHistoryRow struct {
	SearchName  string `json:"search_name"`
	FiredAt     string `json:"fired_at"`
	ResultCount int64  `json:"result_count"`
	Severity    string `json:"severity"`
	Detail      string `json:"detail"`
}

// ListAlertHistory returns recent alert firings.
func (s *Store) ListAlertHistory(ctx context.Context, limit int) ([]AlertHistoryRow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	res, err := s.Query(ctx, fmt.Sprintf(
		"SELECT search_name, toString(fired_at), result_count, severity, detail FROM alert_history ORDER BY fired_at DESC LIMIT %d", limit))
	if err != nil {
		return nil, err
	}
	var out []AlertHistoryRow
	for _, r := range res.Rows {
		if len(r) < 5 {
			continue
		}
		out = append(out, AlertHistoryRow{
			SearchName: asString(r[0]), FiredAt: asString(r[1]),
			ResultCount: asInt(r[2]), Severity: asString(r[3]), Detail: asString(r[4]),
		})
	}
	return out, nil
}

// NotableEvent is a security incident queue entry.
type NotableEvent struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	RuleName  string `json:"rule_name"`
	Severity  string `json:"severity"`
	Status    string `json:"status"`
	Owner     string `json:"owner"`
	Mitre     string `json:"mitre"`
	Entity    string `json:"entity"`
	Detail    string `json:"detail"`
	Raw       string `json:"raw,omitempty"`
}

// InsertNotable adds a notable event.
func (s *Store) InsertNotable(ctx context.Context, n NotableEvent) error {
	if n.Severity == "" {
		n.Severity = "medium"
	}
	if n.Status == "" {
		n.Status = "new"
	}
	return s.exec(ctx, fmt.Sprintf(`INSERT INTO notable_events
		(rule_name, severity, status, mitre, entity, detail, raw, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, now64(3))`,
		quote(n.RuleName), quote(n.Severity), quote(n.Status), quote(n.Mitre), quote(n.Entity), quote(n.Detail), quote(n.Raw)))
}

// ListNotable returns notable events, newest first.
func (s *Store) ListNotable(ctx context.Context, status string, limit int) ([]NotableEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	where := ""
	if status != "" {
		where = " WHERE status = " + quote(status)
	}
	res, err := s.Query(ctx, fmt.Sprintf(`SELECT toString(id), toString(created_at), rule_name, severity,
		status, owner, mitre, entity, detail, raw FROM notable_events FINAL%s ORDER BY created_at DESC LIMIT %d`, where, limit))
	if err != nil {
		return nil, err
	}
	var out []NotableEvent
	for _, r := range res.Rows {
		if len(r) < 9 {
			continue
		}
		out = append(out, NotableEvent{
			ID: asString(r[0]), CreatedAt: asString(r[1]), RuleName: asString(r[2]),
			Severity: asString(r[3]), Status: asString(r[4]), Owner: asString(r[5]),
			Mitre: asString(r[6]), Entity: asString(r[7]), Detail: asString(r[8]),
			Raw: rowString(r, 9),
		})
	}
	return out, nil
}

// SetNotableStatus updates a notable event's triage status and owner.
func (s *Store) SetNotableStatus(ctx context.Context, id, status, owner string) error {
	cur, err := s.Query(ctx, fmt.Sprintf(
		"SELECT rule_name, severity, mitre, entity, detail, toString(created_at), raw FROM notable_events FINAL WHERE id = %s LIMIT 1", quote(id)))
	if err != nil {
		return err
	}
	if len(cur.Rows) == 0 || len(cur.Rows[0]) < 7 {
		return fmt.Errorf("notable event not found")
	}
	r := cur.Rows[0]
	// Preserve raw: the old code re-inserted without it and wiped the field.
	return s.exec(ctx, fmt.Sprintf(`INSERT INTO notable_events
		(id, created_at, rule_name, severity, status, owner, mitre, entity, detail, raw, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now64(3))`,
		quote(id), quoteTime(asString(r[5])), quote(asString(r[0])), quote(asString(r[1])),
		quote(status), quote(owner), quote(asString(r[2])), quote(asString(r[3])), quote(asString(r[4])), quote(asString(r[6]))))
}

func b(v bool) int {
	if v {
		return 1
	}
	return 0
}

func quoteTime(s string) string {
	if s == "" {
		return "now64(3)"
	}
	return fmt.Sprintf("toDateTime64(%s, 3, 'UTC')", quote(s))
}
