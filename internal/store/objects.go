package store

import (
	"context"
	"fmt"
)

// SavedSearch is a reusable query, optionally scheduled as an alert.
type SavedSearch struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Query     string `json:"query"`
	Earliest  string `json:"earliest"`
	Latest    string `json:"latest"`
	Owner     string `json:"owner"`
	IsAlert   bool   `json:"is_alert"`
	Cron      string `json:"cron"`
	Condition string `json:"condition"`
	Actions   string `json:"actions"`
	Disabled  bool   `json:"disabled"`
}

// SaveSearch inserts or replaces a saved search.
func (s *Store) SaveSearch(ctx context.Context, ss SavedSearch) (string, error) {
	id := ss.ID
	idExpr := "generateUUIDv4()"
	if id != "" {
		idExpr = quote(id)
	}
	sql := fmt.Sprintf(`INSERT INTO saved_searches
		(id, name, query, earliest, latest, owner, is_alert, cron, condition, actions, disabled, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s, %d, %s, %s, %s, %d, now64(3))`,
		idExpr, quote(ss.Name), quote(ss.Query), quote(ss.Earliest), quote(ss.Latest),
		quote(ss.Owner), b(ss.IsAlert), quote(ss.Cron), quote(ss.Condition), quote(ss.Actions), b(ss.Disabled))
	if err := s.exec(ctx, sql); err != nil {
		return "", err
	}
	return id, nil
}

// ListSavedSearches returns saved searches, newest first.
func (s *Store) ListSavedSearches(ctx context.Context) ([]SavedSearch, error) {
	res, err := s.Query(ctx, `SELECT toString(id), name, query, earliest, latest, owner,
		is_alert, cron, condition, actions, disabled
		FROM saved_searches FINAL ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	var out []SavedSearch
	for _, r := range res.Rows {
		out = append(out, SavedSearch{
			ID: asString(r[0]), Name: asString(r[1]), Query: asString(r[2]),
			Earliest: asString(r[3]), Latest: asString(r[4]), Owner: asString(r[5]),
			IsAlert: asInt(r[6]) != 0, Cron: asString(r[7]), Condition: asString(r[8]),
			Actions: asString(r[9]), Disabled: asInt(r[10]) != 0,
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

// Dashboard holds a dashboard definition (panels as JSON).
type Dashboard struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Definition string `json:"definition"`
	Owner      string `json:"owner"`
}

// SaveDashboard inserts or replaces a dashboard.
func (s *Store) SaveDashboard(ctx context.Context, d Dashboard) (string, error) {
	idExpr := "generateUUIDv4()"
	if d.ID != "" {
		idExpr = quote(d.ID)
	}
	sql := fmt.Sprintf(
		"INSERT INTO dashboards (id, name, definition, owner, updated_at) VALUES (%s, %s, %s, %s, now64(3))",
		idExpr, quote(d.Name), quote(d.Definition), quote(d.Owner))
	return d.ID, s.exec(ctx, sql)
}

// ListDashboards returns dashboards.
func (s *Store) ListDashboards(ctx context.Context) ([]Dashboard, error) {
	res, err := s.Query(ctx, "SELECT toString(id), name, owner FROM dashboards FINAL ORDER BY updated_at DESC")
	if err != nil {
		return nil, err
	}
	var out []Dashboard
	for _, r := range res.Rows {
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
	if len(res.Rows) == 0 {
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
}

// RecordAlertFire appends to alert history.
func (s *Store) RecordAlertFire(ctx context.Context, f AlertFire) error {
	if f.Severity == "" {
		f.Severity = "medium"
	}
	return s.exec(ctx, fmt.Sprintf(
		"INSERT INTO alert_history (search_id, search_name, result_count, severity, detail) VALUES (%s, %s, %d, %s, %s)",
		quote(f.SearchID), quote(f.SearchName), f.ResultCount, quote(f.Severity), quote(f.Detail)))
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
		(rule_name, severity, status, mitre, entity, detail, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s, now64(3))`,
		quote(n.RuleName), quote(n.Severity), quote(n.Status), quote(n.Mitre), quote(n.Entity), quote(n.Detail)))
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
		status, owner, mitre, entity, detail FROM notable_events FINAL%s ORDER BY created_at DESC LIMIT %d`, where, limit))
	if err != nil {
		return nil, err
	}
	var out []NotableEvent
	for _, r := range res.Rows {
		out = append(out, NotableEvent{
			ID: asString(r[0]), CreatedAt: asString(r[1]), RuleName: asString(r[2]),
			Severity: asString(r[3]), Status: asString(r[4]), Owner: asString(r[5]),
			Mitre: asString(r[6]), Entity: asString(r[7]), Detail: asString(r[8]),
		})
	}
	return out, nil
}

// SetNotableStatus updates a notable event's triage status and owner.
func (s *Store) SetNotableStatus(ctx context.Context, id, status, owner string) error {
	cur, err := s.Query(ctx, fmt.Sprintf(
		"SELECT rule_name, severity, mitre, entity, detail, toString(created_at) FROM notable_events FINAL WHERE id = %s LIMIT 1", quote(id)))
	if err != nil {
		return err
	}
	if len(cur.Rows) == 0 {
		return fmt.Errorf("notable event not found")
	}
	r := cur.Rows[0]
	return s.exec(ctx, fmt.Sprintf(`INSERT INTO notable_events
		(id, created_at, rule_name, severity, status, owner, mitre, entity, detail, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, now64(3))`,
		quote(id), quoteTime(asString(r[5])), quote(asString(r[0])), quote(asString(r[1])),
		quote(status), quote(owner), quote(asString(r[2])), quote(asString(r[3])), quote(asString(r[4]))))
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
