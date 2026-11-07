package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Event is a single log record ready to insert.
type Event struct {
	Time       time.Time         `json:"-"`
	Index      string            `json:"index"`
	Host       string            `json:"host"`
	Source     string            `json:"source"`
	Sourcetype string            `json:"sourcetype"`
	Raw        string            `json:"_raw"`
	Fields     map[string]string `json:"fields"`
}

// eventRow is the JSONEachRow shape ClickHouse ingests.
type eventRow struct {
	Time       string            `json:"_time"`
	Index      string            `json:"index"`
	Host       string            `json:"host"`
	Source     string            `json:"source"`
	Sourcetype string            `json:"sourcetype"`
	Raw        string            `json:"_raw"`
	Fields     map[string]string `json:"fields"`
}

// InsertEvents writes a batch of events using JSONEachRow.
func (s *Store) InsertEvents(ctx context.Context, events []Event) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range events {
		if e.Time.IsZero() {
			e.Time = time.Now().UTC()
		}
		if e.Index == "" {
			e.Index = "main"
		}
		if e.Fields == nil {
			e.Fields = map[string]string{}
		}
		row := eventRow{
			Time:       e.Time.UTC().Format("2006-01-02 15:04:05.000"),
			Index:      e.Index,
			Host:       e.Host,
			Source:     e.Source,
			Sourcetype: e.Sourcetype,
			Raw:        e.Raw,
			Fields:     e.Fields,
		}
		if err := enc.Encode(row); err != nil {
			return 0, err
		}
	}
	stmt := "INSERT INTO events (_time, index, host, source, sourcetype, _raw, fields) FORMAT JSONEachRow\n"
	q := url.Values{}
	q.Set("database", s.db)
	if err := s.insert(ctx, stmt+buf.String()); err != nil {
		return 0, err
	}
	return len(events), nil
}

func (s *Store) insert(ctx context.Context, payload string) error {
	_, err := s.do(ctx, payload, s.db)
	return err
}

// EnsureIndex registers an index and sets its partition TTL.
func (s *Store) EnsureIndex(ctx context.Context, name string, retentionDays uint32) error {
	if !validName(name) {
		return fmt.Errorf("invalid index name %q", name)
	}
	if retentionDays == 0 {
		retentionDays = 90
	}
	sql := fmt.Sprintf(
		"INSERT INTO indexes (name, retention_days, updated_at) VALUES (%s, %d, now64(3))",
		quote(name), retentionDays,
	)
	return s.exec(ctx, sql)
}

// ListIndexes returns known index names with event counts.
func (s *Store) ListIndexes(ctx context.Context) ([]IndexInfo, error) {
	res, err := s.Query(ctx, `
		SELECT i.name, i.retention_days,
		       ifNull(e.cnt, 0) AS events,
		       ifNull(e.bytes, 0) AS bytes,
		       ifNull(toString(e.oldest), '') AS oldest,
		       ifNull(toString(e.newest), '') AS newest
		FROM (SELECT DISTINCT name, retention_days FROM indexes FINAL) i
		LEFT JOIN (
			SELECT index AS name, count() AS cnt, sum(length(_raw)) AS bytes,
			       min(_time) AS oldest, max(_time) AS newest
			FROM events GROUP BY index
		) e ON i.name = e.name
		ORDER BY i.name`)
	if err != nil {
		return nil, err
	}
	var out []IndexInfo
	for _, row := range res.Rows {
		out = append(out, IndexInfo{
			Name:          asString(row[0]),
			RetentionDays: asInt(row[1]),
			Events:        asInt(row[2]),
			Bytes:         asInt(row[3]),
			Oldest:        asString(row[4]),
			Newest:        asString(row[5]),
		})
	}
	return out, nil
}

// IndexInfo describes an index for the UI.
type IndexInfo struct {
	Name          string `json:"name"`
	RetentionDays int64  `json:"retention_days"`
	Events        int64  `json:"events"`
	Bytes         int64  `json:"bytes"`
	Oldest        string `json:"oldest"`
	Newest        string `json:"newest"`
}

func quote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

func validName(s string) bool {
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

func asString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func asInt(v any) int64 {
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
