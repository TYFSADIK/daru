package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// InsertEvents writes a batch of events using JSONEachRow, chunked into
// batches of at most 10000 events so one request cannot be a single giant
// INSERT. Every index name is validated, so a bad index cannot create
// unbounded partitions.
func (s *Store) InsertEvents(ctx context.Context, events []Event) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	const chunkSize = 10000
	total := 0
	for start := 0; start < len(events); start += chunkSize {
		end := start + chunkSize
		if end > len(events) {
			end = len(events)
		}
		n, err := s.insertEventsChunk(ctx, events[start:end])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func (s *Store) insertEventsChunk(ctx context.Context, events []Event) (int, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range events {
		if e.Time.IsZero() {
			e.Time = time.Now().UTC()
		}
		if e.Index == "" {
			e.Index = "main"
		}
		if !validName(e.Index) {
			return 0, fmt.Errorf("invalid index name %q", e.Index)
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
	if err := s.insert(ctx, stmt+buf.String()); err != nil {
		return 0, err
	}
	return len(events), nil
}

func (s *Store) insert(ctx context.Context, payload string) error {
	_, err := s.do(ctx, payload, s.db)
	return err
}

// MaxRetentionDays is the longest per index retention, matching the events
// table TTL backstop.
const MaxRetentionDays = 3650

// EnsureIndex registers an index and its retention in days. Retention is
// enforced by DropOldPartitions, run by RunRetention from serve, not by
// the table TTL, which is a single 90 day value for every index.
func (s *Store) EnsureIndex(ctx context.Context, name string, retentionDays uint32) error {
	if !validName(name) {
		return fmt.Errorf("invalid index name %q", name)
	}
	if retentionDays == 0 {
		retentionDays = 90
	}
	if retentionDays > MaxRetentionDays {
		return fmt.Errorf("retention_days must be at most %d", MaxRetentionDays)
	}
	sql := fmt.Sprintf(
		"INSERT INTO indexes (name, retention_days, updated_at) VALUES (%s, %d, now64(3))",
		quote(name), retentionDays,
	)
	return s.exec(ctx, sql)
}

// RegisterIndex registers an index with retentionDays only when it is not
// registered yet, so an admin's retention setting is never overwritten.
// Use it for defaults and implicit creation; EnsureIndex is for an admin
// deliberately setting retention.
func (s *Store) RegisterIndex(ctx context.Context, name string, retentionDays uint32) error {
	if !validName(name) {
		return fmt.Errorf("invalid index name %q", name)
	}
	if retentionDays == 0 || retentionDays > MaxRetentionDays {
		retentionDays = 90
	}
	return s.exec(ctx, fmt.Sprintf(
		"INSERT INTO indexes (name, retention_days, updated_at) SELECT %s, %d, now64(3) WHERE %s NOT IN (SELECT name FROM indexes)",
		quote(name), retentionDays, quote(name)))
}

// RegisterEventIndexes registers, with 90 day retention, every index that
// holds events but was never registered. Search and the retention sweep
// only see registered indexes, so such data was invisible and kept until
// the table TTL.
func (s *Store) RegisterEventIndexes(ctx context.Context) error {
	return s.exec(ctx, `INSERT INTO indexes (name, retention_days, updated_at)
		SELECT DISTINCT index, 90, now64(3) FROM events
		WHERE index NOT IN (SELECT name FROM indexes)`)
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
		if len(row) < 6 {
			continue
		}
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

// DropOldPartitions enforces per-index retention by dropping whole
// partitions older than each index retention period. The events table is
// partitioned by (index, toYYYYMMDD(_time)), so dropping a day partition
// for one index leaves every other index untouched. It returns the number
// of partitions dropped. A day that is already gone is not an error.
func (s *Store) DropOldPartitions(ctx context.Context) (int, error) {
	indexes, err := s.ListIndexes(ctx)
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	dropped := 0
	for _, ix := range indexes {
		retention := ix.RetentionDays
		if retention <= 0 {
			retention = 90
		}
		cutoff := now.AddDate(0, 0, -int(retention))
		if ix.Events == 0 {
			// No events in this index, nothing to drop. Checked first:
			// ClickHouse's LEFT JOIN fills a missing row with the type
			// default, so an empty index reports an oldest event of
			// 1970-01-01, which would otherwise issue a year of no-op
			// ALTERs on every sweep and count them as drops.
			continue
		}
		oldest, err := time.Parse("2006-01-02 15:04:05.000", ix.Oldest)
		if err != nil || oldest.Year() < 2000 {
			continue
		}
		day := time.Date(oldest.Year(), oldest.Month(), oldest.Day(), 0, 0, 0, 0, time.UTC)
		last := time.Date(cutoff.Year(), cutoff.Month(), cutoff.Day(), 0, 0, 0, 0, time.UTC)
		// Cap the sweep so a very old index cannot issue unbounded ALTERs.
		for n := 0; day.Before(last) && n < 366; n++ {
			part := fmt.Sprintf("(%s, %s)", quote(ix.Name), day.Format("20060102"))
			if err := s.ddl(ctx, "ALTER TABLE events DROP PARTITION "+part, s.db); err != nil {
				// A missing partition is already gone; other errors stop
				// this index but not the whole sweep.
				if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "PARTITION") {
					day = day.AddDate(0, 0, 1)
					continue
				}
				return dropped, fmt.Errorf("drop partition %s for index %s: %w", part, ix.Name, err)
			}
			dropped++
			day = day.AddDate(0, 0, 1)
		}
	}
	return dropped, nil
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
	if n, ok := v.(json.Number); ok {
		return n.String()
	}
	return fmt.Sprintf("%v", v)
}

func asInt(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i
		}
		if f, err := n.Float64(); err == nil {
			return int64(f)
		}
		return 0
	case string:
		var i int64
		if _, err := fmt.Sscan(n, &i); err != nil {
			return 0
		}
		return i
	}
	return 0
}

// rowString returns cell i as a string, or "" when the row is short.
func rowString(r []any, i int) string {
	if i < 0 || i >= len(r) {
		return ""
	}
	return asString(r[i])
}

// rowInt returns cell i as an int, or 0 when the row is short.
func rowInt(r []any, i int) int64 {
	if i < 0 || i >= len(r) {
		return 0
	}
	return asInt(r[i])
}
