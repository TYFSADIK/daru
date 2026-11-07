package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"
)

// ScanRecord is a stored scan run.
type ScanRecord struct {
	ID               string `json:"id"`
	Connector        string `json:"connector"`
	Target           string `json:"target"`
	Profile          string `json:"profile"`
	AuthorizationRef string `json:"authorization_ref"`
	Status           string `json:"status"` // running, completed, failed
	Command          string `json:"command"`
	FindingCount     int64  `json:"finding_count"`
	Error            string `json:"error"`
	CreatedBy        string `json:"created_by"`
	StartedAt        string `json:"started_at"`
	FinishedAt       string `json:"finished_at"`
}

// ScanFinding is one stored finding.
type ScanFinding struct {
	ScanID   string            `json:"scan_id"`
	Title    string            `json:"title"`
	Severity string            `json:"severity"`
	Target   string            `json:"target"`
	Port     string            `json:"port"`
	Service  string            `json:"service"`
	Detail   string            `json:"detail"`
	Fields   map[string]string `json:"fields"`
}

// CreateScan inserts a scan in the running state and returns its id.
func (s *Store) CreateScan(ctx context.Context, sc ScanRecord) (string, error) {
	id := newUUID()
	sql := fmt.Sprintf(`INSERT INTO scans
		(id, connector, target, profile, authorization_ref, status, command, created_by, started_at, updated_at)
		VALUES (%s, %s, %s, %s, %s, 'running', %s, %s, now64(3), now64(3))`,
		quote(id), quote(sc.Connector), quote(sc.Target), quote(sc.Profile),
		quote(sc.AuthorizationRef), quote(sc.Command), quote(sc.CreatedBy))
	return id, s.exec(ctx, sql)
}

// CompleteScan records the final status, finding count, and error.
func (s *Store) CompleteScan(ctx context.Context, id, status string, findingCount int, scanErr string) error {
	cur, err := s.Query(ctx, fmt.Sprintf(
		"SELECT connector, target, profile, authorization_ref, command, created_by, toString(started_at) FROM scans FINAL WHERE id = %s LIMIT 1", quote(id)))
	if err != nil {
		return err
	}
	if len(cur.Rows) == 0 {
		return fmt.Errorf("scan not found")
	}
	r := cur.Rows[0]
	return s.exec(ctx, fmt.Sprintf(`INSERT INTO scans
		(id, connector, target, profile, authorization_ref, status, command, finding_count, error, created_by, started_at, finished_at, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %d, %s, %s, %s, now64(3), now64(3))`,
		quote(id), quote(asString(r[0])), quote(asString(r[1])), quote(asString(r[2])), quote(asString(r[3])),
		quote(status), quote(asString(r[4])), findingCount, quote(scanErr), quote(asString(r[5])), quoteTime(asString(r[6]))))
}

// InsertFindings stores findings and also mirrors them into events so they are
// searchable alongside logs (index "recon", sourcetype = connector).
func (s *Store) InsertFindings(ctx context.Context, connector string, findings []ScanFinding) error {
	if len(findings) == 0 {
		return nil
	}
	var fb bytes.Buffer
	fenc := json.NewEncoder(&fb)
	var events []Event
	now := time.Now().UTC()
	for _, f := range findings {
		fields := f.Fields
		if fields == nil {
			fields = map[string]string{}
		}
		row := map[string]any{
			"id": newUUID(), "scan_id": f.ScanID, "created_at": now.Format("2006-01-02 15:04:05.000"),
			"connector": connector, "target": f.Target, "title": f.Title, "severity": f.Severity,
			"port": f.Port, "service": f.Service, "detail": f.Detail, "fields": fields,
		}
		if err := fenc.Encode(row); err != nil {
			return err
		}
		ev := Event{
			Time: now, Index: "recon", Host: f.Target, Source: connector, Sourcetype: connector,
			Raw: fmt.Sprintf("%s severity=%s target=%s %s", f.Title, f.Severity, f.Target, f.Detail),
			Fields: mergeFields(fields, map[string]string{
				"title": f.Title, "severity": f.Severity, "target": f.Target,
				"port": f.Port, "service": f.Service, "scan_id": f.ScanID, "connector": connector,
			}),
		}
		events = append(events, ev)
	}
	stmt := "INSERT INTO scan_findings (id, scan_id, created_at, connector, target, title, severity, port, service, detail, fields) FORMAT JSONEachRow\n"
	if err := s.insert(ctx, stmt+fb.String()); err != nil {
		return err
	}
	_, err := s.InsertEvents(ctx, events)
	return err
}

// ListScans returns recent scans.
func (s *Store) ListScans(ctx context.Context, limit int) ([]ScanRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	res, err := s.Query(ctx, fmt.Sprintf(`SELECT toString(id), connector, target, profile, authorization_ref,
		status, command, finding_count, error, created_by, toString(started_at), toString(finished_at)
		FROM scans FINAL ORDER BY started_at DESC LIMIT %d`, limit))
	if err != nil {
		return nil, err
	}
	var out []ScanRecord
	for _, r := range res.Rows {
		out = append(out, ScanRecord{
			ID: asString(r[0]), Connector: asString(r[1]), Target: asString(r[2]), Profile: asString(r[3]),
			AuthorizationRef: asString(r[4]), Status: asString(r[5]), Command: asString(r[6]),
			FindingCount: asInt(r[7]), Error: asString(r[8]), CreatedBy: asString(r[9]),
			StartedAt: asString(r[10]), FinishedAt: asString(r[11]),
		})
	}
	return out, nil
}

// ScanFindings returns findings for a scan.
func (s *Store) ScanFindings(ctx context.Context, scanID string, limit int) ([]ScanFinding, error) {
	if limit <= 0 || limit > 10000 {
		limit = 2000
	}
	res, err := s.Query(ctx, fmt.Sprintf(`SELECT title, severity, target, port, service, detail
		FROM scan_findings WHERE scan_id = %s ORDER BY
		multiIf(severity='critical',0,severity='high',1,severity='medium',2,severity='low',3,4), title
		LIMIT %d`, quote(scanID), limit))
	if err != nil {
		return nil, err
	}
	var out []ScanFinding
	for _, r := range res.Rows {
		out = append(out, ScanFinding{
			Title: asString(r[0]), Severity: asString(r[1]), Target: asString(r[2]),
			Port: asString(r[3]), Service: asString(r[4]), Detail: asString(r[5]),
		})
	}
	return out, nil
}

func mergeFields(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		if v != "" {
			out[k] = v
		}
	}
	for k, v := range b {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

// newUUID returns a random RFC 4122 v4 UUID string.
func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
