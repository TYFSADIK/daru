package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	if len(cur.Rows) == 0 || len(cur.Rows[0]) < 7 {
		return fmt.Errorf("scan not found")
	}
	r := cur.Rows[0]
	return s.exec(ctx, fmt.Sprintf(`INSERT INTO scans
		(id, connector, target, profile, authorization_ref, status, command, finding_count, error, created_by, started_at, finished_at, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %d, %s, %s, %s, now64(3), now64(3))`,
		quote(id), quote(asString(r[0])), quote(asString(r[1])), quote(asString(r[2])), quote(asString(r[3])),
		quote(status), quote(asString(r[4])), findingCount, quote(scanErr), quote(asString(r[5])), quoteTime(asString(r[6]))))
}

// deterministicFindingID derives a stable UUID from the finding identity,
// so retrying an insert does not create duplicates. The UUID is built from
// the first 16 bytes of a SHA-256 hash with the version and variant bits
// set, as in RFC 4122 section 4.3. Note the scan_findings table is a plain
// MergeTree in the current schema, so this method also skips findings whose
// id is already stored; with a ReplacingMergeTree engine the same id would
// replace instead.
// InsertFindings stores findings and also mirrors them into events so they are
// searchable alongside logs (index "recon", sourcetype = connector).
func deterministicFindingID(f ScanFinding) string {
	h := sha256.Sum256([]byte(f.ScanID + "\x00" + f.Title + "\x00" + f.Target + "\x00" + f.Port + "\x00" + f.Service))
	var b [16]byte
	copy(b[:], h[:16])
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (s *Store) InsertFindings(ctx context.Context, connector string, findings []ScanFinding) error {
	if len(findings) == 0 {
		return nil
	}
	// Skip findings already stored for this scan, so a retry after a
	// failed events insert does not duplicate the findings table.
	seen, err := s.existingFindingIDs(ctx, findings[0].ScanID)
	if err != nil {
		return err
	}
	var keep []ScanFinding
	for _, f := range findings {
		if !seen[deterministicFindingID(f)] {
			keep = append(keep, f)
		}
	}
	findings = keep
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
			"id": deterministicFindingID(f), "scan_id": f.ScanID, "created_at": now.Format("2006-01-02 15:04:05.000"),
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
	_, err = s.InsertEvents(ctx, events)
	return err
}

func (s *Store) existingFindingIDs(ctx context.Context, scanID string) (map[string]bool, error) {
	res, err := s.Query(ctx, fmt.Sprintf("SELECT toString(id) FROM scan_findings WHERE scan_id = %s", quote(scanID)))
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, r := range res.Rows {
		if len(r) > 0 {
			seen[asString(r[0])] = true
		}
	}
	return seen, nil
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
		if len(r) < 12 {
			continue
		}
		out = append(out, ScanRecord{
			ID: asString(r[0]), Connector: asString(r[1]), Target: asString(r[2]), Profile: asString(r[3]),
			AuthorizationRef: asString(r[4]), Status: asString(r[5]), Command: asString(r[6]),
			FindingCount: asInt(r[7]), Error: asString(r[8]), CreatedBy: asString(r[9]),
			StartedAt: asString(r[10]), FinishedAt: asString(r[11]),
		})
	}
	return out, nil
}

// ScheduledScan is a recurring recon scan.
type ScheduledScan struct {
	ID               string `json:"id"`
	Connector        string `json:"connector"`
	Target           string `json:"target"`
	Profile          string `json:"profile"`
	Ports            string `json:"ports"`
	Cron             string `json:"cron"`
	Enabled          bool   `json:"enabled"`
	CreatedBy        string `json:"created_by"`
	AuthorizationRef string `json:"authorization_ref,omitempty"`
	AllowExternal    bool   `json:"allow_external,omitempty"`
	LastRun          string `json:"last_run"`
	CreatedAt        string `json:"created_at"`
}

// CreateScheduledScan inserts a recurring scan and returns its id.
func (s *Store) CreateScheduledScan(ctx context.Context, sc ScheduledScan) (string, error) {
	id := newUUID()
	enabled := 1
	if !sc.Enabled {
		enabled = 0
	}
	allowExt := 0
	if sc.AllowExternal {
		allowExt = 1
	}
	sql := fmt.Sprintf(`INSERT INTO scheduled_scans
		(id, connector, target, profile, ports, cron, enabled, created_by, authorization_ref, allow_external, created_at, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s, %d, %s, %s, %d, now64(3), now64(3))`,
		quote(id), quote(sc.Connector), quote(sc.Target), quote(sc.Profile), quote(sc.Ports),
		quote(sc.Cron), enabled, quote(sc.CreatedBy), quote(sc.AuthorizationRef), allowExt)
	return id, s.exec(ctx, sql)
}

// ListScheduledScans returns all scheduled scans, at most 1000.
func (s *Store) ListScheduledScans(ctx context.Context) ([]ScheduledScan, error) {
	res, err := s.Query(ctx, `SELECT toString(id), connector, target, profile, ports, cron, enabled,
		created_by, authorization_ref, allow_external, toString(last_run), toString(created_at) FROM scheduled_scans FINAL ORDER BY created_at DESC LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	var out []ScheduledScan
	for _, r := range res.Rows {
		if len(r) < 12 {
			continue
		}
		out = append(out, ScheduledScan{
			ID: asString(r[0]), Connector: asString(r[1]), Target: asString(r[2]), Profile: asString(r[3]),
			Ports: asString(r[4]), Cron: asString(r[5]), Enabled: asInt(r[6]) != 0,
			CreatedBy: asString(r[7]), AuthorizationRef: asString(r[8]), AllowExternal: asInt(r[9]) != 0,
			LastRun: asString(r[10]), CreatedAt: asString(r[11]),
		})
	}
	return out, nil
}

// EnabledScheduledScans returns only the enabled recurring scans.
func (s *Store) EnabledScheduledScans(ctx context.Context) ([]ScheduledScan, error) {
	all, err := s.ListScheduledScans(ctx)
	if err != nil {
		return nil, err
	}
	var out []ScheduledScan
	for _, sc := range all {
		if sc.Enabled {
			out = append(out, sc)
		}
	}
	return out, nil
}

// DeleteScheduledScan removes a recurring scan.
func (s *Store) DeleteScheduledScan(ctx context.Context, id string) error {
	return s.exec(ctx, fmt.Sprintf("ALTER TABLE scheduled_scans DELETE WHERE id = %s", quote(id)))
}

// MarkScheduledScanRun records the last run time of a scheduled scan.
func (s *Store) MarkScheduledScanRun(ctx context.Context, id string) error {
	cur, err := s.Query(ctx, fmt.Sprintf(
		"SELECT connector, target, profile, ports, cron, enabled, created_by, toString(created_at) FROM scheduled_scans FINAL WHERE id = %s LIMIT 1", quote(id)))
	if err != nil {
		return err
	}
	if len(cur.Rows) == 0 || len(cur.Rows[0]) < 8 {
		return fmt.Errorf("scheduled scan not found: %s", id)
	}
	r := cur.Rows[0]
	return s.exec(ctx, fmt.Sprintf(`INSERT INTO scheduled_scans
		(id, connector, target, profile, ports, cron, enabled, created_by, last_run, created_at, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s, %d, %s, now64(3), %s, now64(3))`,
		quote(id), quote(asString(r[0])), quote(asString(r[1])), quote(asString(r[2])), quote(asString(r[3])),
		quote(asString(r[4])), asInt(r[5]), quote(asString(r[6])), quoteTime(asString(r[7]))))
}

// ReconOverview aggregates the recon posture: finding counts by severity, the
// hosts with the most findings, and the most recent high/critical findings.
type ReconOverview struct {
	SeverityCounts map[string]int64 `json:"severity_counts"`
	TopHosts       []HostFindingAgg `json:"top_hosts"`
	RecentHigh     []ScanFinding    `json:"recent_high"`
	TotalFindings  int64            `json:"total_findings"`
	// Partial is true when one of the sections could not be loaded; the
	// sections that did load are still returned, with PartialError set.
	Partial      bool   `json:"partial,omitempty"`
	PartialError string `json:"partial_error,omitempty"`
}

// HostFindingAgg is a per-host finding rollup.
type HostFindingAgg struct {
	Host     string `json:"host"`
	Total    int64  `json:"total"`
	Critical int64  `json:"critical"`
	High     int64  `json:"high"`
	Medium   int64  `json:"medium"`
}

// ReconOverview computes the aggregate posture across all stored findings.
func (s *Store) ReconOverview(ctx context.Context) (*ReconOverview, error) {
	ov := &ReconOverview{SeverityCounts: map[string]int64{}}

	if res, err := s.Query(ctx, `SELECT severity, count() FROM scan_findings GROUP BY severity`); err == nil {
		for _, r := range res.Rows {
			c := asInt(r[1])
			ov.SeverityCounts[asString(r[0])] = c
			ov.TotalFindings += c
		}
	} else {
		return nil, err
	}

	if res, err := s.Query(ctx, `SELECT target, count() AS c,
		countIf(severity='critical') AS crit, countIf(severity='high') AS hi, countIf(severity='medium') AS med
		FROM scan_findings WHERE target != '' GROUP BY target ORDER BY crit DESC, hi DESC, c DESC LIMIT 10`); err == nil {
		for _, r := range res.Rows {
			if len(r) < 5 {
				continue
			}
			ov.TopHosts = append(ov.TopHosts, HostFindingAgg{
				Host: asString(r[0]), Total: asInt(r[1]), Critical: asInt(r[2]), High: asInt(r[3]), Medium: asInt(r[4]),
			})
		}
	} else {
		ov.Partial = true
		ov.PartialError = err.Error()
	}

	if res, err := s.Query(ctx, `SELECT title, severity, target, port, service, detail, connector, toString(created_at)
		FROM scan_findings WHERE severity IN ('critical','high','medium') ORDER BY
		multiIf(severity='critical',0,severity='high',1,2), created_at DESC LIMIT 25`); err == nil {
		for _, r := range res.Rows {
			if len(r) < 8 {
				continue
			}
			ov.RecentHigh = append(ov.RecentHigh, ScanFinding{
				Title: asString(r[0]), Severity: asString(r[1]), Target: asString(r[2]),
				Port: asString(r[3]), Service: asString(r[4]), Detail: asString(r[5]),
				Fields: map[string]string{"connector": asString(r[6]), "seen_at": asString(r[7])},
			})
		}
	} else {
		ov.Partial = true
		if ov.PartialError == "" {
			ov.PartialError = err.Error()
		}
	}
	return ov, nil
}

// FindingsByTarget returns all findings across every scan that targeted a
// given host, newest and most severe first, the per-device intelligence view.
func (s *Store) FindingsByTarget(ctx context.Context, target string, limit int) ([]ScanFinding, error) {
	if limit <= 0 || limit > 10000 {
		limit = 2000
	}
	res, err := s.Query(ctx, fmt.Sprintf(`SELECT title, severity, target, port, service, detail, connector, toString(created_at)
		FROM scan_findings WHERE target = %s ORDER BY
		multiIf(severity='critical',0,severity='high',1,severity='medium',2,severity='low',3,4), created_at DESC
		LIMIT %d`, quote(target), limit))
	if err != nil {
		return nil, err
	}
	var out []ScanFinding
	for _, r := range res.Rows {
		if len(r) < 8 {
			continue
		}
		out = append(out, ScanFinding{
			Title: asString(r[0]), Severity: asString(r[1]), Target: asString(r[2]),
			Port: asString(r[3]), Service: asString(r[4]), Detail: asString(r[5]),
			Fields: map[string]string{"connector": asString(r[6]), "seen_at": asString(r[7])},
		})
	}
	return out, nil
}

// ScanFindings returns findings for a scan.
func (s *Store) ScanFindings(ctx context.Context, scanID string, limit int) ([]ScanFinding, error) {
	if limit <= 0 || limit > 10000 {
		limit = 2000
	}
	res, err := s.Query(ctx, fmt.Sprintf(`SELECT title, severity, target, port, service, detail, toJSONString(fields)
		FROM scan_findings WHERE scan_id = %s ORDER BY
		multiIf(severity='critical',0,severity='high',1,severity='medium',2,severity='low',3,4), title
		LIMIT %d`, quote(scanID), limit))
	if err != nil {
		return nil, err
	}
	var out []ScanFinding
	for _, r := range res.Rows {
		f := ScanFinding{
			Title: asString(r[0]), Severity: asString(r[1]), Target: asString(r[2]),
			Port: asString(r[3]), Service: asString(r[4]), Detail: asString(r[5]),
		}
		if len(r) > 6 {
			var m map[string]string
			if json.Unmarshal([]byte(asString(r[6])), &m) == nil {
				f.Fields = m
			}
		}
		out = append(out, f)
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
	// Since Go 1.24 crypto/rand.Read never returns an error: it crashes the
	// program rather than hand back predictable bytes.
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
