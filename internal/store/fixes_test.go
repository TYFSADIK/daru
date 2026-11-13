package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockStore is a fake ClickHouse that records SQL bodies and answers by
// matching the SQL text.
type mockStore struct {
	t      *testing.T
	bodies []string
	urls   []string
	// handler, if set, answers each request; otherwise returns empty JSONCompact.
	handler func(body string) (string, int)
}

func (m *mockStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	m.bodies = append(m.bodies, string(b))
	m.urls = append(m.urls, r.URL.String())
	resp := `{"meta":[],"data":[],"rows":0,"statistics":{"elapsed":0,"rows_read":0,"bytes_read":0}}`
	code := http.StatusOK
	if m.handler != nil {
		resp, code = m.handler(string(b))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprint(w, resp)
}

func compactResp(cols []string, rows [][]any) string {
	meta := make([]map[string]string, len(cols))
	for i, c := range cols {
		meta[i] = map[string]string{"name": c, "type": "String"}
	}
	data := make([][]json.RawMessage, len(rows))
	for i, row := range rows {
		data[i] = make([]json.RawMessage, len(row))
		for j, v := range row {
			b, _ := json.Marshal(v)
			data[i][j] = b
		}
	}
	b, _ := json.Marshal(map[string]any{
		"meta": meta, "data": data, "rows": len(rows),
		"statistics": map[string]any{"elapsed": 0.01, "rows_read": 10, "bytes_read": 100},
	})
	return string(b)
}

func testStoreWithMock(t *testing.T, m *mockStore) *Store {
	t.Helper()
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return New(Config{URL: srv.URL, Database: "daru"})
}

func TestDoSetsQueryLimits(t *testing.T) {
	m := &mockStore{t: t}
	s := testStoreWithMock(t, m)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if len(m.urls) != 1 {
		t.Fatalf("expected 1 request, got %d", len(m.urls))
	}
	if !strings.Contains(m.urls[0], "max_execution_time=30") || !strings.Contains(m.urls[0], "max_rows_to_read=10000000") {
		t.Errorf("do() should set query limits, URL = %s", m.urls[0])
	}
}

func TestDecodeCellKeepsIntegerPrecision(t *testing.T) {
	v := decodeCell(json.RawMessage("9007199254740993"))
	n, ok := v.(json.Number)
	if !ok {
		t.Fatalf("decodeCell integer = %T %v, want json.Number", v, v)
	}
	if n.String() != "9007199254740993" {
		t.Errorf("decodeCell integer = %s, want 9007199254740993", n.String())
	}
	if f, ok := decodeCell(json.RawMessage("1.5")).(float64); !ok || f != 1.5 {
		t.Errorf("decodeCell 1.5 = %v %T, want float64 1.5", decodeCell(json.RawMessage("1.5")), decodeCell(json.RawMessage("1.5")))
	}
}

func TestDeterministicFindingID(t *testing.T) {
	f := ScanFinding{ScanID: "scan1", Title: "Open port", Target: "10.0.0.1", Port: "22", Service: "ssh"}
	a := deterministicFindingID(f)
	b := deterministicFindingID(f)
	if a != b {
		t.Errorf("deterministic id not stable: %s vs %s", a, b)
	}
	if len(a) != 36 || a[8] != '-' || a[13] != '-' {
		t.Errorf("deterministic id not a UUID: %q", a)
	}
	f.Title = "Other finding"
	if deterministicFindingID(f) == a {
		t.Error("different finding should give a different id")
	}
}

func TestSaveSearchReturnsGeneratedID(t *testing.T) {
	m := &mockStore{t: t}
	s := testStoreWithMock(t, m)
	id, err := s.SaveSearch(context.Background(), SavedSearch{Name: "x", Query: "hi", Owner: "u"})
	if err != nil {
		t.Fatalf("SaveSearch: %v", err)
	}
	if id == "" || len(id) != 36 {
		t.Errorf("SaveSearch should return a generated UUID, got %q", id)
	}
	if len(m.bodies) != 1 || !strings.Contains(m.bodies[0], id) {
		t.Errorf("SaveSearch SQL should contain the returned id, got %v", m.bodies)
	}
	id2, err := s.SaveDashboard(context.Background(), Dashboard{Name: "d", Owner: "u"})
	if err != nil {
		t.Fatalf("SaveDashboard: %v", err)
	}
	if id2 == "" || len(id2) != 36 {
		t.Errorf("SaveDashboard should return a generated UUID, got %q", id2)
	}
}

func TestMarkScheduledScanRunMissingErrors(t *testing.T) {
	m := &mockStore{t: t}
	m.handler = func(body string) (string, int) {
		return compactResp([]string{"connector"}, nil), http.StatusOK
	}
	s := testStoreWithMock(t, m)
	err := s.MarkScheduledScanRun(context.Background(), "nope")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("MarkScheduledScanRun for a missing scan should error, got %v", err)
	}
}

func TestInsertEventsChunksAndValidatesIndex(t *testing.T) {
	m := &mockStore{t: t}
	s := testStoreWithMock(t, m)
	events := make([]Event, 10001)
	for i := range events {
		events[i] = Event{Index: "main", Raw: "hi", Time: time.Now().UTC()}
	}
	n, err := s.InsertEvents(context.Background(), events)
	if err != nil || n != 10001 {
		t.Fatalf("InsertEvents = %d %v, want 10001 nil", n, err)
	}
	inserts := 0
	for _, b := range m.bodies {
		if strings.Contains(b, "INSERT INTO events") {
			inserts++
		}
	}
	if inserts != 2 {
		t.Errorf("10001 events should chunk into 2 inserts, got %d", inserts)
	}
	_, err = s.InsertEvents(context.Background(), []Event{{Index: "bad index!", Raw: "x", Time: time.Now().UTC()}})
	if err == nil {
		t.Error("invalid index name should fail")
	}
}

func TestListQueriesHaveLimits(t *testing.T) {
	m := &mockStore{t: t}
	s := testStoreWithMock(t, m)
	if _, err := s.ListSavedSearches(context.Background()); err != nil {
		t.Fatalf("ListSavedSearches: %v", err)
	}
	if _, err := s.ListDashboards(context.Background()); err != nil {
		t.Fatalf("ListDashboards: %v", err)
	}
	if _, err := s.ListAssets(context.Background()); err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if _, err := s.ListScheduledScans(context.Background()); err != nil {
		t.Fatalf("ListScheduledScans: %v", err)
	}
	for _, b := range m.bodies {
		if !strings.Contains(b, "LIMIT 1000") {
			t.Errorf("list query missing LIMIT 1000:\n%s", b)
		}
	}
}

func TestDropOldPartitions(t *testing.T) {
	oldest := time.Now().UTC().AddDate(0, 0, -10).Format("2006-01-02 15:04:05.000")
	newest := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	alters := 0
	m := &mockStore{t: t}
	m.handler = func(body string) (string, int) {
		if strings.Contains(body, "FROM indexes") || strings.Contains(body, "FROM (SELECT DISTINCT name") {
			return compactResp([]string{"name", "retention_days", "events", "bytes", "oldest", "newest"},
				[][]any{
					{"main", float64(1), float64(5), float64(0), oldest, newest},
					// Empty index: the join reports 1970 as oldest; it must be skipped.
					{"empty", float64(1), float64(0), float64(0), "1970-01-01 00:00:00.000", "1970-01-01 00:00:00.000"},
				}), http.StatusOK
		}
		if strings.Contains(body, "ALTER TABLE events DROP PARTITION") {
			alters++
			return `{}`, http.StatusOK
		}
		return `{"meta":[],"data":[],"rows":0,"statistics":{"elapsed":0,"rows_read":0,"bytes_read":0}}`, http.StatusOK
	}
	s := testStoreWithMock(t, m)
	n, err := s.DropOldPartitions(context.Background())
	if err != nil {
		t.Fatalf("DropOldPartitions: %v", err)
	}
	// Oldest is 10 days ago, retention 1 day, so 9 day partitions are expired.
	if n != 9 || alters != 9 {
		t.Errorf("DropOldPartitions = %d drops (%d ALTERs), want 9", n, alters)
	}
}

func TestRowHelpersGuardShortRows(t *testing.T) {
	if rowString([]any{"a"}, 5) != "" || rowInt([]any{"a"}, 5) != 0 {
		t.Error("row helpers should return zero values for short rows")
	}
	if rowToAsset([]any{"10.0.0.1"}) != nil {
		t.Error("rowToAsset should return nil for a short row")
	}
}

func TestRunRetentionSweepsWithoutScheduler(t *testing.T) {
	oldest := time.Now().UTC().AddDate(0, 0, -3).Format("2006-01-02 15:04:05.000")
	newest := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	drops := make(chan struct{}, 16)
	m := &mockStore{t: t}
	m.handler = func(body string) (string, int) {
		if strings.Contains(body, "FROM (SELECT DISTINCT name") {
			return compactResp([]string{"name", "retention_days", "events", "bytes", "oldest", "newest"},
				[][]any{{"main", float64(1), float64(5), float64(0), oldest, newest}}), http.StatusOK
		}
		if strings.Contains(body, "DROP PARTITION") {
			drops <- struct{}{}
			return `{}`, http.StatusOK
		}
		return `{"meta":[],"data":[],"rows":0,"statistics":{"elapsed":0,"rows_read":0,"bytes_read":0}}`, http.StatusOK
	}
	s := testStoreWithMock(t, m)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.RunRetention(ctx, nil, time.Hour); close(done) }()
	select {
	case <-drops:
	case <-time.After(5 * time.Second):
		t.Fatal("RunRetention did not sweep at start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunRetention did not stop on cancel")
	}
}

func TestCredentialSplit(t *testing.T) {
	type call struct{ user, url, body string }
	var calls []call
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		calls = append(calls, call{r.Header.Get("X-ClickHouse-User"), r.URL.String(), string(b)})
		fmt.Fprint(w, `{"meta":[],"data":[],"rows":0,"statistics":{"elapsed":0,"rows_read":0,"bytes_read":0}}`)
	}))
	defer srv.Close()
	s := New(Config{URL: srv.URL, Database: "daru", User: "daru_app", Password: "a", AdminUser: "daru_admin", AdminPassword: "b"})
	if !s.SplitPrivileges() {
		t.Fatal("SplitPrivileges should be true with a separate admin user")
	}
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	for _, c := range calls {
		if c.user != "daru_admin" {
			t.Errorf("migration statement ran as %q, want daru_admin: %.60s", c.user, c.body)
		}
	}
	calls = nil
	if _, err := s.Query(ctx, "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.QueryReadOnly(ctx, "SELECT 2"); err != nil {
		t.Fatal(err)
	}
	if calls[0].user != "daru_app" || strings.Contains(calls[0].url, "readonly") {
		t.Errorf("app query wrong: %+v", calls[0])
	}
	if calls[1].user != "daru_app" || !strings.Contains(calls[1].url, "readonly=2") {
		t.Errorf("search query should be app user with readonly=2: %+v", calls[1])
	}
	// No admin configured: one user does everything, as before.
	one := New(Config{URL: srv.URL, User: "daru", Password: "x"})
	if one.SplitPrivileges() {
		t.Error("SplitPrivileges should be false without an admin user")
	}
}

func TestEnsureIndexRetentionBounds(t *testing.T) {
	m := &mockStore{t: t}
	s := testStoreWithMock(t, m)
	if err := s.EnsureIndex(context.Background(), "long", MaxRetentionDays); err != nil {
		t.Errorf("retention at the backstop should be allowed: %v", err)
	}
	if err := s.EnsureIndex(context.Background(), "toolong", MaxRetentionDays+1); err == nil {
		t.Error("retention beyond the TTL backstop should be refused")
	}
}
