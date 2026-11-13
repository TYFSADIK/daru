package search

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

	"github.com/TYFSADIK/daru/internal/store"
)

// mockCH is a fake ClickHouse HTTP endpoint that records request bodies and
// returns canned JSONCompact responses.
type mockCH struct {
	t      *testing.T
	bodies []string
	resp   string
}

func (m *mockCH) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	m.bodies = append(m.bodies, string(b))
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, m.resp)
}

func compactJSON(t *testing.T, cols []string, rows [][]any) string {
	t.Helper()
	meta := make([]map[string]string, len(cols))
	for i, c := range cols {
		meta[i] = map[string]string{"name": c, "type": "String"}
	}
	data := make([][]json.RawMessage, len(rows))
	for i, row := range rows {
		data[i] = make([]json.RawMessage, len(row))
		for j, v := range row {
			b, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			data[i][j] = b
		}
	}
	b, err := json.Marshal(map[string]any{
		"meta": meta, "data": data, "rows": len(rows),
		"statistics": map[string]any{"elapsed": 0.01, "rows_read": 10, "bytes_read": 100},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func testService(t *testing.T, resp string) (*Service, *mockCH) {
	t.Helper()
	m := &mockCH{t: t, resp: resp}
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	st := store.New(store.Config{URL: srv.URL, Database: "daru"})
	return New(st), m
}

func TestRunDefaultsEarliestTo24h(t *testing.T) {
	now := time.Date(2026, 11, 8, 15, 30, 45, 0, time.UTC)
	resp := compactJSON(t, []string{"_time", "host", "_raw", "fields"},
		[][]any{{"2026-11-08 15:00:00.000", "web1", "hi", map[string]any{}}})
	svc, m := testService(t, resp)
	_, err := svc.Run(context.Background(), Request{Query: "hi", Now: now})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(m.bodies) != 1 {
		t.Fatalf("expected 1 request, got %d", len(m.bodies))
	}
	if !strings.Contains(m.bodies[0], "2026-11-07 15:30:45") {
		t.Errorf("default earliest should be 24h before now, SQL body:\n%s", m.bodies[0])
	}
}

func TestRunUnknownIndexesOnlyReturnsEmpty(t *testing.T) {
	resp := compactJSON(t, []string{"_time", "_raw", "fields"}, nil)
	svc, m := testService(t, resp)
	out, err := svc.Run(context.Background(), Request{
		Query: "hi", IndexesSpecified: true, Indexes: []string{},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Count != 0 || len(out.Rows) != 0 {
		t.Errorf("unknown indexes only should return no rows, got %+v", out)
	}
	if len(m.bodies) != 0 {
		t.Errorf("unknown indexes only must not query ClickHouse, got %d requests", len(m.bodies))
	}
}

func TestCountUsesDedicatedCountQuery(t *testing.T) {
	resp := compactJSON(t, []string{"count()"}, [][]any{{float64(42)}})
	svc, m := testService(t, resp)
	n, err := svc.Count(context.Background(), Request{Query: "status=500", Earliest: "-1h"})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 42 {
		t.Errorf("Count = %d, want 42", n)
	}
	if len(m.bodies) != 1 || !strings.Contains(m.bodies[0], "SELECT count() FROM (") {
		t.Errorf("Count should wrap the query in SELECT count(), got %v", m.bodies)
	}
	if strings.Contains(m.bodies[0], "LIMIT 1") {
		t.Errorf("count query must not keep the row limit, got %s", m.bodies[0])
	}
}

func TestEventColumnsDerivedFromRows(t *testing.T) {
	resp := compactJSON(t, []string{"_time", "host", "_raw", "fields"},
		[][]any{{"2026-11-08 15:00:00.000", "web1", "status=500", map[string]any{"status": "500", "bytes": "10"}}})
	svc, _ := testService(t, resp)
	out, err := svc.Run(context.Background(), Request{Query: "hi", Earliest: "-1h"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	cols := map[string]bool{}
	for _, c := range out.Columns {
		cols[c] = true
	}
	for _, want := range []string{"_time", "host", "status", "bytes", "_raw"} {
		if !cols[want] {
			t.Errorf("columns %v missing %q", out.Columns, want)
		}
	}
	if len(out.Fields) == 0 || !out.Fields[0].Sampled {
		t.Errorf("field summaries should be labelled sampled: %+v", out.Fields)
	}
	if !out.Sampled {
		t.Error("response should be labelled sampled")
	}
}

func TestAggregatedValue(t *testing.T) {
	rows := []map[string]any{{"count": float64(7)}}
	v, ok := AggregatedValue(rows)
	if !ok || v != 7 {
		t.Errorf("AggregatedValue = %v %v, want 7 true", v, ok)
	}
	if _, ok := AggregatedValue([]map[string]any{{"a": float64(1)}, {"a": float64(2)}}); ok {
		t.Error("AggregatedValue should fail for more than one row")
	}
}

func TestAggregatedTotalMultiGroup(t *testing.T) {
	// stats count by host: three groups, total 2+5+3 = 10, not 3 groups.
	rows := []map[string]any{
		{"host": "10.0.0.1", "count": "2"},
		{"host": "10.0.0.2", "count": "5"},
		{"host": "10.0.0.3", "count": json.Number("3")},
	}
	v, ok := AggregatedTotal(rows, []string{"host", "count"}, "")
	if !ok || v != 10 {
		t.Errorf("AggregatedTotal = %v %v, want 10 true", v, ok)
	}
	// No column named count: first numeric column in result order, and an
	// IP-looking group column must not be mistaken for a number.
	rows = []map[string]any{
		{"src": "10.0.0.1", "hits": float64(4), "bytes": float64(100)},
		{"src": "10.0.0.2", "hits": float64(6), "bytes": float64(200)},
	}
	v, ok = AggregatedTotal(rows, []string{"src", "hits", "bytes"}, "")
	if !ok || v != 10 {
		t.Errorf("AggregatedTotal without count = %v %v, want 10 true", v, ok)
	}
	// Timechart: sum every series column, skip _time, sparse cells are zero.
	rows = []map[string]any{
		{"_time": "2026-11-13 10:00:00", "web": float64(1), "db": float64(2)},
		{"_time": "2026-11-13 10:05:00", "web": float64(3)},
	}
	v, ok = AggregatedTotal(rows, []string{"_time", "web", "db"}, "_time")
	if !ok || v != 6 {
		t.Errorf("AggregatedTotal timechart = %v %v, want 6 true", v, ok)
	}
	// No rows: zero, which is a valid count.
	if v, ok := AggregatedTotal(nil, []string{"count"}, ""); !ok || v != 0 {
		t.Errorf("AggregatedTotal empty = %v %v, want 0 true", v, ok)
	}
	// Only strings: no measure.
	if _, ok := AggregatedTotal([]map[string]any{{"host": "a"}}, []string{"host"}, ""); ok {
		t.Error("AggregatedTotal should fail without a numeric column")
	}
}
