package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/TYFSADIK/basalt/internal/query"
)

// testStore connects to a live ClickHouse when BASALT_TEST_CH is set, else
// skips. CI without a database still passes; local runs exercise real SQL.
func testStore(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("BASALT_TEST_CH")
	if url == "" {
		t.Skip("set BASALT_TEST_CH to run store integration tests")
	}
	s := New(Config{
		URL:      url,
		Database: "basalt_test",
		User:     os.Getenv("BASALT_TEST_USER"),
		Password: os.Getenv("BASALT_TEST_PASS"),
	})
	ctx := context.Background()
	if err := s.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	return s
}

func TestRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	s.exec(ctx, "DROP DATABASE IF EXISTS basalt_test")
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Use recent timestamps: the events table has a 90-day retention TTL, so
	// old data would be purged by a background merge mid-test.
	base := time.Now().UTC().Add(-100 * time.Minute)
	var events []Event
	for i := 0; i < 100; i++ {
		status := "200"
		if i%5 == 0 {
			status = "500"
		}
		events = append(events, Event{
			Time:       base.Add(time.Duration(i) * time.Minute),
			Index:      "main",
			Host:       "web0" + string(rune('1'+i%3)),
			Source:     "/var/log/access.log",
			Sourcetype: "access_combined",
			Raw:        "GET /page status=" + status,
			Fields:     map[string]string{"status": status, "bytes": "1024"},
		})
	}
	n, err := s.InsertEvents(ctx, events)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if n != 100 {
		t.Fatalf("inserted %d, want 100", n)
	}

	run := func(q string) *Result {
		p, err := query.Parse(q)
		if err != nil {
			t.Fatalf("parse %q: %v", q, err)
		}
		c, err := query.Compile(p, query.Options{Indexes: []string{"main"}, MaxRows: 1000})
		if err != nil {
			t.Fatalf("compile %q: %v", q, err)
		}
		res, err := s.Query(ctx, c.SQL)
		if err != nil {
			t.Fatalf("query %q: %v\nSQL: %s", q, err, c.SQL)
		}
		return res
	}

	if got := run(`status=500 | stats count`).Rows; len(got) != 1 || asInt(got[0][0]) != 20 {
		t.Errorf("status=500 count = %v, want 20", got)
	}
	if got := run(`* | stats count by host`).Rows; len(got) != 3 {
		t.Errorf("count by host rows = %d, want 3", len(got))
	}
	if got := run(`* | stats avg(bytes) as a`).Rows; len(got) != 1 || asInt(got[0][0]) != 1024 {
		t.Errorf("avg(bytes) = %v, want 1024", got)
	}
	top := run(`* | top limit=2 status`)
	if len(top.Rows) != 2 {
		t.Errorf("top rows = %d, want 2", len(top.Rows))
	}
	tc := run(`* | timechart span=1h count`)
	if len(tc.Rows) == 0 {
		t.Errorf("timechart returned no buckets")
	}
	ev := run(`status=500`)
	if len(ev.Rows) != 20 {
		t.Errorf("raw search returned %d events, want 20", len(ev.Rows))
	}
}
