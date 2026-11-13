package store

import (
	"context"
	"testing"
	"time"
)

// TestRoundTripAudit stores audit events in a live ClickHouse and reads them
// back through each filter. It runs with the other integration tests.
func TestRoundTripAudit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	actor := "audit-test-" + time.Now().Format("150405.000000")
	now := time.Now()
	evs := []AuditEvent{
		{Time: now.Add(-2 * time.Hour), Event: "login.failure", Actor: actor, IP: "192.0.2.7", Outcome: "failure"},
		{Time: now.Add(-1 * time.Hour), Event: "login.success", Actor: actor, IP: "192.0.2.7"},
		{Time: now, Event: "token.create", Actor: actor, IP: "192.0.2.8", Details: map[string]string{"name": "fw-forwarder", "index": "network"}},
	}
	if err := s.InsertAudit(ctx, evs); err != nil {
		t.Fatal(err)
	}
	check := func(name string, f AuditFilter, want int) {
		t.Helper()
		f.Actor = actor
		got, err := s.ListAudit(ctx, f)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != want {
			t.Errorf("%s: got %d events, want %d", name, len(got), want)
		}
	}
	check("all", AuditFilter{}, 3)
	check("event prefix", AuditFilter{Event: "login."}, 2)
	check("exact event", AuditFilter{Event: "token.create"}, 1)
	check("failures", AuditFilter{Outcome: "failure"}, 1)
	check("detail text", AuditFilter{Text: "fw-forw"}, 1)
	check("ip text", AuditFilter{Text: "192.0.2.8"}, 1)
	check("since", AuditFilter{Since: now.Add(-90 * time.Minute)}, 2)
	got, _ := s.ListAudit(ctx, AuditFilter{Actor: actor})
	if len(got) == 3 {
		if got[0].Event != "token.create" {
			t.Errorf("newest first: got %s", got[0].Event)
		}
		if got[0].Details["index"] != "network" {
			t.Errorf("details not read back: %v", got[0].Details)
		}
		if got[2].Outcome != "failure" {
			t.Errorf("outcome not read back: %q", got[2].Outcome)
		}
	}
}
