package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/TYFSADIK/daru/internal/search"
	"github.com/TYFSADIK/daru/internal/store"
)

// Scheduler runs enabled alert searches once per minute.
type Scheduler struct {
	st     *store.Store
	search *search.Service
	log    *slog.Logger
	notify []Notifier
}

// Notifier delivers a fired alert somewhere (webhook, log, etc.).
type Notifier interface {
	Notify(ctx context.Context, a Fired) error
}

// Fired describes an alert that met its condition.
type Fired struct {
	SearchName  string
	Severity    string
	ResultCount int
	Query       string
	Sample      []map[string]any
}

// NewScheduler creates a Scheduler with a log notifier by default.
func NewScheduler(st *store.Store, svc *search.Service, log *slog.Logger) *Scheduler {
	s := &Scheduler{st: st, search: svc, log: log}
	s.notify = append(s.notify, &logNotifier{log: log})
	return s
}

// AddNotifier registers an extra delivery channel.
func (s *Scheduler) AddNotifier(n Notifier) { s.notify = append(s.notify, n) }

// Run ticks every minute until the context is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	// Align to the next minute boundary.
	now := time.Now().UTC()
	next := now.Truncate(time.Minute).Add(time.Minute)
	timer := time.NewTimer(time.Until(next))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			minute := time.Now().UTC().Truncate(time.Minute)
			s.tick(ctx, minute)
			timer.Reset(time.Until(minute.Add(2 * time.Minute)))
		}
	}
}

func (s *Scheduler) tick(ctx context.Context, minute time.Time) {
	alerts, err := s.st.EnabledAlerts(ctx)
	if err != nil {
		s.log.Warn("could not load alerts", "err", err)
		return
	}
	for _, a := range alerts {
		sched, err := ParseCron(a.Cron)
		if err != nil {
			s.log.Warn("bad cron in alert", "alert", a.Name, "err", err)
			continue
		}
		if !sched.Matches(minute) {
			continue
		}
		s.runAlert(ctx, a)
	}
}

func (s *Scheduler) runAlert(ctx context.Context, a store.SavedSearch) {
	resp, err := s.search.Run(ctx, search.Request{
		Query:    a.Query,
		Earliest: orDefault(a.Earliest, "-5m"),
		Latest:   orDefault(a.Latest, "now"),
		MaxRows:  1000,
	})
	if err != nil {
		s.log.Warn("alert search failed", "alert", a.Name, "err", err)
		return
	}
	if !conditionMet(a.Condition, resp.Count) {
		return
	}
	severity, actions := parseActions(a.Actions)
	detail := fmt.Sprintf("%d result(s) matched", resp.Count)
	if err := s.st.RecordAlertFire(ctx, store.AlertFire{
		SearchID: a.ID, SearchName: a.Name, ResultCount: int64(resp.Count),
		Severity: severity, Detail: detail,
	}); err != nil {
		s.log.Warn("could not record alert fire", "err", err)
	}
	// A security alert also raises a notable event for the incident queue.
	if actions["notable"] {
		s.st.InsertNotable(ctx, store.NotableEvent{
			RuleName: a.Name, Severity: severity, Status: "new",
			Detail: detail,
		})
	}
	sample := resp.Rows
	if len(sample) > 5 {
		sample = sample[:5]
	}
	fired := Fired{SearchName: a.Name, Severity: severity, ResultCount: resp.Count, Query: a.Query, Sample: sample}
	for _, n := range s.notify {
		if err := n.Notify(ctx, fired); err != nil {
			s.log.Warn("notifier failed", "err", err)
		}
	}
}

// conditionMet evaluates a simple condition such as "count > 0" or ">= 10".
// An empty condition fires whenever there is at least one result.
func conditionMet(condition string, count int) bool {
	condition = strings.TrimSpace(condition)
	if condition == "" {
		return count > 0
	}
	condition = strings.TrimPrefix(condition, "count")
	condition = strings.TrimSpace(condition)
	for _, op := range []string{">=", "<=", "==", "!=", ">", "<", "="} {
		if strings.HasPrefix(condition, op) {
			n := 0
			fmt.Sscan(strings.TrimSpace(condition[len(op):]), &n)
			switch op {
			case ">":
				return count > n
			case "<":
				return count < n
			case ">=":
				return count >= n
			case "<=":
				return count <= n
			case "==", "=":
				return count == n
			case "!=":
				return count != n
			}
		}
	}
	return count > 0
}

func parseActions(raw string) (severity string, actions map[string]bool) {
	severity = "medium"
	actions = map[string]bool{}
	if raw == "" {
		return
	}
	var cfg struct {
		Severity string   `json:"severity"`
		Actions  []string `json:"actions"`
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err == nil {
		if cfg.Severity != "" {
			severity = cfg.Severity
		}
		for _, a := range cfg.Actions {
			actions[a] = true
		}
	}
	return
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

type logNotifier struct{ log *slog.Logger }

func (n *logNotifier) Notify(_ context.Context, a Fired) error {
	n.log.Info("alert fired", "alert", a.SearchName, "severity", a.Severity, "results", a.ResultCount)
	return nil
}
