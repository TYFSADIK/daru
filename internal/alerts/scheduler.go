package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TYFSADIK/daru/internal/search"
	"github.com/TYFSADIK/daru/internal/store"
)

// Scheduler runs enabled alert searches once per minute.
type Scheduler struct {
	st            *store.Store
	search        *search.Service
	log           *slog.Logger
	notify        []Notifier
	webhookSecret []byte

	// IndexScope, when set, resolves the indexes an alert's owner may
	// read. The alert search is limited to them, so a scheduled alert can
	// never read an index its owner cannot search interactively. The
	// bool reports whether the returned list must be enforced.
	IndexScope func(ctx context.Context, owner string) ([]string, bool, error)
}

// Notifier delivers a fired alert somewhere (webhook, log, etc.).
type Notifier interface {
	Notify(ctx context.Context, a Fired) error
}

// Fired describes an alert that met its condition.
type Fired struct {
	SearchName     string
	Severity       string
	ResultCount    int
	Query          string
	Sample         []map[string]any
	WebhookURL     string
	MitreTactic    string
	MitreTechnique string
}

// ActionConfig is the parsed form of a saved search actions JSON document.
type ActionConfig struct {
	Severity       string
	Actions        map[string]bool
	WebhookURL     string
	SuppressMin    int
	MitreTactic    string
	MitreTechnique string
}

// NewScheduler creates a Scheduler with a log notifier by default.
func NewScheduler(st *store.Store, svc *search.Service, log *slog.Logger) *Scheduler {
	s := &Scheduler{st: st, search: svc, log: log}
	s.notify = append(s.notify, &logNotifier{log: log})
	return s
}

// SetWebhookSecret enables HMAC-SHA256 signing of every webhook delivery.
// Receivers verify X-Daru-Signature against the timestamp and raw body; see
// SignWebhook. An empty secret leaves webhooks unsigned.
func (s *Scheduler) SetWebhookSecret(secret string) { s.webhookSecret = []byte(secret) }

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
			// Next tick is one minute after the minute just processed,
			// computed from the wall clock, so odd minutes are not skipped.
			timer.Reset(time.Until(minute.Add(time.Minute)))
		}
	}
}

func (s *Scheduler) tick(ctx context.Context, minute time.Time) {
	alerts, err := s.st.EnabledAlerts(ctx)
	if err != nil {
		s.log.Warn("could not load alerts", "err", err)
		return
	}
	// Run matching alerts concurrently, each with its own timeout, so one
	// slow search cannot delay every other alert past its minute.
	var wg sync.WaitGroup
	for _, a := range alerts {
		sched, err := ParseCron(a.Cron)
		if err != nil {
			s.log.Warn("bad cron in alert", "alert", a.Name, "err", err)
			continue
		}
		if !sched.Matches(minute) {
			continue
		}
		wg.Add(1)
		go func(a store.SavedSearch) {
			defer wg.Done()
			actx, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
			s.runAlert(actx, a)
		}(a)
	}
	wg.Wait()
}

func (s *Scheduler) runAlert(ctx context.Context, a store.SavedSearch) {
	cfg, err := ParseActions(a.Actions)
	if err != nil {
		s.log.Warn("bad alert actions, skipping", "alert", a.Name, "err", err)
		return
	}
	// Merge MITRE tags stored on the saved search itself.
	if cfg.MitreTactic == "" {
		cfg.MitreTactic = a.MitreTactic
	}
	if cfg.MitreTechnique == "" {
		cfg.MitreTechnique = a.MitreTechnique
	}
	// Suppression: do not re-fire the same alert inside its window.
	if cfg.SuppressMin > 0 {
		last, err := s.st.LastAlertFire(ctx, a.ID)
		if err != nil {
			s.log.Warn("could not check alert suppression", "alert", a.Name, "err", err)
		} else if !last.IsZero() && time.Since(last) < time.Duration(cfg.SuppressMin)*time.Minute {
			s.log.Info("alert suppressed, fired recently", "alert", a.Name, "last", last)
			return
		}
	}
	earliest := a.Earliest
	if earliest == "" {
		earliest = DefaultWindow(a.Cron)
	}
	req := search.Request{
		Query:    a.Query,
		Earliest: earliest,
		Latest:   orDefault(a.Latest, "now"),
		MaxRows:  5,
	}
	if s.IndexScope != nil && a.Owner != "" {
		indexes, enforced, err := s.IndexScope(ctx, a.Owner)
		if err != nil {
			s.log.Warn("could not resolve alert owner index access, skipping", "alert", a.Name, "owner", a.Owner, "err", err)
			return
		}
		req.Indexes, req.IndexesSpecified = indexes, enforced
	}
	// Evaluate the condition on a true count, not on len(rows).
	count, sample, err := s.alertCount(ctx, req)
	if err != nil {
		s.log.Warn("alert search failed", "alert", a.Name, "err", err)
		return
	}
	ok, err := conditionMetStrict(a.Condition, count)
	if err != nil {
		s.log.Warn("bad alert condition, skipping", "alert", a.Name, "err", err)
		return
	}
	if !ok {
		return
	}
	detail := fmt.Sprintf("%d result(s) matched", count)
	fired := Fired{
		SearchName: a.Name, Severity: cfg.Severity, ResultCount: count,
		Query: a.Query, Sample: sample,
		WebhookURL: cfg.WebhookURL, MitreTactic: cfg.MitreTactic,
		MitreTechnique: cfg.MitreTechnique,
	}
	delivered := true
	for _, n := range s.notify {
		if err := n.Notify(ctx, fired); err != nil {
			delivered = false
			s.log.Warn("notifier failed", "err", err)
		}
	}
	if cfg.Actions["webhook"] && cfg.WebhookURL != "" {
		if err := (&webhookNotifier{url: cfg.WebhookURL, secret: s.webhookSecret}).Notify(ctx, fired); err != nil {
			delivered = false
			s.log.Warn("webhook notifier failed", "alert", a.Name, "err", err)
		}
	}
	if err := s.st.RecordAlertFire(ctx, store.AlertFire{
		SearchID: a.ID, SearchName: a.Name, ResultCount: int64(count),
		Severity: cfg.Severity, Detail: detail, Delivered: delivered,
	}); err != nil {
		s.log.Warn("could not record alert fire", "err", err)
	}
	// A security alert also raises a notable event for the incident queue.
	if cfg.Actions["notable"] {
		mitre := mitreString(cfg.MitreTactic, cfg.MitreTechnique)
		if err := s.st.InsertNotable(ctx, store.NotableEvent{
			RuleName: a.Name, Severity: cfg.Severity, Status: "new",
			Mitre: mitre, Detail: detail,
		}); err != nil {
			s.log.Warn("could not raise notable event", "alert", a.Name, "err", err)
		}
	}
}

// alertCount returns the condition count and up to 5 sample rows. For a
// reporting query (stats, timechart) the count is the measure column summed
// over every output row; for an event query it is a dedicated count query.
func (s *Scheduler) alertCount(ctx context.Context, req search.Request) (int, []map[string]any, error) {
	resp, err := s.search.Run(ctx, req)
	if err != nil {
		return 0, nil, err
	}
	if resp.Kind == "table" || resp.Kind == "timechart" || resp.Kind == "chart" {
		// The first run fetched only a sample. A reporting result with
		// more groups than that is re-run in full, so the sum covers
		// every group and not just the first few.
		if len(resp.Rows) >= req.MaxRows {
			full := req
			full.MaxRows = 0 // the service caps this at its MaxRows
			if resp, err = s.search.Run(ctx, full); err != nil {
				return 0, nil, err
			}
		}
		// Sum the measure column over every group, so "stats count by
		// host" with three hosts of 2, 5, and 3 events counts 10, not 3.
		if v, ok := search.AggregatedTotal(resp.Rows, resp.Columns, resp.TimeField); ok {
			sample := resp.Rows
			if len(sample) > 5 {
				sample = sample[:5]
			}
			return int(v), sample, nil
		}
		return len(resp.Rows), resp.Rows, nil
	}
	n, err := s.search.Count(ctx, req)
	if err != nil {
		return 0, nil, err
	}
	return n, resp.Rows, nil
}

// DefaultWindow derives the alert lookback from its cron interval: 5m for
// every minute, 1h for hourly, 24h for daily, and up to 7d for weekly.
func DefaultWindow(cron string) string {
	return windowForCron(cron, time.Now().UTC())
}

func windowForCron(cron string, from time.Time) string {
	sched, err := ParseCron(cron)
	if err != nil {
		return "-5m"
	}
	start := from.Truncate(time.Minute)
	var first, second time.Time
	// Scan two weeks so a weekly schedule still finds a second firing.
	for i := 0; i < 14*24*60; i++ {
		t := start.Add(time.Duration(i) * time.Minute)
		if sched.Matches(t) {
			if first.IsZero() {
				first = t
			} else {
				second = t
				break
			}
		}
	}
	if first.IsZero() || second.IsZero() {
		return "-24h"
	}
	d := second.Sub(first)
	switch {
	case d <= 5*time.Minute:
		return "-5m"
	case d <= time.Hour:
		return "-1h"
	case d <= 24*time.Hour:
		return "-24h"
	default:
		return "-7d"
	}
}

func mitreString(tactic, technique string) string {
	switch {
	case tactic != "" && technique != "":
		return tactic + ":" + technique
	case technique != "":
		return technique
	default:
		return tactic
	}
}

// ValidateCondition checks an alert condition string strictly.
func ValidateCondition(condition string) error {
	_, err := conditionMetStrict(condition, 0)
	return err
}

// conditionMetStrict evaluates a condition and returns an error for any
// malformed value instead of silently treating it as zero.
func conditionMetStrict(condition string, count int) (bool, error) {
	condition = strings.TrimSpace(condition)
	if condition == "" {
		return count > 0, nil
	}
	condition = strings.TrimPrefix(condition, "count")
	condition = strings.TrimSpace(condition)
	for _, op := range []string{">=", "<=", "==", "!=", ">", "<", "="} {
		if strings.HasPrefix(condition, op) {
			rest := strings.TrimSpace(condition[len(op):])
			if rest == "" {
				return false, fmt.Errorf("condition %q needs a number after %s", condition, op)
			}
			n, err := strconv.Atoi(rest)
			if err != nil {
				return false, fmt.Errorf("condition %q: %q is not a number", condition, rest)
			}
			switch op {
			case ">":
				return count > n, nil
			case "<":
				return count < n, nil
			case ">=":
				return count >= n, nil
			case "<=":
				return count <= n, nil
			case "==", "=":
				return count == n, nil
			case "!=":
				return count != n, nil
			}
		}
	}
	return false, fmt.Errorf("condition %q needs an operator such as > or >=", condition)
}

// conditionMet evaluates a simple condition such as "count > 0" or ">= 10".
// An empty condition fires whenever there is at least one result.
// Malformed conditions return false; use conditionMetStrict for an error.
func conditionMet(condition string, count int) bool {
	ok, _ := conditionMetStrict(condition, count)
	return ok
}

// ParseActions parses an actions JSON document strictly.
func ParseActions(raw string) (ActionConfig, error) {
	cfg := ActionConfig{Severity: "medium", Actions: map[string]bool{}}
	if strings.TrimSpace(raw) == "" {
		return cfg, nil
	}
	var doc struct {
		Severity       string   `json:"severity"`
		Actions        []string `json:"actions"`
		WebhookURL     string   `json:"webhook_url"`
		SuppressMin    int      `json:"suppress_minutes"`
		MitreTactic    string   `json:"mitre_tactic"`
		MitreTechnique string   `json:"mitre_technique"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return cfg, fmt.Errorf("invalid alert actions JSON: %w", err)
	}
	if doc.Severity != "" {
		switch doc.Severity {
		case "low", "medium", "high", "critical":
			cfg.Severity = doc.Severity
		default:
			return cfg, fmt.Errorf("invalid severity %q", doc.Severity)
		}
	}
	for _, a := range doc.Actions {
		cfg.Actions[a] = true
	}
	if doc.WebhookURL != "" {
		u, err := url.Parse(doc.WebhookURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return cfg, fmt.Errorf("invalid webhook_url %q", doc.WebhookURL)
		}
		cfg.WebhookURL = doc.WebhookURL
	}
	if doc.SuppressMin < 0 || doc.SuppressMin > 60*24*7 {
		return cfg, fmt.Errorf("suppress_minutes out of range 0-10080")
	}
	cfg.SuppressMin = doc.SuppressMin
	if doc.MitreTactic != "" && !validMitreID(doc.MitreTactic, "TA") {
		return cfg, fmt.Errorf("invalid mitre_tactic %q", doc.MitreTactic)
	}
	if doc.MitreTechnique != "" && !validMitreID(doc.MitreTechnique, "T") {
		return cfg, fmt.Errorf("invalid mitre_technique %q", doc.MitreTechnique)
	}
	cfg.MitreTactic = doc.MitreTactic
	cfg.MitreTechnique = doc.MitreTechnique
	return cfg, nil
}

// ValidMitreID reports whether id is a MITRE tactic (TA0000) or technique
// (T0000 or T0000.000) identifier.
func ValidMitreID(id, prefix string) bool { return validMitreID(id, prefix) }

func validMitreID(id, prefix string) bool {
	if !strings.HasPrefix(id, prefix) {
		return false
	}
	rest := strings.TrimPrefix(id, prefix)
	// Accept TA0001, T1078, and T1078.001 sub techniques.
	parts := strings.Split(rest, ".")
	for i, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
		if i == 0 && len(part) != 4 {
			return false
		}
		if i == 1 && len(part) != 3 {
			return false
		}
		if i > 1 {
			return false
		}
	}
	return true
}

// ValidateActions checks an actions JSON document at save time.
func ValidateActions(raw string) error {
	_, err := ParseActions(raw)
	return err
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

// webhookNotifier posts a fired alert as JSON to a configured URL, with a
// 10 second timeout and one retry on a network error or 5xx response. When
// a secret is set, each request carries an HMAC-SHA256 signature.
type webhookNotifier struct {
	url    string
	client *http.Client
	secret []byte
	now    func() time.Time // for tests
}

// Webhook signature headers. The signature is
// "sha256=" + hex(HMAC-SHA256(secret, timestamp + "." + body)), where
// timestamp is the X-Daru-Timestamp value (Unix seconds). Receivers should
// recompute it with a constant time compare and reject timestamps more than
// five minutes old to stop replays.
const (
	WebhookSignatureHeader = "X-Daru-Signature"
	WebhookTimestampHeader = "X-Daru-Timestamp"
)

// SignWebhook returns the X-Daru-Signature value for a body and timestamp.
func SignWebhook(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhook checks a signature produced by SignWebhook, rejecting
// timestamps outside maxAge. It is exported so receivers written in Go,
// and the tests, share one definition of the scheme.
func VerifyWebhook(secret []byte, timestamp, signature string, body []byte, now time.Time, maxAge time.Duration) bool {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	age := now.Sub(time.Unix(ts, 0))
	if age < -maxAge || age > maxAge {
		return false
	}
	want := SignWebhook(secret, timestamp, body)
	return hmac.Equal([]byte(want), []byte(signature))
}

func (n *webhookNotifier) Notify(ctx context.Context, a Fired) error {
	client := n.client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	body, err := json.Marshal(map[string]any{
		"alert": a.SearchName, "severity": a.Severity,
		"result_count": a.ResultCount, "query": a.Query,
		"mitre_tactic": a.MitreTactic, "mitre_technique": a.MitreTechnique,
		"fired_at": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Daru-Webhook/1")
		if len(n.secret) > 0 {
			now := time.Now
			if n.now != nil {
				now = n.now
			}
			// Signed per attempt, so a retry carries a fresh timestamp.
			ts := strconv.FormatInt(now().Unix(), 10)
			req.Header.Set(WebhookTimestampHeader, ts)
			req.Header.Set(WebhookSignatureHeader, SignWebhook(n.secret, ts, body))
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("webhook returned status %d", resp.StatusCode)
		if resp.StatusCode < 500 {
			return lastErr
		}
	}
	return lastErr
}
