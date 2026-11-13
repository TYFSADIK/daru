package api

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// metrics is a small, dependency free Prometheus registry. Daru keeps its
// single binary and stdlib only stance, so this writes the text exposition
// format (version 0.0.4) directly instead of importing client_golang.
type metrics struct {
	start time.Time

	mu       sync.Mutex
	requests map[string]uint64 // key: route class + "|" + status class

	ingestEvents   atomic.Uint64
	ingestRejected atomic.Uint64 // events refused by the rate limiter
	searches       atomic.Uint64
	searchErrors   atomic.Uint64
	scansStarted   atomic.Uint64
	quotaRejected  atomic.Uint64
	auditDropped   atomic.Uint64
	loginFailures  atomic.Uint64
}

func newMetrics() *metrics {
	return &metrics{start: time.Now(), requests: map[string]uint64{}}
}

// routeClass buckets a path into a low cardinality label, so per id paths
// such as /api/device/10.0.0.1 never create a new series each.
func routeClass(path string) string {
	switch {
	case strings.HasPrefix(path, "/services/"):
		return "ingest"
	case path == "/api/ingest":
		return "ingest"
	case strings.HasPrefix(path, "/api/search"):
		return "search"
	case strings.HasPrefix(path, "/api/recon"), strings.HasPrefix(path, "/api/live"):
		return "recon"
	case strings.HasPrefix(path, "/api/admin"):
		return "admin"
	case path == "/api/login" || path == "/api/logout" || strings.HasPrefix(path, "/api/me"):
		return "auth"
	case path == "/api/health" || path == "/ready" || path == "/metrics":
		return "probe"
	case strings.HasPrefix(path, "/api/"):
		return "api"
	default:
		return "ui"
	}
}

func (m *metrics) observe(path string, status int) {
	if m == nil {
		return
	}
	key := routeClass(path) + "|" + fmt.Sprintf("%dxx", status/100)
	m.mu.Lock()
	m.requests[key]++
	m.mu.Unlock()
}

// write renders every metric in Prometheus text format. Gauges that live
// on the Server (scan slots in use) are passed in.
func (m *metrics) write(w http.ResponseWriter, scansRunning, scanSlots int, ready bool) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var b strings.Builder
	counter := func(name, help string, v uint64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	gauge := func(name, help string, v float64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n", name, help, name, name, v)
	}

	b.WriteString("# HELP daru_http_requests_total HTTP requests by route class and status class.\n# TYPE daru_http_requests_total counter\n")
	m.mu.Lock()
	keys := make([]string, 0, len(m.requests))
	for k := range m.requests {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		route, code, _ := strings.Cut(k, "|")
		fmt.Fprintf(&b, "daru_http_requests_total{route=%q,code=%q} %d\n", route, code, m.requests[k])
	}
	m.mu.Unlock()

	counter("daru_ingest_events_total", "Events accepted by the ingest endpoints.", m.ingestEvents.Load())
	counter("daru_ingest_events_rejected_total", "Events refused by the global ingest rate limiter.", m.ingestRejected.Load())
	counter("daru_searches_total", "Searches run through the API.", m.searches.Load())
	counter("daru_search_errors_total", "Searches that failed.", m.searchErrors.Load())
	counter("daru_scans_started_total", "Recon scans started, manual and scheduled.", m.scansStarted.Load())
	counter("daru_quota_rejections_total", "Requests refused by a per user scan or schedule quota.", m.quotaRejected.Load())
	counter("daru_audit_dropped_total", "Audit events that could not be stored (they remain in the server log).", m.auditDropped.Load())
	counter("daru_login_failures_total", "Failed login attempts.", m.loginFailures.Load())
	gauge("daru_scans_running", "Recon scans currently holding a slot.", float64(scansRunning))
	gauge("daru_scan_slots", "Maximum concurrent recon scans.", float64(scanSlots))
	r := 0.0
	if ready {
		r = 1
	}
	gauge("daru_ready", "1 when ClickHouse answered the readiness probe.", r)
	gauge("daru_uptime_seconds", "Seconds since the server started.", time.Since(m.start).Seconds())
	gauge("daru_goroutines", "Goroutines in the Daru process.", float64(runtime.NumGoroutine()))
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	gauge("daru_heap_alloc_bytes", "Bytes of allocated heap objects.", float64(ms.HeapAlloc))
	_, _ = w.Write([]byte(b.String()))
}

// handleReady is the readiness probe: 200 only when ClickHouse answers
// within two seconds, 503 otherwise. Like /api/health it is
// unauthenticated and reveals nothing but the verdict.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.ready(r.Context()) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
}

func (s *Server) ready(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return s.Store.Ping(ctx) == nil
}

// handleMetrics serves Prometheus metrics. With MetricsToken set, a
// matching "Authorization: Bearer <token>" is required. Without it, only
// loopback clients are served, so a default install never exposes
// operational data to the network.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.MetricsToken != "" {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.MetricsToken)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="daru-metrics"`)
			writeError(w, http.StatusUnauthorized, "metrics token required")
			return
		}
	} else if !remoteIsLoopback(r) {
		writeError(w, http.StatusForbidden, "metrics are served to loopback only unless DARU_METRICS_TOKEN is set")
		return
	}
	s.metrics.write(w, len(s.reconSem), cap(s.reconSem), s.ready(r.Context()))
}

func remoteIsLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
