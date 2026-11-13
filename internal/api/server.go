// Package api is Basalt's HTTP server: session-authenticated JSON endpoints
// for search, administration, and saved objects, plus Splunk HEC-compatible
// ingest endpoints and the embedded web UI.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TYFSADIK/daru/internal/auth"
	"github.com/TYFSADIK/daru/internal/ingest"
	"github.com/TYFSADIK/daru/internal/search"
	"github.com/TYFSADIK/daru/internal/store"
)

// Server holds the API dependencies.
type Server struct {
	Store  *store.Store
	Auth   *auth.Manager
	Ingest *ingest.Ingester
	Search *search.Service
	Log    *slog.Logger
	Web    http.Handler // static UI, may be nil
	Secure bool         // set Secure flag on cookies (behind HTTPS)

	// Limits. Zero values take the Default* constants in limits.go; a
	// negative value disables that limit.
	IngestMaxEPS int // ingest events per second for the whole deployment
	// Replicas is how many Daru servers share the ingest limit. Each
	// server enforces IngestMaxEPS / Replicas, so together they stay
	// within the deployment wide limit. 0 or 1 means a single server.
	Replicas              int
	ScanConcurrentPerUser int // running scans per user
	ScanPerHourPerUser    int // scans started per user per hour
	SchedulesPerUser      int // scheduled scans owned per user

	// OIDC configures single sign on; a nil Provider disables it.
	OIDC OIDCSettings
	// LDAP, when set, checks passwords the local accounts do not match.
	LDAP       *auth.LDAPAuthenticator
	LDAPPolicy ExternalAccountPolicy
	// SAML configures SAML 2.0 single sign on; nil disables it.
	SAML *SAMLSettings

	// MetricsToken, when set, is required as a Bearer token on /metrics.
	// When empty, /metrics answers loopback clients only.
	MetricsToken string

	initOnce sync.Once

	// Stored audit trail: events queue here for a batching writer.
	auditOnce sync.Once
	auditCh   chan store.AuditEvent
	auditDone chan struct{}
	reconSem  chan struct{} // bounds concurrent scans
	capSem    chan struct{} // bounds concurrent live packet captures

	loginLimiter  *loginLimiter
	captureTokens map[string]captureToken
	captureMu     sync.Mutex

	ingestLimit *ingestLimiter
	quotas      *userQuotas
	metrics     *metrics
	acl         *indexACLCache
}

// limitOr resolves a configured limit: 0 means the default, negative
// means disabled (returned as 0).
func limitOr(v, def int) int {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	default:
		return v
	}
}

// initLimits builds the limiters once. Handler and RunScheduler both call
// it, so either may run first.
func (s *Server) initLimits() {
	s.initOnce.Do(func() {
		if s.reconSem == nil {
			s.reconSem = make(chan struct{}, 4)
		}
		eps := limitOr(s.IngestMaxEPS, DefaultIngestMaxEPS)
		if s.Replicas > 1 && eps > 0 {
			eps = (eps + s.Replicas - 1) / s.Replicas
		}
		s.ingestLimit = newIngestLimiter(eps)
		s.quotas = newUserQuotas(
			limitOr(s.ScanConcurrentPerUser, DefaultScanConcurrentPerUser),
			limitOr(s.ScanPerHourPerUser, DefaultScanPerHourPerUser),
			limitOr(s.SchedulesPerUser, DefaultSchedulesPerUser),
		)
		s.metrics = newMetrics()
		s.acl = newIndexACLCache()
	})
}

// captureToken is a one time token issued by POST /api/live/capture/start.
// The GET stream only runs when the caller presents a token issued in the
// last five minutes, so a plain GET (a link, an image tag, a top level
// navigation) can never start a packet capture.
type captureToken struct {
	iface    string
	duration int
	filter   string
	save     bool
	username string
	expires  time.Time
}

const sessionCookie = "daru_session"

type ctxKey int

const sessionKey ctxKey = 1

// Handler builds the HTTP handler with all routes.
func (s *Server) Handler() http.Handler {
	s.initLimits()
	if s.capSem == nil {
		s.capSem = make(chan struct{}, 2)
	}
	if s.loginLimiter == nil {
		s.loginLimiter = newLoginLimiter()
	}
	if s.captureTokens == nil {
		s.captureTokens = map[string]captureToken{}
	}
	mux := http.NewServeMux()

	// Auth.
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/oidc/config", s.handleOIDCConfig)
	mux.HandleFunc("GET /api/oidc/login", s.handleOIDCLogin)
	mux.HandleFunc("GET /api/oidc/callback", s.handleOIDCCallback)
	mux.HandleFunc("GET /api/saml/config", s.handleSAMLConfig)
	mux.HandleFunc("GET /api/saml/metadata", s.handleSAMLMetadata)
	mux.HandleFunc("GET /api/saml/login", s.handleSAMLLogin)
	mux.HandleFunc("POST /api/saml/acs", s.handleSAMLACS)
	mux.HandleFunc("GET /api/me", s.authed(auth.RoleUser, s.handleMe))
	mux.HandleFunc("POST /api/me/totp/enrol", s.authed(auth.RoleUser, s.handleTOTPEnrol))
	mux.HandleFunc("POST /api/me/totp/enable", s.authed(auth.RoleUser, s.handleTOTPEnable))
	mux.HandleFunc("POST /api/me/totp/disable", s.authed(auth.RoleUser, s.handleTOTPDisable))

	// Search.
	mux.HandleFunc("POST /api/search", s.authed(auth.RoleUser, s.handleSearch))
	mux.HandleFunc("GET /api/indexes", s.authed(auth.RoleUser, s.handleListIndexes))
	mux.HandleFunc("GET /api/commands", s.authed(auth.RoleUser, s.handleCommands))

	// Saved searches and dashboards.
	mux.HandleFunc("GET /api/saved", s.authed(auth.RoleUser, s.handleListSaved))
	mux.HandleFunc("POST /api/saved", s.authed(auth.RolePower, s.handleCreateSaved))
	mux.HandleFunc("DELETE /api/saved/{id}", s.authed(auth.RolePower, s.handleDeleteSaved))
	mux.HandleFunc("GET /api/dashboards", s.authed(auth.RoleUser, s.handleListDashboards))
	mux.HandleFunc("GET /api/dashboards/{id}", s.authed(auth.RoleUser, s.handleGetDashboard))
	mux.HandleFunc("POST /api/dashboards", s.authed(auth.RolePower, s.handleSaveDashboard))
	mux.HandleFunc("DELETE /api/dashboards/{id}", s.authed(auth.RolePower, s.handleDeleteDashboard))

	// Alerts.
	mux.HandleFunc("GET /api/alerts/history", s.authed(auth.RoleUser, s.handleAlertHistory))
	mux.HandleFunc("GET /api/notable", s.authed(auth.RoleUser, s.handleListNotable))
	mux.HandleFunc("POST /api/notable/{id}/status", s.authed(auth.RolePower, s.handleNotableStatus))
	mux.HandleFunc("GET /api/notable/{id}", s.authed(auth.RoleUser, s.handleNotableDetail))
	mux.HandleFunc("POST /api/notable/{id}/notes", s.authed(auth.RolePower, s.handleNotableNote))
	mux.HandleFunc("POST /api/notable/{id}/assign", s.authed(auth.RolePower, s.handleNotableAssign))

	// Recon and scanning.
	mux.HandleFunc("GET /api/recon/connectors", s.authed(auth.RoleUser, s.handleReconConnectors))
	mux.HandleFunc("POST /api/recon/scan", s.authed(auth.RolePower, s.handleReconScan))
	mux.HandleFunc("GET /api/recon/scans", s.authed(auth.RoleUser, s.handleReconScans))
	mux.HandleFunc("GET /api/recon/scans/{id}/findings", s.authed(auth.RoleUser, s.handleReconFindings))
	mux.HandleFunc("GET /api/recon/networks", s.authed(auth.RoleUser, s.handleReconNetworks))
	mux.HandleFunc("GET /api/assets", s.authed(auth.RoleUser, s.handleAssets))
	mux.HandleFunc("GET /api/device/{ip}", s.authed(auth.RoleUser, s.handleDevice))
	mux.HandleFunc("GET /api/recon/overview", s.authed(auth.RoleUser, s.handleReconOverview))
	mux.HandleFunc("POST /api/recon/pcap", s.authed(auth.RolePower, s.handleReconPcap))
	mux.HandleFunc("GET /api/recon/schedules", s.authed(auth.RoleUser, s.handleListSchedules))
	mux.HandleFunc("POST /api/recon/schedules", s.authed(auth.RolePower, s.handleCreateSchedule))
	mux.HandleFunc("DELETE /api/recon/schedules/{id}", s.authed(auth.RolePower, s.handleDeleteSchedule))

	// Live monitor: interfaces/WiFi snapshot and streaming packet capture.
	// Capture is two steps on purpose. POST /api/live/capture/start issues
	// a one time stream token; GET /api/live/capture only streams when the
	// token is presented, so a GET alone never starts a capture.
	mux.HandleFunc("GET /api/live/interfaces", s.authed(auth.RoleUser, s.handleLiveInterfaces))
	mux.HandleFunc("POST /api/live/capture/start", s.authed(auth.RolePower, s.handleLiveCaptureStart))
	mux.HandleFunc("GET /api/live/capture", s.authed(auth.RolePower, s.captureGate(s.handleLiveCapture)))

	// Administration.
	mux.HandleFunc("GET /api/admin/users", s.authed(auth.RoleAdmin, s.handleListUsers))
	mux.HandleFunc("POST /api/admin/users", s.authed(auth.RoleAdmin, s.handleCreateUser))
	mux.HandleFunc("POST /api/admin/users/{username}/password", s.authed(auth.RoleAdmin, s.handleSetPassword))
	mux.HandleFunc("POST /api/admin/users/{username}/role", s.authed(auth.RoleAdmin, s.handleSetRole))
	mux.HandleFunc("POST /api/admin/users/{username}/disabled", s.authed(auth.RoleAdmin, s.handleSetDisabled))
	mux.HandleFunc("POST /api/admin/users/{username}/indexes", s.authed(auth.RoleAdmin, s.handleSetIndexAccess))
	mux.HandleFunc("POST /api/admin/indexes", s.authed(auth.RoleAdmin, s.handleCreateIndex))
	mux.HandleFunc("GET /api/admin/audit", s.authed(auth.RoleAdmin, s.handleListAudit))
	mux.HandleFunc("GET /api/me/sessions", s.authed(auth.RoleUser, s.handleListMySessions))
	mux.HandleFunc("POST /api/me/sessions/revoke-others", s.authed(auth.RoleUser, s.handleRevokeOtherSessions))
	mux.HandleFunc("POST /api/me/sessions/{id}/revoke", s.authed(auth.RoleUser, s.handleRevokeMySession))
	mux.HandleFunc("GET /api/admin/users/{username}/sessions", s.authed(auth.RoleAdmin, s.handleListUserSessions))
	mux.HandleFunc("POST /api/admin/users/{username}/sessions/revoke", s.authed(auth.RoleAdmin, s.handleRevokeUserSessions))
	mux.HandleFunc("GET /api/admin/tokens", s.authed(auth.RoleAdmin, s.handleListTokens))
	mux.HandleFunc("POST /api/admin/tokens", s.authed(auth.RoleAdmin, s.handleCreateToken))
	mux.HandleFunc("POST /api/admin/tokens/{name}/disable", s.authed(auth.RoleAdmin, s.handleDisableToken))
	mux.HandleFunc("POST /api/admin/users/{username}/totp/disable", s.authed(auth.RoleAdmin, s.handleAdminDisableTOTP))
	mux.HandleFunc("GET /api/system", s.authed(auth.RoleAdmin, s.handleSystemInfo))
	mux.HandleFunc("POST /api/admin/update-tools", s.authed(auth.RoleAdmin, s.handleUpdateTools))

	// Ingest (Splunk HEC compatible + raw + JSON).
	mux.HandleFunc("POST /services/collector", s.handleHEC)
	mux.HandleFunc("POST /services/collector/event", s.handleHEC)
	mux.HandleFunc("POST /services/collector/raw", s.handleHECRaw)
	mux.HandleFunc("GET /services/collector/health", s.handleCollectorHealth)
	mux.HandleFunc("POST /api/ingest", s.handleJSONIngest)

	// Health, readiness, and metrics. /api/health is liveness: the process
	// answers. /ready also requires ClickHouse. /metrics is Prometheus text.
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /ready", s.handleReady)
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	// Web UI (static). Everything not under /api or /services falls through.
	if s.Web != nil {
		mux.Handle("/", s.Web)
	}

	return s.recoverer(s.logger(s.securityHeaders(mux)))
}

// handleLiveCaptureStart validates a capture request and issues a one time
// stream token. The token carries the capture parameters, so the GET stream
// cannot be repointed at a different interface or filter by editing the URL.
func (s *Server) handleLiveCaptureStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Iface    string `json:"iface"`
		Duration int    `json:"duration"`
		Filter   string `json:"filter"`
		Save     bool   `json:"save"`
	}
	if err := readJSON(r, &req, 16*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Iface == "" {
		writeError(w, http.StatusBadRequest, "iface is required")
		return
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue stream token")
		return
	}
	token := hex.EncodeToString(b)
	sess := sessionFrom(r.Context())
	s.captureMu.Lock()
	if s.captureTokens == nil {
		s.captureTokens = map[string]captureToken{}
	}
	s.captureTokens[token] = captureToken{
		iface:    req.Iface,
		duration: req.Duration,
		filter:   req.Filter,
		save:     req.Save,
		username: sess.Username,
		expires:  time.Now().Add(5 * time.Minute),
	}
	s.captureMu.Unlock()
	s.audit(r, "live.capture.start", sess.Username, "iface", req.Iface, "duration", req.Duration)
	writeJSON(w, http.StatusOK, map[string]any{
		"stream_token": token,
		"url":          "/api/live/capture?stream_token=" + token,
		"expires_in":   300,
	})
}

// captureGate wraps the live capture stream: it consumes a one time token
// issued by handleLiveCaptureStart, rewrites the request query to the
// parameters stored with that token, and rejects the request otherwise.
func (s *Server) captureGate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("stream_token")
		if token == "" {
			writeError(w, http.StatusForbidden, "live capture requires a stream token from POST /api/live/capture/start")
			return
		}
		s.captureMu.Lock()
		ct, ok := s.captureTokens[token]
		if ok {
			delete(s.captureTokens, token)
		}
		// Drop expired tokens while holding the lock.
		for k, v := range s.captureTokens {
			if time.Now().After(v.expires) {
				delete(s.captureTokens, k)
			}
		}
		s.captureMu.Unlock()
		if !ok || time.Now().After(ct.expires) {
			writeError(w, http.StatusForbidden, "stream token invalid or expired")
			return
		}
		sess := sessionFrom(r.Context())
		if sess == nil || sess.Username != ct.username {
			writeError(w, http.StatusForbidden, "stream token belongs to another user")
			return
		}
		q := url.Values{}
		q.Set("iface", ct.iface)
		q.Set("duration", strconv.Itoa(ct.duration))
		q.Set("filter", ct.filter)
		if ct.save {
			q.Set("save", "1")
		}
		r.URL.RawQuery = q.Encode()
		next(w, r)
	}
}

// --- middleware ---

func (s *Server) logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		s.metrics.observe(r.URL.Path, sw.status)
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/services/") {
			s.Log.Info("request",
				"method", r.Method, "path", r.URL.Path,
				"status", sw.status, "ms", time.Since(start).Milliseconds())
		}
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.Log.Error("panic", "err", rec, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Flush forwards to the underlying writer so Server-Sent Events (the live
// packet stream) can push each event immediately.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer for
// deadlines and other optional interfaces.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// authed wraps a handler with session auth, a minimum role, and CSRF
// protection for state changing requests made with a session cookie.
func (s *Server) authed(minRole string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, cookieAuth := s.session(r)
		if sess == nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if !roleAtLeast(sess.Role, minRole) {
			writeError(w, http.StatusForbidden, "insufficient role")
			return
		}
		s.ensureCSRFCookie(w, r)
		if !s.validateCSRF(w, r, cookieAuth) {
			return
		}
		ctx := context.WithValue(r.Context(), sessionKey, sess)
		next(w, r.WithContext(ctx))
	}
}

// session resolves the session token and reports whether it came from the
// session cookie. Cookie auth is ambient, so it needs CSRF protection;
// Bearer auth is not ambient, so it does not.
func (s *Server) session(r *http.Request) (*auth.Session, bool) {
	token := ""
	cookieAuth := false
	if c, err := r.Cookie(sessionCookie); err == nil {
		token = c.Value
		cookieAuth = true
	}
	if token == "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			token = strings.TrimPrefix(h, "Bearer ")
		}
	}
	if token == "" {
		return nil, false
	}
	sess, err := s.Auth.Validate(r.Context(), token)
	if err != nil {
		return nil, false
	}
	return sess, cookieAuth
}

func sessionFrom(ctx context.Context) *auth.Session {
	if s, ok := ctx.Value(sessionKey).(*auth.Session); ok {
		return s
	}
	return nil
}

var roleRank = map[string]int{auth.RoleUser: 1, auth.RolePower: 2, auth.RoleAdmin: 3}

func roleAtLeast(have, min string) bool { return roleRank[have] >= roleRank[min] }

// --- helpers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v) // headers are sent; a write error means the client left
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any, maxBytes int64) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBytes))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
