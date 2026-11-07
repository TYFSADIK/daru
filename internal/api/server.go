// Package api is Basalt's HTTP server: session-authenticated JSON endpoints
// for search, administration, and saved objects, plus Splunk HEC-compatible
// ingest endpoints and the embedded web UI.
package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
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

	reconSem chan struct{} // bounds concurrent scans
}

const sessionCookie = "daru_session"

type ctxKey int

const sessionKey ctxKey = 1

// Handler builds the HTTP handler with all routes.
func (s *Server) Handler() http.Handler {
	if s.reconSem == nil {
		s.reconSem = make(chan struct{}, 4)
	}
	mux := http.NewServeMux()

	// Auth.
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/me", s.authed(auth.RoleUser, s.handleMe))

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

	// Recon and scanning.
	mux.HandleFunc("GET /api/recon/connectors", s.authed(auth.RoleUser, s.handleReconConnectors))
	mux.HandleFunc("POST /api/recon/scan", s.authed(auth.RolePower, s.handleReconScan))
	mux.HandleFunc("GET /api/recon/scans", s.authed(auth.RoleUser, s.handleReconScans))
	mux.HandleFunc("GET /api/recon/scans/{id}/findings", s.authed(auth.RoleUser, s.handleReconFindings))

	// Administration.
	mux.HandleFunc("GET /api/admin/users", s.authed(auth.RoleAdmin, s.handleListUsers))
	mux.HandleFunc("POST /api/admin/users", s.authed(auth.RoleAdmin, s.handleCreateUser))
	mux.HandleFunc("POST /api/admin/users/{username}/password", s.authed(auth.RoleAdmin, s.handleSetPassword))
	mux.HandleFunc("POST /api/admin/users/{username}/role", s.authed(auth.RoleAdmin, s.handleSetRole))
	mux.HandleFunc("POST /api/admin/users/{username}/disabled", s.authed(auth.RoleAdmin, s.handleSetDisabled))
	mux.HandleFunc("POST /api/admin/indexes", s.authed(auth.RoleAdmin, s.handleCreateIndex))
	mux.HandleFunc("GET /api/admin/tokens", s.authed(auth.RoleAdmin, s.handleListTokens))
	mux.HandleFunc("POST /api/admin/tokens", s.authed(auth.RoleAdmin, s.handleCreateToken))
	mux.HandleFunc("POST /api/admin/tokens/{name}/disable", s.authed(auth.RoleAdmin, s.handleDisableToken))

	// Ingest (Splunk HEC compatible + raw + JSON).
	mux.HandleFunc("POST /services/collector", s.handleHEC)
	mux.HandleFunc("POST /services/collector/event", s.handleHEC)
	mux.HandleFunc("POST /services/collector/raw", s.handleHECRaw)
	mux.HandleFunc("GET /services/collector/health", s.handleCollectorHealth)
	mux.HandleFunc("POST /api/ingest", s.handleJSONIngest)

	// Health.
	mux.HandleFunc("GET /api/health", s.handleHealth)

	// Web UI (static). Everything not under /api or /services falls through.
	if s.Web != nil {
		mux.Handle("/", s.Web)
	}

	return s.recoverer(s.logger(mux))
}

// --- middleware ---

func (s *Server) logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
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

// authed wraps a handler with session auth and a minimum role.
func (s *Server) authed(minRole string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.session(r)
		if sess == nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if !roleAtLeast(sess.Role, minRole) {
			writeError(w, http.StatusForbidden, "insufficient role")
			return
		}
		ctx := context.WithValue(r.Context(), sessionKey, sess)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) session(r *http.Request) *auth.Session {
	token := ""
	if c, err := r.Cookie(sessionCookie); err == nil {
		token = c.Value
	}
	if token == "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			token = strings.TrimPrefix(h, "Bearer ")
		}
	}
	if token == "" {
		return nil
	}
	sess, err := s.Auth.Validate(r.Context(), token)
	if err != nil {
		return nil
	}
	return sess
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
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any, maxBytes int64) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBytes))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
