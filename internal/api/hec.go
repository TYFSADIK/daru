package api

import (
	"io"
	"net/http"
	"strings"

	"github.com/TYFSADIK/daru/internal/ingest"
)

const maxIngestBytes = 64 << 20 // 64 MiB per request

// ingestToken resolves the HEC token from the Authorization header. Splunk
// forwarders send "Authorization: Splunk <token>"; Bearer is also accepted.
func (s *Server) ingestToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	switch {
	case strings.HasPrefix(h, "Splunk "):
		return strings.TrimSpace(strings.TrimPrefix(h, "Splunk "))
	case strings.HasPrefix(h, "Bearer "):
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}

func (s *Server) authIngest(w http.ResponseWriter, r *http.Request) (string, bool) {
	token := s.ingestToken(r)
	if token == "" {
		writeHECError(w, http.StatusUnauthorized, "Token required")
		return "", false
	}
	tok, err := s.Auth.ValidateIngestToken(r.Context(), token)
	if err != nil {
		writeHECError(w, http.StatusForbidden, "Invalid token")
		return "", false
	}
	return tok.DefaultIndex, true
}

func (s *Server) handleHEC(w http.ResponseWriter, r *http.Request) {
	defaultIndex, ok := s.authIngest(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxIngestBytes))
	if err != nil {
		writeHECError(w, http.StatusBadRequest, "Could not read body")
		return
	}
	events, err := ingest.ParseHEC(body, defaultIndex, hostFrom(r))
	if err != nil {
		writeHECError(w, http.StatusBadRequest, err.Error())
		return
	}
	n, err := s.Ingest.Write(r.Context(), events)
	if err != nil {
		writeHECError(w, http.StatusInternalServerError, "Could not store events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"text": "Success", "code": 0, "events": n})
}

func (s *Server) handleHECRaw(w http.ResponseWriter, r *http.Request) {
	defaultIndex, ok := s.authIngest(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxIngestBytes))
	if err != nil {
		writeHECError(w, http.StatusBadRequest, "Could not read body")
		return
	}
	q := r.URL.Query()
	index := firstNonEmpty(q.Get("index"), defaultIndex)
	events := ingest.ParseRaw(body, index, firstNonEmpty(q.Get("host"), hostFrom(r)), q.Get("source"), q.Get("sourcetype"))
	n, err := s.Ingest.Write(r.Context(), events)
	if err != nil {
		writeHECError(w, http.StatusInternalServerError, "Could not store events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"text": "Success", "code": 0, "events": n})
}

func (s *Server) handleCollectorHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"text": "HEC is available and accepting input", "code": 17})
}

// handleJSONIngest accepts a simple JSON array of events, for scripts that do
// not speak HEC.
func (s *Server) handleJSONIngest(w http.ResponseWriter, r *http.Request) {
	defaultIndex, ok := s.authIngest(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxIngestBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read body")
		return
	}
	events, err := ingest.ParseHEC(body, defaultIndex, hostFrom(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	n, err := s.Ingest.Write(r.Context(), events)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not store events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": n})
}

func writeHECError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"text": msg, "code": code})
}

func hostFrom(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
