package api

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/TYFSADIK/daru/internal/auth"
	"github.com/TYFSADIK/daru/internal/ingest"
	"github.com/TYFSADIK/daru/internal/store"
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

// validIndexName mirrors store.validName: letters, digits, underscore and
// hyphen only. It is duplicated here because that helper is unexported and
// the ingest layer must reject a bad index before any event is stored.
func validIndexName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// enforceTokenIndex rejects a batch in which any event names an index other
// than the token's default. A token for "main" must not be able to forge
// events into "network" or "recon", where they would look like scan or
// packet findings.
func enforceTokenIndex(events []store.Event, tok *auth.IngestToken) error {
	if !validIndexName(tok.DefaultIndex) {
		return fmt.Errorf("token has an invalid default index")
	}
	for _, ev := range events {
		if ev.Index != tok.DefaultIndex {
			return fmt.Errorf("event index %q does not match token index %q", ev.Index, tok.DefaultIndex)
		}
	}
	return nil
}

func (s *Server) authIngest(w http.ResponseWriter, r *http.Request) (*auth.IngestToken, bool) {
	token := s.ingestToken(r)
	if token == "" {
		writeHECError(w, http.StatusUnauthorized, "Token required")
		return nil, false
	}
	tok, err := s.Auth.ValidateIngestToken(r.Context(), token)
	if err != nil {
		writeHECError(w, http.StatusForbidden, "Invalid token")
		return nil, false
	}
	return tok, true
}

func (s *Server) handleHEC(w http.ResponseWriter, r *http.Request) {
	tok, ok := s.authIngest(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxIngestBytes))
	if err != nil {
		writeHECError(w, http.StatusBadRequest, "Could not read body")
		return
	}
	events, err := ingest.ParseHEC(body, tok.DefaultIndex, hostFrom(r))
	if err != nil {
		writeHECError(w, http.StatusBadRequest, "Could not parse events")
		return
	}
	if err := enforceTokenIndex(events, tok); err != nil {
		s.Log.Warn("hec index rejected", "token", tok.Name, "err", err)
		writeHECError(w, http.StatusForbidden, "Event index does not match token index")
		return
	}
	if !s.admitIngest(w, len(events), true) {
		return
	}
	n, err := s.Ingest.Write(r.Context(), events)
	if err != nil {
		writeHECError(w, http.StatusInternalServerError, "Could not store events")
		return
	}
	s.metrics.ingestEvents.Add(uint64(n)) // #nosec G115 -- n is a non-negative event count
	writeJSON(w, http.StatusOK, map[string]any{"text": "Success", "code": 0, "events": n})
}

func (s *Server) handleHECRaw(w http.ResponseWriter, r *http.Request) {
	tok, ok := s.authIngest(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxIngestBytes))
	if err != nil {
		writeHECError(w, http.StatusBadRequest, "Could not read body")
		return
	}
	q := r.URL.Query()
	if want := q.Get("index"); want != "" && want != tok.DefaultIndex {
		writeHECError(w, http.StatusForbidden, "Index does not match token index")
		return
	}
	events, perr := ingest.ParseRawStrict(body, tok.DefaultIndex, firstNonEmpty(q.Get("host"), hostFrom(r)), q.Get("source"), q.Get("sourcetype"))
	if perr != nil {
		writeHECError(w, http.StatusBadRequest, "Could not parse raw body")
		return
	}
	if !s.admitIngest(w, len(events), true) {
		return
	}
	n, err := s.Ingest.Write(r.Context(), events)
	if err != nil {
		writeHECError(w, http.StatusInternalServerError, "Could not store events")
		return
	}
	s.metrics.ingestEvents.Add(uint64(n)) // #nosec G115 -- n is a non-negative event count
	writeJSON(w, http.StatusOK, map[string]any{"text": "Success", "code": 0, "events": n})
}

func (s *Server) handleCollectorHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"text": "HEC is available and accepting input", "code": 17})
}

// handleJSONIngest accepts a simple JSON array of events, for scripts that do
// not speak HEC.
func (s *Server) handleJSONIngest(w http.ResponseWriter, r *http.Request) {
	tok, ok := s.authIngest(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxIngestBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read body")
		return
	}
	events, err := ingest.ParseHEC(body, tok.DefaultIndex, hostFrom(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not parse events")
		return
	}
	if err := enforceTokenIndex(events, tok); err != nil {
		s.Log.Warn("json ingest index rejected", "token", tok.Name, "err", err)
		writeError(w, http.StatusForbidden, "event index does not match token index")
		return
	}
	if !s.admitIngest(w, len(events), false) {
		return
	}
	n, err := s.Ingest.Write(r.Context(), events)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not store events")
		return
	}
	s.metrics.ingestEvents.Add(uint64(n)) // #nosec G115 -- n is a non-negative event count
	writeJSON(w, http.StatusOK, map[string]any{"events": n})
}

// admitIngest applies the global events per second limit. It writes a 429
// with Retry-After and returns false when the batch does not fit.
func (s *Server) admitIngest(w http.ResponseWriter, n int, hec bool) bool {
	ok, wait := s.ingestLimit.take(n)
	if ok {
		return true
	}
	s.metrics.ingestRejected.Add(uint64(n)) // #nosec G115 -- n is a non-negative event count
	secs := int(wait/time.Second) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	if hec {
		// HEC code 9 is "server is busy"; forwarders back off on it.
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"text": "Server is busy, ingest rate limit reached", "code": 9})
	} else {
		writeError(w, http.StatusTooManyRequests, "ingest rate limit reached")
	}
	return false
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
