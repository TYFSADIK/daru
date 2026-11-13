package api

import (
	"context"
	"net/http"

	"github.com/TYFSADIK/daru/internal/auth"
)

// sessionCtx attaches where a sign in came from, for the sessions list.
func (s *Server) sessionCtx(r *http.Request, method string) context.Context {
	return auth.WithSessionMeta(r.Context(), auth.SessionMeta{IP: clientIP(r), UserAgent: r.UserAgent(), Method: method})
}

func (s *Server) handleListMySessions(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	list, err := s.Auth.ListSessions(r.Context(), sess.Username, sess.Token)
	if err != nil {
		s.Log.Warn("could not list sessions", "err", err)
		writeError(w, http.StatusInternalServerError, "could not list sessions")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": list})
}

// handleRevokeMySession signs out one of the caller's own sessions.
func (s *Server) handleRevokeMySession(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	id := r.PathValue("id")
	if err := s.Auth.RevokeSession(r.Context(), sess.Username, id); err != nil {
		writeError(w, http.StatusBadRequest, "could not revoke session")
		return
	}
	s.audit(r, "session.revoke", sess.Username, "session", id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// handleRevokeOtherSessions signs out everywhere except this session.
func (s *Server) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	if err := s.Auth.RevokeOthers(r.Context(), sess.Username, sess.Token); err != nil {
		s.Log.Warn("could not revoke sessions", "err", err)
		writeError(w, http.StatusInternalServerError, "could not revoke sessions")
		return
	}
	s.audit(r, "session.revoke_others", sess.Username)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleListUserSessions(w http.ResponseWriter, r *http.Request) {
	list, err := s.Auth.ListSessions(r.Context(), r.PathValue("username"), "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list sessions")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": list})
}

// handleRevokeUserSessions signs a user out everywhere, for example when a
// laptop is lost or an account may be compromised.
func (s *Server) handleRevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	target := r.PathValue("username")
	if err := s.Auth.RevokeAll(r.Context(), target); err != nil {
		writeError(w, http.StatusInternalServerError, "could not revoke sessions")
		return
	}
	s.audit(r, "session.revoke_all_admin", sessionFrom(r.Context()).Username, "target", target)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
