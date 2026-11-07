package api

import (
	"net/http"
	"time"

	"github.com/TYFSADIK/daru/internal/query"
	"github.com/TYFSADIK/daru/internal/search"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	code := http.StatusOK
	if err := s.Store.Ping(r.Context()); err != nil {
		status, code = "degraded", http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{"status": status, "time": time.Now().UTC()})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	user, token, err := s.Auth.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((12 * time.Hour).Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.Auth.Logout(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"username": sess.Username,
		"role":     sess.Role,
	})
}

func (s *Server) handleCommands(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"commands": query.Commands()})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query    string   `json:"query"`
		Earliest string   `json:"earliest"`
		Latest   string   `json:"latest"`
		MaxRows  int      `json:"max_rows"`
		Indexes  []string `json:"indexes"`
	}
	if err := readJSON(r, &req, 1024*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Query == "" {
		writeError(w, http.StatusBadRequest, "query is required")
		return
	}

	indexes, err := s.allowedIndexes(r, req.Indexes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp, err := s.Search.Run(r.Context(), search.Request{
		Query:    req.Query,
		Earliest: req.Earliest,
		Latest:   req.Latest,
		Indexes:  indexes,
		MaxRows:  req.MaxRows,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// allowedIndexes resolves which indexes a search may read. Every authenticated
// user may read every index for now; the requested subset narrows it.
func (s *Server) allowedIndexes(r *http.Request, requested []string) ([]string, error) {
	all, err := s.Store.ListIndexes(r.Context())
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	var names []string
	for _, ix := range all {
		have[ix.Name] = true
		names = append(names, ix.Name)
	}
	if len(requested) == 0 {
		return names, nil
	}
	var out []string
	for _, want := range requested {
		if have[want] {
			out = append(out, want)
		}
	}
	return out, nil
}

func (s *Server) handleListIndexes(w http.ResponseWriter, r *http.Request) {
	indexes, err := s.Store.ListIndexes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"indexes": indexes})
}
