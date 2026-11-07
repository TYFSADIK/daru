package api

import (
	"net/http"

	"github.com/TYFSADIK/daru/internal/store"
)

func (s *Server) handleListSaved(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListSavedSearches(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": list})
}

func (s *Server) handleCreateSaved(w http.ResponseWriter, r *http.Request) {
	var ss store.SavedSearch
	if err := readJSON(r, &ss, 256*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if ss.Name == "" || ss.Query == "" {
		writeError(w, http.StatusBadRequest, "name and query are required")
		return
	}
	ss.Owner = sessionFrom(r.Context()).Username
	if _, err := s.Store.SaveSearch(r.Context(), ss); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

func (s *Server) handleDeleteSaved(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.DeleteSavedSearch(r.Context(), r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleListDashboards(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListDashboards(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"dashboards": list})
}

func (s *Server) handleGetDashboard(w http.ResponseWriter, r *http.Request) {
	d, err := s.Store.GetDashboard(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if d == nil {
		writeError(w, http.StatusNotFound, "dashboard not found")
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) handleSaveDashboard(w http.ResponseWriter, r *http.Request) {
	var d store.Dashboard
	if err := readJSON(r, &d, 1024*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if d.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	d.Owner = sessionFrom(r.Context()).Username
	if _, err := s.Store.SaveDashboard(r.Context(), d); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

func (s *Server) handleDeleteDashboard(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.DeleteDashboard(r.Context(), r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleAlertHistory(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListAlertHistory(r.Context(), 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"history": list})
}

func (s *Server) handleListNotable(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	list, err := s.Store.ListNotable(r.Context(), status, 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"notable": list})
}

func (s *Server) handleNotableStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status string `json:"status"`
	}
	if err := readJSON(r, &req, 16*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	owner := sessionFrom(r.Context()).Username
	if err := s.Store.SetNotableStatus(r.Context(), r.PathValue("id"), req.Status, owner); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}
