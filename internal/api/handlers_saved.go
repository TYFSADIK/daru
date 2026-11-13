package api

import (
	"net/http"

	"github.com/TYFSADIK/daru/internal/alerts"
	"github.com/TYFSADIK/daru/internal/query"
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
	// Validate the query and, for alerts, the schedule, condition, and
	// actions now, so a bad alert does not fail silently every minute.
	if _, err := query.Parse(ss.Query); err != nil {
		writeError(w, http.StatusBadRequest, "invalid query: "+err.Error())
		return
	}
	if ss.IsAlert {
		if _, err := alerts.ParseCron(ss.Cron); err != nil {
			writeError(w, http.StatusBadRequest, "invalid cron expression: "+err.Error())
			return
		}
		if err := alerts.ValidateCondition(ss.Condition); err != nil {
			writeError(w, http.StatusBadRequest, "invalid alert condition: "+err.Error())
			return
		}
		if err := alerts.ValidateActions(ss.Actions); err != nil {
			writeError(w, http.StatusBadRequest, "invalid alert actions: "+err.Error())
			return
		}
		if ss.MitreTactic != "" && !alerts.ValidMitreID(ss.MitreTactic, "TA") {
			writeError(w, http.StatusBadRequest, "invalid mitre_tactic, expected TA0000")
			return
		}
		if ss.MitreTechnique != "" && !alerts.ValidMitreID(ss.MitreTechnique, "T") {
			writeError(w, http.StatusBadRequest, "invalid mitre_technique, expected T0000 or T0000.000")
			return
		}
	}
	sess := sessionFrom(r.Context())
	if ss.ID != "" {
		if existing, err := s.Store.GetSavedSearch(r.Context(), ss.ID); err == nil && existing != nil {
			if existing.Owner != sess.Username && sess.Role != "admin" {
				writeError(w, http.StatusForbidden, "not your saved search")
				return
			}
		} else {
			ss.ID = ""
		}
	}
	ss.Owner = sess.Username
	id, err := s.Store.SaveSearch(r.Context(), ss)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved", "id": id})
}

func (s *Server) handleDeleteSaved(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	if existing, err := s.Store.GetSavedSearch(r.Context(), r.PathValue("id")); err == nil && existing != nil {
		if existing.Owner != sess.Username && sess.Role != "admin" {
			writeError(w, http.StatusForbidden, "not your saved search")
			return
		}
	}
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
	sess := sessionFrom(r.Context())
	if d.ID != "" {
		if existing, err := s.Store.GetDashboard(r.Context(), d.ID); err == nil && existing != nil {
			if existing.Owner != sess.Username && sess.Role != "admin" {
				writeError(w, http.StatusForbidden, "not your dashboard")
				return
			}
		} else {
			d.ID = ""
		}
	}
	d.Owner = sess.Username
	id, err := s.Store.SaveDashboard(r.Context(), d)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved", "id": id})
}

func (s *Server) handleDeleteDashboard(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	if existing, err := s.Store.GetDashboard(r.Context(), r.PathValue("id")); err == nil && existing != nil {
		if existing.Owner != sess.Username && sess.Role != "admin" {
			writeError(w, http.StatusForbidden, "not your dashboard")
			return
		}
	}
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
