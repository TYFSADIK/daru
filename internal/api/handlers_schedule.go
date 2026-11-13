package api

import (
	"context"
	"net/http"
	"time"

	"github.com/TYFSADIK/daru/internal/alerts"
	"github.com/TYFSADIK/daru/internal/recon"
	"github.com/TYFSADIK/daru/internal/store"
)

func (s *Server) handleListSchedules(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListScheduledScans(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schedules": list})
}

func (s *Server) handleCreateSchedule(w http.ResponseWriter, r *http.Request) {
	var sc store.ScheduledScan
	if err := readJSON(r, &sc, 16*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if _, ok := recon.Get(sc.Connector); !ok {
		writeError(w, http.StatusBadRequest, "unknown connector")
		return
	}
	if _, err := alerts.ParseCron(sc.Cron); err != nil {
		writeError(w, http.StatusBadRequest, "invalid cron expression: "+err.Error())
		return
	}
	// Validate target/gate up front so a bad schedule never silently fails.
	// The stored authorization reference is required for external targets;
	// there is no placeholder value. Local targets need no reference.
	if _, _, _, err := recon.Prepare(recon.Request{
		Connector: sc.Connector, Target: sc.Target, Profile: sc.Profile, Ports: sc.Ports,
		Confirmed: sc.AuthorizationRef != "", AuthorizationRef: sc.AuthorizationRef, AllowExternal: sc.AllowExternal,
		Scheduled: true, Source: "schedule",
	}); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sc.Enabled = true
	sc.CreatedBy = sessionFrom(r.Context()).Username
	existing, err := s.Store.ListScheduledScans(r.Context())
	if err != nil {
		s.Log.Warn("could not count scheduled scans", "err", err)
		writeError(w, http.StatusInternalServerError, "could not check schedule quota")
		return
	}
	owned := 0
	for _, e := range existing {
		if e.CreatedBy == sc.CreatedBy {
			owned++
		}
	}
	if err := s.quotas.checkSchedules(sc.CreatedBy, owned); err != nil {
		s.metrics.quotaRejected.Add(1)
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	id, err := s.Store.CreateScheduledScan(r.Context(), sc)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (s *Server) handleDeleteSchedule(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	if list, err := s.Store.ListScheduledScans(r.Context()); err == nil {
		for _, sc := range list {
			if sc.ID == r.PathValue("id") && sc.CreatedBy != "" && sc.CreatedBy != sess.Username && sess.Role != "admin" {
				writeError(w, http.StatusForbidden, "not your scheduled scan")
				return
			}
		}
	}
	if err := s.Store.DeleteScheduledScan(r.Context(), r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// RunScheduler ticks every minute and launches any scheduled scans whose cron
// expression matches the current minute. Call it in a goroutine at startup.
func (s *Server) RunScheduler(ctx context.Context) {
	s.initLimits()
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
			s.scheduleTick(ctx, minute)
			// Next tick is one minute after the minute just processed,
			// computed from the wall clock, so odd minutes are not skipped.
			timer.Reset(time.Until(minute.Add(time.Minute)))
		}
	}
}

func (s *Server) scheduleTick(ctx context.Context, minute time.Time) {
	scans, err := s.Store.EnabledScheduledScans(ctx)
	if err != nil {
		s.Log.Warn("could not load scheduled scans", "err", err)
		return
	}
	for _, sc := range scans {
		sched, err := alerts.ParseCron(sc.Cron)
		if err != nil || !sched.Matches(minute) {
			continue
		}
		req := recon.Request{
			Connector: sc.Connector, Target: sc.Target, Profile: sc.Profile, Ports: sc.Ports,
			Confirmed: sc.AuthorizationRef != "", AuthorizationRef: sc.AuthorizationRef, AllowExternal: sc.AllowExternal,
			Scheduled: true, Source: "schedule",
		}
		connector, args, target, err := recon.Prepare(req)
		if err != nil {
			s.Log.Warn("scheduled scan prepare failed", "schedule", sc.ID, "err", err)
			continue
		}
		req.Target = target
		if _, err := s.launchReconScan(connector, args, req, "scheduler:"+sc.CreatedBy); err != nil {
			s.Log.Warn("scheduled scan launch failed", "schedule", sc.ID, "err", err)
			continue
		}
		if err := s.Store.MarkScheduledScanRun(ctx, sc.ID); err != nil {
			s.Log.Warn("could not mark scheduled scan run", "schedule", sc.ID, "err", err)
		}
		s.Log.Info("scheduled scan launched", "connector", sc.Connector, "target", target, "cron", sc.Cron)
	}
}
