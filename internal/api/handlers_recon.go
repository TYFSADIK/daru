package api

import (
	"context"
	"net/http"
	"time"

	"github.com/TYFSADIK/daru/internal/recon"
	"github.com/TYFSADIK/daru/internal/store"
)

func (s *Server) handleReconConnectors(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"connectors": recon.List()})
}

func (s *Server) handleReconScan(w http.ResponseWriter, r *http.Request) {
	var req recon.Request
	if err := readJSON(r, &req, 64*1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	// Validate and enforce the authorization gate before anything runs.
	connector, args, target, err := recon.Prepare(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	user := sessionFrom(r.Context()).Username
	req.Target = target

	scanID, err := s.Store.CreateScan(r.Context(), store.ScanRecord{
		Connector: connector.Name, Target: target, Profile: req.Profile,
		AuthorizationRef: req.AuthorizationRef, CreatedBy: user,
		Command: connector.Binary + " " + recon.CommandString(args),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Run in the background so the UI can poll. A semaphore bounds concurrency.
	s.reconSem <- struct{}{}
	go func() {
		defer func() { <-s.reconSem }()
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
		defer cancel()
		res := recon.Execute(ctx, connector, args, req, 20*time.Minute)
		findings := make([]store.ScanFinding, 0, len(res.Findings))
		for _, f := range res.Findings {
			findings = append(findings, store.ScanFinding{
				ScanID: scanID, Title: f.Title, Severity: f.Severity, Target: f.Target,
				Port: f.Port, Service: f.Service, Detail: f.Detail, Fields: f.Fields,
			})
		}
		if err := s.Store.InsertFindings(ctx, connector.Name, findings); err != nil {
			s.Log.Warn("could not store findings", "scan", scanID, "err", err)
		}
		if err := s.Store.UpsertAssetsFromFindings(ctx, connector.Name, findings); err != nil {
			s.Log.Warn("could not update asset inventory", "scan", scanID, "err", err)
		}
		status := "completed"
		if res.Err != "" && len(findings) == 0 {
			status = "failed"
		}
		if err := s.Store.CompleteScan(ctx, scanID, status, len(findings), res.Err); err != nil {
			s.Log.Warn("could not complete scan", "scan", scanID, "err", err)
		}
		s.Log.Info("scan finished", "connector", connector.Name, "target", target,
			"findings", len(findings), "status", status)
	}()

	writeJSON(w, http.StatusOK, map[string]any{"scan_id": scanID, "status": "running"})
}

func (s *Server) handleReconNetworks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"networks": recon.LocalNetworks()})
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	assets, err := s.Store.ListAssets(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"assets": assets})
}

func (s *Server) handleReconScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.Store.ListScans(r.Context(), 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": scans})
}

func (s *Server) handleReconFindings(w http.ResponseWriter, r *http.Request) {
	findings, err := s.Store.ScanFindings(r.Context(), r.PathValue("id"), 2000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": findings})
}
