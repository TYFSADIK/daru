package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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

	scanID, err := s.launchReconScan(connector, args, req, user)
	if err != nil {
		if err == recon.ErrBusy || errors.Is(err, ErrQuota) {
			writeError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scan_id": scanID, "status": "running"})
}

// acquireReconSem waits briefly for a scan slot instead of blocking the
// HTTP handler indefinitely. A full semaphore returns recon.ErrBusy, which
// callers map to HTTP 429.
func (s *Server) acquireReconSem() error {
	select {
	case s.reconSem <- struct{}{}:
		return nil
	case <-time.After(10 * time.Second):
		return recon.ErrBusy
	}
}

// findingFields copies a recon finding's fields and adds its MITRE mapping,
// so the tactic and technique survive into the stored finding.
func findingFields(f recon.Finding) map[string]string {
	fields := map[string]string{}
	for k, v := range f.Fields {
		fields[k] = v
	}
	if f.MitreTactic != "" {
		fields["mitre_tactic"] = f.MitreTactic
	}
	if f.MitreTechnique != "" {
		fields["mitre_technique"] = f.MitreTechnique
	}
	return fields
}

// launchReconScan creates a scan record and runs it in a bounded background
// goroutine, storing findings and updating inventory. Shared by the HTTP
// handler and the scheduled-scan runner.
func (s *Server) launchReconScan(connector *recon.Connector, args []string, req recon.Request, user string) (string, error) {
	s.initLimits()
	// Quota and slot come first, so a refused scan never leaves a
	// "running" scan record behind.
	release, err := s.quotas.acquireScan(user)
	if err != nil {
		s.metrics.quotaRejected.Add(1)
		return "", err
	}
	if err := s.acquireReconSem(); err != nil {
		release()
		return "", err
	}
	scanID, err := s.Store.CreateScan(context.Background(), store.ScanRecord{
		Connector: connector.Name, Target: req.Target, Profile: req.Profile,
		AuthorizationRef: req.AuthorizationRef, CreatedBy: user,
		Command: connector.Binary + " " + recon.CommandString(args),
	})
	if err != nil {
		<-s.reconSem
		release()
		return "", err
	}
	s.metrics.scansStarted.Add(1)
	go func() {
		defer func() { <-s.reconSem; release() }()
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
		defer cancel()
		res := recon.Execute(ctx, connector, args, req, 20*time.Minute)
		findings := make([]store.ScanFinding, 0, len(res.Findings))
		for _, f := range res.Findings {
			findings = append(findings, store.ScanFinding{
				ScanID: scanID, Title: f.Title, Severity: f.Severity, Target: f.Target,
				Port: f.Port, Service: f.Service, Detail: f.Detail, Fields: findingFields(f),
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
		s.Log.Info("scan finished", "connector", connector.Name, "target", req.Target,
			"findings", len(findings), "status", status)
	}()
	return scanID, nil
}

func (s *Server) handleReconNetworks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"networks": recon.LocalNetworks()})
}

// handleReconPcap accepts an uploaded capture file, analyzes it with the
// tshark rich decoder, stores the findings as a scan, and returns the scan id.
// The file is saved server-side with a generated name (no client-supplied
// path), size-bounded, and deleted after analysis.
func (s *Server) handleReconPcap(w http.ResponseWriter, r *http.Request) {
	const maxPcap = 200 << 20 // 200 MB
	r.Body = http.MaxBytesReader(w, r.Body, maxPcap+1<<20)
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "upload too large or malformed")
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "no file uploaded (field 'file')")
		return
	}
	defer file.Close()
	// Uploads go in a random MkdirTemp subdirectory of the allowlisted
	// pcap directory, never a predictable path. The base directory is
	// checked first: a pre-planted symlink in /tmp must not redirect it.
	base := filepath.Join(os.TempDir(), "daru-pcap")
	if fi, err := os.Lstat(base); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			writeError(w, http.StatusInternalServerError, "pcap upload directory is a symlink; refusing upload")
			return
		}
		if !fi.IsDir() {
			writeError(w, http.StatusInternalServerError, "pcap upload path is not a directory")
			return
		}
	} else if err := os.MkdirAll(base, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	dir, err := os.MkdirTemp(base, "cap-")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer os.RemoveAll(dir)
	tmp, err := os.CreateTemp(dir, "cap-*.pcap")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	path := tmp.Name()
	n, err := io.Copy(tmp, io.LimitReader(file, maxPcap+1))
	tmp.Close()
	if err != nil {
		os.Remove(path)
		writeError(w, http.StatusInternalServerError, "could not save upload")
		return
	}
	if n > maxPcap {
		os.Remove(path)
		writeError(w, http.StatusRequestEntityTooLarge, "capture file is over 200 MB")
		return
	}

	req := recon.Request{Connector: "tshark-pcap", Target: path, Profile: "summary"}
	connector, args, target, err := recon.Prepare(req)
	if err != nil {
		os.Remove(path)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Target = target
	user := sessionFrom(r.Context()).Username
	label := hdr.Filename
	release, err := s.quotas.acquireScan(user)
	if err != nil {
		os.Remove(path)
		s.metrics.quotaRejected.Add(1)
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	if err := s.acquireReconSem(); err != nil {
		os.Remove(path)
		release()
		if err == recon.ErrBusy {
			writeError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	scanID, err := s.Store.CreateScan(r.Context(), store.ScanRecord{
		Connector: "tshark-pcap", Target: label, Profile: "summary", CreatedBy: user,
		Command: fmt.Sprintf("tshark -r %s (%d bytes)", label, n),
	})
	if err != nil {
		<-s.reconSem
		release()
		os.Remove(path)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.metrics.scansStarted.Add(1)
	go func() {
		defer func() { <-s.reconSem; release(); os.Remove(path) }()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		res := recon.Execute(ctx, connector, args, req, 8*time.Minute)
		findings := make([]store.ScanFinding, 0, len(res.Findings))
		for _, f := range res.Findings {
			findings = append(findings, store.ScanFinding{
				ScanID: scanID, Title: f.Title, Severity: f.Severity, Target: f.Target,
				Port: f.Port, Service: f.Service, Detail: f.Detail, Fields: findingFields(f),
			})
		}
		s.Store.InsertFindings(ctx, "tshark-pcap", findings)
		status := "completed"
		if res.Err != "" && len(findings) == 0 {
			status = "failed"
		}
		s.Store.CompleteScan(ctx, scanID, status, len(findings), res.Err)
		s.Log.Info("pcap analyzed", "file", label, "packets", len(findings))
	}()
	writeJSON(w, http.StatusOK, map[string]any{"scan_id": scanID, "status": "running", "file": label})
}

// handleReconOverview returns the aggregate recon posture for the dashboard.
func (s *Server) handleReconOverview(w http.ResponseWriter, r *http.Request) {
	ov, err := s.Store.ReconOverview(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ov)
}

// handleDevice returns everything Daru knows about one host: its inventory
// record plus every finding from every tool that targeted it.
func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if ip == "" {
		writeError(w, http.StatusBadRequest, "ip required")
		return
	}
	asset, _ := s.Store.GetAsset(r.Context(), ip)
	findings, err := s.Store.FindingsByTarget(r.Context(), ip, 2000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"asset": asset, "findings": findings})
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
