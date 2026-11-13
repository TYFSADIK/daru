package api

import (
	"context"
	_ "embed"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// updateToolsScript is the same script as scripts/update-tools.sh, embedded so
// the server can run it no matter where daru was launched from. Keep the two
// copies in sync.
//
//go:embed assets/update-tools.sh
var updateToolsScript []byte

// handleSystemInfo reports runtime facts the UI shows, notably whether Daru is
// running as root (which determines whether raw-socket scans work without the
// per-tool capability grant).
func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	writeJSON(w, http.StatusOK, map[string]any{
		"running_as_root": os.Geteuid() == 0,
		"uid":             os.Geteuid(),
		"pid":             os.Getpid(),
		"hostname":        host,
	})
}

// handleUpdateTools runs the embedded tool-update script and returns its
// combined output. Admin only, and gated three ways: the server must be
// started with DARU_ALLOW_TOOL_UPDATE=true, the request must carry the
// re-confirmation header X-Daru-Confirm: update-tools, and the server must
// not be running as root unless DARU_ALLOW_ROOT_UPDATE=1 is explicitly set.
// It can take several minutes (go builds, apt), so it runs with a generous
// timeout and the UI waits with a spinner. Only the output hash is written
// to the audit log, never the output itself.
func (s *Server) handleUpdateTools(w http.ResponseWriter, r *http.Request) {
	username := sessionFrom(r.Context()).Username
	if os.Getenv("DARU_ALLOW_TOOL_UPDATE") != "true" {
		s.audit(r, "tools.update_blocked", username, "reason", "disabled")
		writeError(w, http.StatusForbidden, "tool updates are disabled on this server")
		return
	}
	if r.Header.Get("X-Daru-Confirm") != "update-tools" {
		s.audit(r, "tools.update_blocked", username, "reason", "confirmation missing")
		writeError(w, http.StatusForbidden, "tool update requires X-Daru-Confirm: update-tools")
		return
	}
	if os.Geteuid() == 0 && os.Getenv("DARU_ALLOW_ROOT_UPDATE") != "1" {
		s.audit(r, "tools.update_blocked", username, "reason", "running as root")
		writeError(w, http.StatusForbidden, "refusing to run tool updates as root")
		return
	}
	s.audit(r, "tools.update_start", username)
	f, err := os.CreateTemp("", "daru-update-*.sh")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not stage update script")
		return
	}
	path := f.Name()
	defer func() { _ = os.Remove(path) }()
	if _, err := f.Write(updateToolsScript); err != nil {
		_ = f.Close()
		writeError(w, http.StatusInternalServerError, "could not write update script")
		return
	}
	if err := f.Close(); err != nil { // a failed flush would run a partial script
		writeError(w, http.StatusInternalServerError, "could not write update script")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", path) // #nosec G204 -- path is a CreateTemp file holding the embedded update script
	out, runErr := cmd.CombinedOutput()
	if len(out) > 512<<10 {
		out = out[len(out)-(512<<10):]
	}
	resp := map[string]any{"output": string(out), "ok": runErr == nil}
	if ctx.Err() == context.DeadlineExceeded {
		resp["ok"] = false
		resp["error"] = "tool update timed out after 30 minutes"
	} else if runErr != nil {
		resp["error"] = "tool update failed"
	}
	s.audit(r, "tools.update_finish", username, "ok", resp["ok"], "output_sha256", auditHash(out))
	writeJSON(w, http.StatusOK, resp)
}
