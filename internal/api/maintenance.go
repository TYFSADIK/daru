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
// combined output. Admin only. It can take several minutes (go builds, apt),
// so it runs with a generous timeout and the UI waits with a spinner.
func (s *Server) handleUpdateTools(w http.ResponseWriter, r *http.Request) {
	f, err := os.CreateTemp("", "daru-update-*.sh")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not stage update script")
		return
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err := f.Write(updateToolsScript); err != nil {
		f.Close()
		writeError(w, http.StatusInternalServerError, "could not write update script")
		return
	}
	f.Close()

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", path)
	out, runErr := cmd.CombinedOutput()
	if len(out) > 512<<10 {
		out = out[len(out)-(512<<10):]
	}
	resp := map[string]any{"output": string(out), "ok": runErr == nil}
	if ctx.Err() == context.DeadlineExceeded {
		resp["ok"] = false
		resp["error"] = "tool update timed out after 30 minutes"
	} else if runErr != nil {
		resp["error"] = runErr.Error()
	}
	s.Log.Info("tool update requested", "ok", resp["ok"])
	writeJSON(w, http.StatusOK, resp)
}
