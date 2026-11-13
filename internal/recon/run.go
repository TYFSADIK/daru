package recon

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Result is the outcome of a completed scan.
type Result struct {
	Connector string
	Target    string
	Profile   string
	Command   string
	ExitCode  int
	Findings  []Finding
	RawOutput string
	Started   time.Time
	Finished  time.Time
	Err       string
}

// MaxOutputBytes caps captured tool output.
const MaxOutputBytes = 16 << 20

// ErrBusy is returned when the recon semaphore is full; handlers map it to 429.
var ErrBusy = fmt.Errorf("recon busy: too many scans running, try again shortly")

// ValidateScheduled validates a request created by the scheduler. Scheduled
// scans never get the "scheduled" placeholder as an authorization reference:
// an external scheduled scan needs a real, non-empty reference, a
// confirmation, and allow_external. Local scheduled scans need no reference.
func ValidateScheduled(r Request) error {
	c, ok := Get(r.Connector)
	if !ok {
		return fmt.Errorf("unknown connector %q", r.Connector)
	}
	if ScanIsLocal(c, r) {
		return nil
	}
	if !r.Confirmed {
		return fmt.Errorf("scheduled external scan: confirmation is required")
	}
	ref := strings.TrimSpace(r.AuthorizationRef)
	if ref == "" || strings.EqualFold(ref, "scheduled") {
		return fmt.Errorf("scheduled external scan: a real authorization reference is required, not %q", r.AuthorizationRef)
	}
	if len(ref) < 3 {
		return fmt.Errorf("scheduled external scan: authorization reference is too short")
	}
	if !r.AllowExternal {
		return fmt.Errorf("scheduled external scan: allow_external is required")
	}
	return nil
}

// Prepare validates a request and returns the connector and final arguments,
// enforcing the authorization gate and scope guard. It does not run anything.
func Prepare(r Request) (*Connector, []string, string, error) {
	c, ok := Get(r.Connector)
	if !ok {
		return nil, nil, "", fmt.Errorf("unknown connector %q", r.Connector)
	}
	// Authorization gate, before anything about tooling. Scanning your own
	// local network, loopback, or private ranges is friction-free. External
	// targets (public IPs, domains, or allow_external) still require an
	// explicit confirmation and an authorization reference.
	if r.Scheduled {
		if err := ValidateScheduled(r); err != nil {
			return nil, nil, "", err
		}
	} else if !ScanIsLocal(c, r) {
		if !r.Confirmed {
			return nil, nil, "", fmt.Errorf("external target: confirm you are authorized to test it")
		}
		if len(r.AuthorizationRef) < 3 {
			return nil, nil, "", fmt.Errorf("external target: an authorization reference is required (ticket, ROE, or engagement id)")
		}
		if len(ExternalAllowlist) > 0 && !externalAllowed(r.Target) {
			return nil, nil, "", fmt.Errorf("external target %q is not on the server allowlist", r.Target)
		}
	}
	if !c.Available() {
		return nil, nil, "", fmt.Errorf("%s is not installed (missing binary %q)", c.Name, c.Binary)
	}
	if c.IsNative() {
		// Native connectors build no command-line arguments, but still pass
		// scope validation below.
		if c.AllowEmptyTarget && strings.TrimSpace(r.Target) == "" {
			return c, nil, "", nil
		}
		target, err := ValidateTarget(c, r)
		if err != nil {
			return nil, nil, "", err
		}
		return c, nil, target, nil
	}
	target, err := ValidateTarget(c, r)
	if err != nil {
		return nil, nil, "", err
	}
	r.Target = target
	args, err := c.runArgs(r)
	if err != nil {
		return nil, nil, "", err
	}
	return c, args, target, nil
}

// Execute runs a prepared scan, dispatching to the native collector or the
// external binary as appropriate.
func Execute(ctx context.Context, c *Connector, args []string, r Request, timeout time.Duration) *Result {
	if c.IsNative() {
		return runNative(ctx, c, r, timeout)
	}
	return Run(ctx, c, args, r, timeout)
}

func runNative(ctx context.Context, c *Connector, r Request, timeout time.Duration) *Result {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res := &Result{
		Connector: c.Name, Target: r.Target, Profile: profileOr(c, r.Profile),
		Command: c.Name + " (native) " + r.Target, Started: time.Now().UTC(),
	}
	if _, err := ValidateTarget(c, r); err != nil && strings.TrimSpace(r.Target) != "" {
		res.Finished = time.Now().UTC()
		res.Err = "scope re-check failed before exec: " + err.Error()
		return res
	}
	findings, err := c.native(runCtx, r)
	res.Finished = time.Now().UTC()
	res.Findings = applyMitre(c.Name, capFindings(findings, r.Target))
	if err != nil {
		res.Err = err.Error()
	}
	return res
}

// recheckTarget re-validates the target immediately before exec and, for
// host targets, pins the scan to the IP address that was just checked. This
// closes the DNS rebinding gap: a name that resolved to a private address
// at Prepare time cannot be re-resolved to a public address at tool time.
// URL and domain targets are re-validated but not rewritten, since the tool
// needs the hostname for TLS and HTTP Host handling.
func recheckTarget(c *Connector, r Request) (Request, error) {
	if c.TargetKind == TgtHost || c.TargetKind == TgtCIDR {
		t := strings.TrimSpace(r.Target)
		if strings.Contains(t, "/") {
			if _, err := ValidateTarget(c, r); err != nil {
				return r, err
			}
			return r, nil
		}
		if net.ParseIP(t) == nil {
			ip, err := resolveHostIP(t, r.AllowExternal)
			if err != nil {
				return r, err
			}
			r.Target = ip
		}
		return r, nil
	}
	if _, err := ValidateTarget(c, r); err != nil {
		return r, err
	}
	return r, nil
}

// Run executes a prepared scan. The caller passes the connector and args from
// Prepare so the gate cannot be bypassed.
func Run(ctx context.Context, c *Connector, args []string, r Request, timeout time.Duration) *Result {
	if timeout <= 0 {
		timeout = 20 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res := &Result{
		Connector: c.Name, Target: r.Target, Profile: profileOr(c, r.Profile),
		Command: c.Binary + " " + shellQuote(args), Started: time.Now().UTC(),
	}

	// Re-check the scope guard immediately before exec, and pin host targets
	// to the resolved IP. A failed re-check aborts the scan.
	if pinned, err := recheckTarget(c, r); err != nil {
		res.Finished = time.Now().UTC()
		res.Err = "scope re-check failed before exec: " + err.Error()
		return res
	} else if pinned.Target != r.Target {
		r = pinned
		// Rebuild args against the pinned IP so the tool scans the checked
		// address, not a name it would resolve again itself.
		if rebuilt, err := c.runArgs(r); err == nil {
			args = rebuilt
			res.Command = c.Binary + " " + shellQuote(args)
		}
	}

	bin := c.resolve()
	if bin == "" {
		res.Finished = time.Now().UTC()
		res.Err = "connector binary could not be resolved (refusing bare-name fallback)"
		return res
	}
	cmd := exec.CommandContext(runCtx, bin, args...) // #nosec G204 -- recon tools run as an argv list (no shell) from a vetted binary path
	cmd.Env = append(os.Environ(), "PATH="+execPATH())
	// Run each external tool in a disposable working directory so scanners that
	// drop artifacts in cwd (e.g. fierce's "<domain>_ips.txt") don't litter
	// daru's install directory.
	if dir, err := os.MkdirTemp("", "daru-scan-"); err == nil {
		cmd.Dir = dir
		defer os.RemoveAll(dir)
	}
	if c.stdinTarget && r.Target != "" {
		cmd.Stdin = strings.NewReader(r.Target + "\n")
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = capWriter(&stdout, MaxOutputBytes)
	cmd.Stderr = capWriter(&stderr, 256<<10)
	err := cmd.Run()
	res.Finished = time.Now().UTC()

	if runCtx.Err() == context.DeadlineExceeded {
		res.Err = "scan timed out"
	} else if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
			// Many scanners exit non-zero when they find things; keep the output.
		} else {
			res.Err = err.Error()
		}
	}
	out := stdout.Bytes()
	res.RawOutput = string(out)
	if res.Err == "" || len(out) > 0 {
		res.Findings = c.runParse(out, r)
	}
	if len(res.Findings) == 0 && res.Err == "" && stderr.Len() > 0 {
		res.Err = truncate(stderr.String(), 2000)
	}
	return res
}

// cappedWriter stops writing after n bytes to bound memory.
type cappedWriter struct {
	buf *bytes.Buffer
	n   int
}

func capWriter(buf *bytes.Buffer, n int) *cappedWriter { return &cappedWriter{buf: buf, n: n} }

func (w *cappedWriter) Write(p []byte) (int, error) {
	if w.buf.Len() >= w.n {
		return len(p), nil
	}
	room := w.n - w.buf.Len()
	if room < len(p) {
		w.buf.Write(p[:room])
		return len(p), nil
	}
	return w.buf.Write(p)
}

// CommandString renders args for display and storage.
func CommandString(args []string) string { return shellQuote(args) }

func shellQuote(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		if a == "" || containsSpace(a) || strings.Contains(a, "'") {
			out += "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		} else {
			out += a
		}
	}
	return out
}

func containsSpace(s string) bool {
	for _, r := range s {
		if r == ' ' || r == '\t' {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
