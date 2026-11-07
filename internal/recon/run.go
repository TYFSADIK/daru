package recon

import (
	"bytes"
	"context"
	"fmt"
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
	if !ScanIsLocal(c, r) {
		if !r.Confirmed {
			return nil, nil, "", fmt.Errorf("external target: confirm you are authorized to test it")
		}
		if len(r.AuthorizationRef) < 3 {
			return nil, nil, "", fmt.Errorf("external target: an authorization reference is required (ticket, ROE, or engagement id)")
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
	findings, err := c.native(runCtx, r)
	res.Finished = time.Now().UTC()
	res.Findings = findings
	if err != nil {
		res.Err = err.Error()
	}
	return res
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

	bin := resolveBinary(c.Binary)
	if bin == "" {
		bin = c.Binary
	}
	cmd := exec.CommandContext(runCtx, bin, args...)
	cmd.Env = append(os.Environ(), "PATH="+execPATH())
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
		if a == "" || containsSpace(a) {
			out += "'" + a + "'"
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
