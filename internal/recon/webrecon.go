package recon

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// web-recon ("god mode" for a web target): one action that fuses several web
// tools, HTTP probe + tech fingerprint, technology fingerprint, and content
// discovery (plus template-based vulnerability scanning on the full profile) ,
// into a single aggregated result. It runs each tool the operator already has
// installed and skips the rest, flowing through the same authorization gate,
// scope guard, history, and dashboards as every other scan.
func init() {
	register(&Connector{
		Name: "web-recon", Binary: "", Category: CatWebScan, TargetKind: TgtURL,
		Desc: "God-mode web assessment: fuses HTTP probe, tech fingerprint, and content discovery (plus nuclei on 'full') for a URL.",
		Profiles: []Profile{
			{"fast", "httpx + whatweb + gobuster"},
			{"full", "fast + nuclei template scan"},
		},
		native: webRecon,
	})
}

func webRecon(ctx context.Context, r Request) ([]Finding, error) {
	target := strings.TrimSpace(r.Target)
	if target == "" {
		return nil, fmt.Errorf("a URL target is required")
	}
	full := r.Profile == "full"

	// The sub-tools to run, in order. Each is skipped if not installed.
	steps := []struct {
		conn    string
		profile string
		label   string
	}{
		{"httpx", "probe", "HTTP probe"},
		{"whatweb", "default", "tech fingerprint"},
		{"gobuster", "dir", "content discovery"},
	}
	if full {
		steps = append(steps, struct {
			conn    string
			profile string
			label   string
		}{"nuclei", "default", "vulnerability templates"})
	}

	var findings []Finding
	ran := 0
	for _, st := range steps {
		c, ok := Get(st.conn)
		if !ok || !c.Available() {
			continue
		}
		select {
		case <-ctx.Done():
			return findings, nil
		default:
		}
		req := Request{Connector: st.conn, Target: target, Profile: st.profile, Confirmed: r.Confirmed, AuthorizationRef: r.AuthorizationRef, AllowExternal: r.AllowExternal}
		args, err := c.build(c, req)
		if err != nil {
			// e.g. gobuster with no wordlist; record and continue.
			findings = append(findings, Finding{
				Title: st.label + " skipped: " + err.Error(), Severity: "info", Target: target, Service: "web",
			})
			continue
		}
		timeout := 4 * time.Minute
		if st.conn == "nuclei" {
			timeout = 8 * time.Minute
		}
		hctx, cancel := context.WithTimeout(ctx, timeout)
		res := Run(hctx, c, args, req, timeout)
		cancel()
		// Prefix each sub-finding's service so the dashboard shows which tool
		// produced it, and merge.
		for _, f := range res.Findings {
			if f.Fields == nil {
				f.Fields = map[string]string{}
			}
			f.Fields["source_tool"] = st.conn
			findings = append(findings, f)
		}
		ran++
	}
	if ran == 0 {
		return nil, fmt.Errorf("no web tools installed (need httpx, whatweb, or gobuster)")
	}
	if len(findings) == 0 {
		findings = append(findings, Finding{Title: "web-recon completed; no notable findings", Severity: "info", Target: target, Service: "web"})
	}
	return findings, nil
}
