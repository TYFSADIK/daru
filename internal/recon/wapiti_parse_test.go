package recon

import (
	"strings"
	"testing"
)

func TestParseWapitiIgnoresBanner(t *testing.T) {
	// banner + logs around a real wapiti JSON report
	out := []byte(`     __  __
    / / / /  wapiti 3.x
[*] Launching module sql
{"vulnerabilities":{"SQL Injection":[{"method":"GET","path":"/?user=1","info":"SQLi via user","level":3,"parameter":"user"}],"Cross Site Scripting":[]},"classifications":{},"infos":{}}
[*] Scan done.
`)
	f := parseWapiti(out, Request{Target: "http://x/"})
	if len(f) != 1 {
		t.Fatalf("want 1 vuln finding, got %d (banner leaked?)", len(f))
	}
	if !strings.Contains(f[0].Title, "SQL Injection") || f[0].Severity != "high" {
		t.Errorf("unexpected finding: %+v", f[0])
	}
}
func TestParseWapitiNoReport(t *testing.T) {
	f := parseWapiti([]byte("just a banner\nno json here\n"), Request{Target: "http://x/"})
	if len(f) != 1 || !strings.Contains(f[0].Title, "no parseable report") {
		t.Fatalf("expected clean no-report message, got %+v", f)
	}
}
