package recon

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// C6: BPF must never be splittable into tcpdump options.
func TestValidBPFRejectsOptions(t *testing.T) {
	for _, s := range []string{"-w /tmp/x.pcap", "-r /tmp/victim.pcap", "tcp and -F foo", "host -z", "port 443 -w out"} {
		if validBPF(s) {
			t.Errorf("validBPF should reject %q", s)
		}
	}
	for _, s := range []string{"tcp port 443", "host 192.168.1.1 and udp", "not arp", "port 53 or port 5353"} {
		if !validBPF(s) {
			t.Errorf("validBPF should accept %q", s)
		}
	}
}

// M2: explicit RFC1918 only, no CGNAT or benchmarking space.
func TestIsPrivateIPExplicit(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true}, {"172.16.0.1", true}, {"172.31.255.255", true},
		{"192.168.1.1", true}, {"127.0.0.1", true}, {"169.254.1.1", true},
		{"100.64.0.1", false}, {"198.18.0.1", false}, {"172.32.0.1", false},
		{"8.8.8.8", false}, {"0.0.0.0", false}, {"192.0.0.1", false},
	}
	for _, c := range cases {
		if got := isPrivateIP(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("isPrivateIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

// C7/M6: unresolvable hosts fail closed, CIDR capped at /16.
func TestGuardFailsClosedAndCIDRCap(t *testing.T) {
	if _, err := guardResolvedHost("nonexistent.invalid", false); err == nil {
		t.Error("unresolvable host should fail closed")
	}
	nmap := Registry["nmap"]
	if _, err := ValidateTarget(nmap, Request{Target: "10.0.0.0/8"}); err == nil {
		t.Error("/8 CIDR should be rejected")
	}
	if _, err := ValidateTarget(nmap, Request{Target: "192.168.0.0/15"}); err == nil {
		t.Error("/15 CIDR should be rejected (cap is /16)")
	}
	if _, err := ValidateTarget(nmap, Request{Target: "192.168.0.0/16"}); err != nil {
		t.Errorf("/16 CIDR should pass: %v", err)
	}
	if _, err := ValidateTarget(nmap, Request{Target: "192.168.1.0/24"}); err != nil {
		t.Errorf("/24 CIDR should pass: %v", err)
	}
}

// M3: leading dash targets and bad hostnames are rejected.
func TestLeadingDashTargetRejected(t *testing.T) {
	nmap := Registry["nmap"]
	for _, target := range []string{"-foo", "--help", "-Pn"} {
		if _, err := ValidateTarget(nmap, Request{Target: target}); err == nil {
			t.Errorf("target %q should be rejected", target)
		}
	}
	for _, h := range []string{"-bad", "bad-", ".bad", "bad."} {
		if hostName(h) {
			t.Errorf("hostName(%q) should be false", h)
		}
	}
	if !hostName("good-host.example") {
		t.Error("hostName(good-host.example) should be true")
	}
	// nmap args now carry a -- separator before the target.
	args, err := Registry["nmap"].runArgs(Request{Target: "127.0.0.1", Profile: "quick"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-- 127.0.0.1") {
		t.Errorf("nmap args should contain '--' before target: %v", args)
	}
}

// C7: scheduled scans need a real reference for external targets.
func TestValidateScheduled(t *testing.T) {
	ext := Request{Connector: "nmap", Target: "8.8.8.8", Scheduled: true, Confirmed: true, AuthorizationRef: "scheduled", AllowExternal: true}
	if err := ValidateScheduled(ext); err == nil {
		t.Error("scheduled scan with reference 'scheduled' should be rejected")
	}
	ext.AuthorizationRef = ""
	if err := ValidateScheduled(ext); err == nil {
		t.Error("scheduled scan with no reference should be rejected")
	}
	ext.AuthorizationRef = "ROE-123"
	if err := ValidateScheduled(ext); err != nil {
		t.Errorf("scheduled scan with a real reference should pass validation: %v", err)
	}
	local := Request{Connector: "nmap", Target: "192.168.1.1", Scheduled: true}
	if err := ValidateScheduled(local); err != nil {
		t.Errorf("local scheduled scan should pass: %v", err)
	}
	// Prepare enforces the gate before checking tool availability: a valid
	// scheduled scan may still fail as "not installed" here (nmap is not
	// present in this VM), but it must never fail on authorization.
	if _, _, _, err := Prepare(ext); err != nil && (strings.Contains(err.Error(), "authorized") || strings.Contains(err.Error(), "authorization reference")) {
		t.Errorf("Prepare should pass the gate for a valid scheduled scan, got %v", err)
	}
	if _, _, _, err := Prepare(Request{Connector: "nmap", Target: "8.8.8.8", Scheduled: true, Confirmed: true, AuthorizationRef: "scheduled", AllowExternal: true}); err == nil || !strings.Contains(err.Error(), "authorization reference") {
		t.Errorf("Prepare should reject a 'scheduled' reference, got %v", err)
	}
}

// H7: pcap paths must be under the allowlist, with the right extension,
// and symlinks must resolve inside the allowlist.
func TestValidatePcapPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DARU_PCAP_DIR", dir)
	good := filepath.Join(dir, "cap.pcap")
	if err := os.WriteFile(good, []byte("fake"), 0o644); err != nil {
		t.Fatal(err)
	}
	conn := Registry["tshark-pcap"]
	if _, err := ValidateTarget(conn, Request{Target: good}); err != nil {
		t.Errorf("allowlisted pcap should pass: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "cap.pcap")
	if err := os.WriteFile(outside, []byte("fake"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateTarget(conn, Request{Target: outside}); err == nil {
		t.Error("pcap outside the allowlist should be rejected")
	}
	if _, err := ValidateTarget(conn, Request{Target: "/etc/passwd"}); err == nil {
		t.Error("/etc/passwd should be rejected")
	}
	if _, err := ValidateTarget(conn, Request{Target: filepath.Join(dir, "cap.txt")}); err == nil {
		t.Error("non-pcap extension should be rejected")
	}
	link := filepath.Join(dir, "link.pcap")
	if err := os.Symlink("/etc/passwd", link); err == nil {
		if _, err := ValidateTarget(conn, Request{Target: link}); err == nil {
			t.Error("symlink escaping the allowlist should be rejected")
		}
	}
}

// M1: loopback and allowlist enforcement, duration caps.
func TestCaptureFilterRules(t *testing.T) {
	if err := ValidateCaptureFilter(CaptureFilter{Iface: "lo"}); err == nil {
		t.Error("loopback capture for a power user should be rejected")
	}
	if err := ValidateCaptureFilter(CaptureFilter{Iface: "lo", Admin: true}); err != nil {
		t.Errorf("loopback capture for admin should pass: %v", err)
	}
	if got := clampCaptureDuration(3600, false); got != 300 {
		t.Errorf("power capture should clamp to 300s, got %d", got)
	}
	if got := clampCaptureDuration(3600, true); got != 3600 {
		t.Errorf("admin capture should allow 3600s, got %d", got)
	}
	if got := clampCaptureDuration(0, false); got != 300 {
		t.Errorf("empty duration should default to 300s, got %d", got)
	}
	t.Setenv("DARU_CAPTURE_IFACES", "eth0,wlan0")
	if err := ValidateCaptureFilter(CaptureFilter{Iface: "eth1"}); err == nil {
		t.Error("interface outside the allowlist should be rejected")
	}
	if err := ValidateCaptureFilter(CaptureFilter{Iface: "eth0"}); err != nil {
		t.Errorf("allowlisted interface should pass: %v", err)
	}
}

// M5: every parser output is capped centrally at 5000 findings.
func TestCapFindings(t *testing.T) {
	var in []Finding
	for i := 0; i < 6000; i++ {
		in = append(in, Finding{Title: fmt.Sprintf("f%d", i), Target: "127.0.0.1"})
	}
	out := capFindings(in, "127.0.0.1")
	if len(out) != MaxFindings+1 {
		t.Fatalf("want %d findings, got %d", MaxFindings+1, len(out))
	}
	if out[MaxFindings].Service != "truncated" {
		t.Errorf("last finding should be the truncation marker, got %+v", out[MaxFindings])
	}
	if got := capFindings(in[:10], "127.0.0.1"); len(got) != 10 {
		t.Errorf("small lists should pass through, got %d", len(got))
	}
}

// MITRE mapping for the headline connectors, and the posture collector.
func TestMitreMapping(t *testing.T) {
	cases := map[string][2]string{
		"nmap": {"Reconnaissance", "T1595.002"}, "nuclei": {"Initial Access", "T1190"},
		"nikto": {"Initial Access", "T1190"}, "sqlmap": {"Initial Access", "T1190"},
		"wapiti": {"Initial Access", "T1190"},
	}
	for name, want := range cases {
		tactic, tech := mitreForConnector(name)
		if tactic != want[0] || tech != want[1] {
			t.Errorf("mitreForConnector(%q) = %q/%q, want %q/%q", name, tactic, tech, want[0], want[1])
		}
	}
	fs := applyMitre("nmap", []Finding{{Title: "x", Target: "127.0.0.1"}})
	if fs[0].MitreTactic != "Reconnaissance" || fs[0].MitreTechnique != "T1595.002" {
		t.Errorf("applyMitre did not fill MITRE fields: %+v", fs[0])
	}
	found, err := postureCollect(context.Background(), Request{})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		t.Fatal("posture collector should return findings")
	}
	seen := map[string]bool{}
	for _, f := range found {
		seen[f.MitreTactic] = true
	}
	if !seen["Reconnaissance"] || !seen["Initial Access"] {
		t.Errorf("posture should cover Reconnaissance and Initial Access, got %v", found)
	}
	if _, ok := Registry["posture"]; !ok {
		t.Error("posture connector should be registered")
	}
}

// New connectors: registration, argument builders, and parsers.
func TestNewConnectors(t *testing.T) {
	for _, name := range []string{"rustscan", "dalfox", "wpscan", "assetfinder", "waybackurls", "gau", "hakrawler", "trufflehog"} {
		c, ok := Registry[name]
		if !ok {
			t.Errorf("connector %q should be registered", name)
			continue
		}
		if c.build == nil || c.parse == nil {
			t.Errorf("connector %q needs build and parse", name)
		}
		if c.verify == nil {
			t.Errorf("connector %q needs a binary verifier", name)
		}
	}
	args, err := Registry["rustscan"].runArgs(Request{Target: "192.168.1.1", Profile: "quick"})
	if err != nil || !strings.Contains(strings.Join(args, " "), "192.168.1.1") {
		t.Errorf("rustscan args wrong: %v %v", args, err)
	}
	args, err = Registry["dalfox"].runArgs(Request{Target: "https://192.168.1.1/?q=1"})
	if err != nil || args[0] != "url" {
		t.Errorf("dalfox args wrong: %v %v", args, err)
	}
	args, err = Registry["wpscan"].runArgs(Request{Target: "https://192.168.1.1/"})
	if err != nil || !strings.Contains(strings.Join(args, " "), "--url") {
		t.Errorf("wpscan args wrong: %v %v", args, err)
	}
	args, err = Registry["assetfinder"].runArgs(Request{Target: "example.local"})
	if err != nil || !strings.Contains(strings.Join(args, " "), "--subs-only") {
		t.Errorf("assetfinder args wrong: %v %v", args, err)
	}
	args, err = Registry["gau"].runArgs(Request{Target: "example.local"})
	if err != nil || !strings.Contains(strings.Join(args, " "), "--subs") {
		t.Errorf("gau args wrong: %v %v", args, err)
	}
	args, err = Registry["hakrawler"].runArgs(Request{Target: "https://192.168.1.1/"})
	if err != nil || args[0] != "-url" {
		t.Errorf("hakrawler args wrong: %v %v", args, err)
	}
	args, err = Registry["trufflehog"].runArgs(Request{Target: "https://192.168.1.1/repo.git"})
	if err != nil || !strings.Contains(strings.Join(args, " "), "--only-verified") {
		t.Errorf("trufflehog default profile should use --only-verified: %v %v", args, err)
	}
}

func TestNewParsers(t *testing.T) {
	r := Request{Target: "192.168.1.1"}
	fs := parseRustscan([]byte("Open 192.168.1.1:80\nOpen 192.168.1.1:443\n"), r)
	if len(fs) != 2 || fs[0].Port != "80" {
		t.Errorf("parseRustscan wrong: %+v", fs)
	}
	dalfox := `{"type":"Reflected XSS","severity":"high","url":"https://192.168.1.1/?q=1","payload":"<script>alert(1)</script>"}`
	fs = parseDalfox([]byte(dalfox), r)
	if len(fs) != 1 || fs[0].Severity != "high" {
		t.Errorf("parseDalfox wrong: %+v", fs)
	}
	wp := `{"version":{"number":"6.5"},"interesting_findings":[{"type":"robots.txt","url":"https://192.168.1.1/robots.txt"}],"vulnerabilities":[{"title":"CVE-2024-1"}]}`
	fs = parseWpscan([]byte(wp), r)
	if len(fs) != 3 {
		t.Errorf("parseWpscan should return version + finding + vuln, got %+v", fs)
	}
	urls := parseURLList([]byte("https://example.local/a\nhttps://example.local/b\nhttps://example.local/a\nnot-a-url\n"), r)
	if len(urls) != 2 {
		t.Errorf("parseURLList should dedupe and skip non-URLs, got %+v", urls)
	}
	th := `{"DetectorName":"github","Verified":true,"SourceMetadata":{"Data":{"Git":{"repository":"repo","file":"config.py","line":3}}}}`
	fs = parseTrufflehog([]byte(th), r)
	if len(fs) != 1 || fs[0].Severity != "high" {
		t.Errorf("parseTrufflehog verified secret should be high: %+v", fs)
	}
}

// M17: shellQuote must escape single quotes; ffuf must not panic on empty target.
func TestShellQuoteEscapesSingleQuote(t *testing.T) {
	q := shellQuote([]string{"a'b", "x y"})
	if !strings.Contains(q, `'a'\''b'`) {
		t.Errorf("shellQuote should escape a single quote as '\\'', got %q", q)
	}
	if _, err := Registry["ffuf"].runArgs(Request{Target: ""}); err == nil {
		t.Error("ffuf with an empty target should return an error, not panic")
	}
}

// M7: capped writer bounds helper output.
func TestCapWriterBounds(t *testing.T) {
	var buf bytes.Buffer
	w := capWriter(&buf, 10)
	if _, err := w.Write([]byte("0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 10 {
		t.Errorf("capWriter should stop at 10 bytes, got %d", buf.Len())
	}
}

// H8: root must not trust user-writable binary directories.
func TestBinarySafeForRoot(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tool")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if !binarySafeForRoot(p) {
			t.Error("root-owned 0755 binary should be safe for root")
		}
	} else {
		// Not running as root: the temp file is owned by this user, so root
		// must not trust it. Check a system binary for the positive case.
		if binarySafeForRoot(p) {
			t.Error("non-root-owned binary should not be safe for root")
		}
		for _, sys := range []string{"/bin/sh", "/usr/bin/env"} {
			if fi, err := os.Stat(sys); err == nil && fi.Mode().Perm()&0o022 == 0 {
				if !binarySafeForRoot(sys) {
					t.Errorf("%s (root-owned, not writable) should be safe for root", sys)
				}
				break
			}
		}
	}
	if err := os.Chmod(p, 0o777); err != nil {
		t.Fatal(err)
	}
	if binarySafeForRoot(p) {
		t.Error("world-writable binary should not be safe for root")
	}
}

// M4: ErrBusy is the typed semaphore-full error handlers map to 429.
func TestErrBusy(t *testing.T) {
	if ErrBusy == nil || !strings.Contains(ErrBusy.Error(), "busy") {
		t.Errorf("ErrBusy should describe a busy scanner, got %v", ErrBusy)
	}
}

// runNative re-check: a public URL without authorization must not run.
func TestRunNativeRecheck(t *testing.T) {
	c := Registry["crtsh"]
	res := runNative(context.Background(), c, Request{Target: "example.invalid"}, 5*time.Second)
	if res.Err == "" {
		t.Errorf("runNative should fail the scope re-check for an unresolvable public domain, got %+v", res)
	}
}
