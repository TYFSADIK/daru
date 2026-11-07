package recon

import (
	"strings"
	"testing"
)

func TestAuthorizationGate(t *testing.T) {
	// Missing confirmation is rejected before anything runs.
	_, _, _, err := Prepare(Request{Connector: "nmap", Target: "127.0.0.1", AuthorizationRef: "ROE-1"})
	if err == nil || !strings.Contains(err.Error(), "authorized") {
		t.Errorf("unconfirmed scan should be rejected, got %v", err)
	}
	// Missing authorization reference is rejected.
	_, _, _, err = Prepare(Request{Connector: "nmap", Target: "127.0.0.1", Confirmed: true})
	if err == nil || !strings.Contains(err.Error(), "authorization reference") {
		t.Errorf("missing auth ref should be rejected, got %v", err)
	}
	// Unknown connector.
	_, _, _, err = Prepare(Request{Connector: "nope", Target: "x", Confirmed: true, AuthorizationRef: "ROE-1"})
	if err == nil {
		t.Error("unknown connector should fail")
	}
}

func TestScopeGuard(t *testing.T) {
	nmap := Registry["nmap"]
	cases := []struct {
		target   string
		external bool
		ok       bool
	}{
		{"127.0.0.1", false, true},
		{"10.0.0.5", false, true},
		{"192.168.1.0/24", false, true},
		{"8.8.8.8", false, false},      // public, not allowed
		{"8.8.8.8", true, true},        // public, explicitly allowed
		{"10.0.0.0/8", true, false},    // too large even if external allowed
		{"not a host!!", false, false}, // invalid
	}
	for _, c := range cases {
		_, err := ValidateTarget(nmap, Request{Target: c.target, AllowExternal: c.external})
		if (err == nil) != c.ok {
			t.Errorf("ValidateTarget(%q, external=%v) ok=%v, want %v (err=%v)", c.target, c.external, err == nil, c.ok, err)
		}
	}
}

func TestURLGuard(t *testing.T) {
	nuclei := Registry["nuclei"]
	if _, err := ValidateTarget(nuclei, Request{Target: "http://10.0.0.1/"}); err != nil {
		t.Errorf("private URL should pass: %v", err)
	}
	if _, err := ValidateTarget(nuclei, Request{Target: "ftp://10.0.0.1/"}); err == nil {
		t.Error("non-http URL should fail")
	}
}

func TestNmapArgs(t *testing.T) {
	c := Registry["nmap"]
	args, err := c.runArgs(Request{Target: "127.0.0.1", Profile: "vuln"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--script vuln") || !strings.Contains(joined, "-oX -") {
		t.Errorf("nmap vuln args wrong: %v", args)
	}
	// Invalid port spec rejected.
	if _, err := c.runArgs(Request{Target: "127.0.0.1", Ports: "80; rm -rf"}); err == nil {
		t.Error("bad port spec should be rejected")
	}
}

func TestNmapParse(t *testing.T) {
	xml := `<?xml version="1.0"?><nmaprun><host><status state="up"/>
	<address addr="127.0.0.1" addrtype="ipv4"/>
	<ports><port protocol="tcp" portid="22"><state state="open"/>
	<service name="ssh" product="OpenSSH" version="9.0"/></port></ports></host></nmaprun>`
	f := parseNmapXML([]byte(xml), Request{Target: "127.0.0.1"})
	if len(f) != 1 || f[0].Port != "22/tcp" || f[0].Service != "ssh" {
		t.Errorf("nmap parse wrong: %+v", f)
	}
}

func TestRegistryInstalled(t *testing.T) {
	if len(Registry) < 20 {
		t.Errorf("expected many connectors, got %d", len(Registry))
	}
	// No connector should be in a denied category.
	for name, c := range Registry {
		if strings.Contains(strings.ToLower(string(c.Category)), "ddos") {
			t.Errorf("connector %q is in a denied category", name)
		}
	}
}
