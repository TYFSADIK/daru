package recon

import "testing"

// Captured enum4linux-ng -A output against a real Windows 10 host.
const e4lNgReal = `ENUM4LINUX - next generation (v1.3.10)

[*] Target ........... 192.168.2.82
[+] SMB is accessible on 445/tcp
[+] Got domain/workgroup name: WORKGROUP
[+] Full NetBIOS names information:
- DESKTOP-CPJ0VFK <20> -         M <ACTIVE>  File Server Service
- DESKTOP-CPJ0VFK <00> -         M <ACTIVE>  Workstation Service
- WORKGROUP       <00> - <GROUP> M <ACTIVE>  Domain/Workgroup Name
- MAC Address = 58-96-1D-F0-71-E3
Supported dialects:
  SMB 1.0: false
  SMB 3.1.1: true
Preferred dialect: SMB 3.0
SMB1 only: false
SMB signing required: true
NetBIOS computer name: DESKTOP-CPJ0VFK
DNS domain: DESKTOP-CPJ0VFK
FQDN: DESKTOP-CPJ0VFK
OS: Windows 10, Windows Server 2019, Windows Server 2016
OS build: '26100'`

func TestParseEnum4linuxNg(t *testing.T) {
	f := parseEnum4linux(e4lNgReal, "192.168.2.82")
	if len(f) < 9 {
		t.Fatalf("expected rich extraction, got %d findings", len(f))
	}
	want := map[string]bool{
		"NetBIOS computer name: DESKTOP-CPJ0VFK":                   false,
		"OS: Windows 10, Windows Server 2019, Windows Server 2016": false,
		"OS build: 26100":                 false,
		"MAC Address = 58-96-1D-F0-71-E3": false,
		"SMB preferred dialect: SMB 3.0":  false,
		"SMB signing required: true":      false,
	}
	for _, x := range f {
		if _, ok := want[x.Title]; ok {
			want[x.Title] = true
		}
	}
	for k, got := range want {
		if !got {
			t.Errorf("missing expected finding: %q", k)
		}
	}
}

// A weaker host: SMBv1 enabled and signing not required must be flagged medium.
func TestParseEnum4linuxNgInsecure(t *testing.T) {
	out := `[+] SMB is accessible on 445/tcp
Supported dialects:
  SMB 1.0: true
Preferred dialect: SMB 1.0
SMB signing required: false`
	f := parseEnum4linux(out, "10.0.0.5")
	var smbv1, signing bool
	for _, x := range f {
		if x.Severity == "medium" && contains(x.Title, "SMBv1") {
			smbv1 = true
		}
		if x.Severity == "medium" && contains(x.Title, "signing is NOT required") {
			signing = true
		}
	}
	if !smbv1 {
		t.Error("SMBv1-enabled host should raise a medium finding")
	}
	if !signing {
		t.Error("SMB-signing-not-required should raise a medium finding")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
