package recon

import (
	"strings"
	"testing"
)

func TestParseSmbmapCleanError(t *testing.T) {
	out := []byte("[*] Detected 1 hosts serving SMB\n[!] Something weird happened on (192.168.2.82) Error occurs while reading from remote(104) on line 1015\n")
	f := parseSmbmap(out, Request{Target: "192.168.2.82"})
	var clean bool
	for _, x := range f {
		if strings.Contains(x.Title, "line 1015") {
			t.Errorf("internal error leaked: %q", x.Title)
		}
		if strings.Contains(x.Title, "Could not enumerate shares") {
			clean = true
		}
	}
	if !clean {
		t.Error("expected a clean enumeration-failed message")
	}
}
func TestParseSmbmapShares(t *testing.T) {
	out := []byte("[+] IP: 10.0.0.5:445\tName: host\nDisk\tPermissions\n----\t-----------\nADMIN$\tREAD, WRITE\nIPC$\tREAD ONLY\n")
	f := parseSmbmap(out, Request{Target: "10.0.0.5"})
	var rw, ro bool
	for _, x := range f {
		if strings.Contains(x.Title, "ADMIN$") && x.Severity == "medium" {
			rw = true
		}
		if strings.Contains(x.Title, "IPC$") && x.Severity == "low" {
			ro = true
		}
	}
	if !rw {
		t.Error("read-write share should be medium")
	}
	if !ro {
		t.Error("read-only share should be low")
	}
}
