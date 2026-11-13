package recon

import (
	"strings"
	"testing"
)

func TestParseNiktoSkipsBanner(t *testing.T) {
	out := []byte(`+ Target IP:          127.0.0.1
+ Target Hostname:    localhost
+ Target Port:        8099
+ Start Time:         2026-11-08 11:06:18 (GMT-5)
+ Server: SimpleHTTP/0.6
+ /admin/: Admin login page/section found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ End Time:           2026-11-08 11:07:00 (GMT-5)`)
	f := parseNikto(out, Request{Target: "http://127.0.0.1:8099/"})
	for _, x := range f {
		low := strings.ToLower(x.Title)
		if strings.HasPrefix(low, "target ") || strings.HasPrefix(low, "start time") || strings.HasPrefix(low, "end time") {
			t.Errorf("banner line leaked as finding: %q", x.Title)
		}
	}
	var hasAdmin, hasOsvdbMed bool
	for _, x := range f {
		if strings.Contains(x.Title, "/admin/") {
			hasAdmin = true
		}
		if strings.Contains(x.Title, "OSVDB") && x.Severity == "medium" {
			hasOsvdbMed = true
		}
	}
	if !hasAdmin {
		t.Error("real finding /admin/ missing")
	}
	if !hasOsvdbMed {
		t.Error("OSVDB finding should be medium")
	}
}
