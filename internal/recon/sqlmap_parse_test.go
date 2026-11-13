package recon

import (
	"strings"
	"testing"
)

func TestParseSqlmapCleanVerdict(t *testing.T) {
	out := []byte("[11:19:38] [WARNING] heuristic (basic) test shows that GET parameter 'user' might be injectable\n[11:19:38] [WARNING] GET parameter 'user' does not seem to be injectable\n[11:19:38] [ERROR] all tested parameters do not appear to be injectable\n")
	f := parseSqlmap(out, Request{Target: "http://x/?user=1"})
	for _, x := range f {
		if strings.Contains(x.Title, "heuristic") {
			t.Errorf("heuristic chatter leaked: %q", x.Title)
		}
		if strings.HasPrefix(x.Title, "[") {
			t.Errorf("log prefix not stripped: %q", x.Title)
		}
		if x.Severity == "critical" {
			t.Errorf("not-injectable wrongly marked critical: %q", x.Title)
		}
	}
	if len(f) == 0 {
		t.Fatal("expected a verdict finding")
	}
}
func TestParseSqlmapInjectable(t *testing.T) {
	out := []byte("[12:00:00] [INFO] GET parameter 'id' is injectable\n[12:00:01] [INFO] back-end DBMS: MySQL\n")
	f := parseSqlmap(out, Request{Target: "http://x/?id=1"})
	var crit bool
	for _, x := range f {
		if x.Severity == "critical" && strings.Contains(x.Title, "injectable") {
			crit = true
		}
	}
	if !crit {
		t.Error("injectable param should be critical")
	}
}
