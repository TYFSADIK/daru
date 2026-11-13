package recon

import "testing"

func TestParseDnsx(t *testing.T) {
	line := `{"host":"example.com","a":["93.184.216.34"],"aaaa":["2606:2800:220:1:248:1893:25c8:1946"],"mx":["0 ."],"ns":["a.iana-servers.net","b.iana-servers.net"],"txt":["v=spf1 -all","wgyf8z8cgvm2qmxpnbnldrcltvk4xqfn"]}`
	f := parseDnsx([]byte(line), Request{Target: "example.com"})
	if len(f) != 7 { // 1 A + 1 AAAA + 1 MX + 2 NS + 2 TXT
		t.Fatalf("want 7 expanded records, got %d", len(f))
	}
	var spfLow bool
	kinds := map[string]int{}
	for _, x := range f {
		kinds[x.Fields["record_type"]]++
		if x.Fields["record_type"] == "TXT" && x.Title == "TXT example.com → v=spf1 -all" && x.Severity == "low" {
			spfLow = true
		}
	}
	if kinds["A"] != 1 || kinds["AAAA"] != 1 || kinds["MX"] != 1 || kinds["NS"] != 2 || kinds["TXT"] != 2 {
		t.Fatalf("unexpected record breakdown: %v", kinds)
	}
	if !spfLow {
		t.Error("SPF TXT record should be flagged low severity")
	}
}
