package recon

import (
	"strings"
	"testing"
)

func TestNmapDiscoveryOmitsPn(t *testing.T) {
	c := Registry["nmap"]
	// Discovery must NOT send -Pn, which would mark every address "up".
	args, err := c.build(c, Request{Target: "192.168.1.0/24", Profile: "discovery"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "-Pn") {
		t.Errorf("discovery profile must not use -Pn: %s", joined)
	}
	if !strings.Contains(joined, "-sn") {
		t.Errorf("discovery profile should use -sn: %s", joined)
	}
	// A normal port scan still uses -Pn.
	args, _ = c.build(c, Request{Target: "192.168.1.1", Profile: "quick"})
	if !strings.Contains(strings.Join(args, " "), "-Pn") {
		t.Errorf("quick profile should keep -Pn: %v", args)
	}
}

func TestParseAliveHosts(t *testing.T) {
	out := "192.168.1.1\n192.168.1.5\nnot-an-ip\n192.168.1.5\n"
	fs := parseAliveHosts([]byte(out), Request{})
	if len(fs) != 2 {
		t.Fatalf("want 2 unique hosts, got %d: %+v", len(fs), fs)
	}
	if fs[0].Fields["_kind"] != "host" {
		t.Errorf("alive hosts should be _kind host for the inventory: %+v", fs[0])
	}
}

func TestParseZmap(t *testing.T) {
	out := "saddr,sport\n192.168.1.4,80\n192.168.1.4,80\nbad\n10.0.0.2,443\n"
	fs := parseZmap([]byte(out), Request{})
	if len(fs) != 2 {
		t.Fatalf("want 2 results, got %d: %+v", len(fs), fs)
	}
	if fs[0].Port != "80" || fs[0].Fields["_kind"] != "host" {
		t.Errorf("unexpected first finding: %+v", fs[0])
	}
}

func TestParseNbtscan(t *testing.T) {
	out := "192.168.2.82\tDESKTOP-1\t<server>\t58:96:1d:f0:71:e3\nheader line\n"
	fs := parseNbtscan([]byte(out), Request{})
	if len(fs) != 1 {
		t.Fatalf("want 1 host, got %d: %+v", len(fs), fs)
	}
	if fs[0].Fields["hostname"] != "DESKTOP-1" || fs[0].Fields["_kind"] != "host" {
		t.Errorf("unexpected finding: %+v", fs[0])
	}
}

func TestParseNaabu(t *testing.T) {
	out := `{"host":"h","ip":"192.168.1.9","port":22}
{"ip":"192.168.1.9","port":80}
garbage`
	fs := parseNaabu([]byte(out), Request{})
	if len(fs) != 2 {
		t.Fatalf("want 2 ports, got %d: %+v", len(fs), fs)
	}
	if fs[0].Target != "192.168.1.9" || fs[0].Port != "22" {
		t.Errorf("unexpected finding: %+v", fs[0])
	}
}

func TestParseSmbmap(t *testing.T) {
	out := strings.Join([]string{
		"[+] IP: 192.168.2.1:445\tName: host\tStatus: NULL Session",
		"\tDisk                 Permissions     Comment",
		"\t----                 -----------     -------",
		"\tipc$                 NO ACCESS       IPC Service",
		"\tpublic               READ ONLY",
		"\tsecret               READ, WRITE",
		"[|] Authenticating...",
		"Closing connections...",
	}, "\n")
	fs := parseSmbmap([]byte(out), Request{Target: "192.168.2.1"})
	var shares, medium int
	for _, f := range fs {
		if strings.HasPrefix(f.Title, "Share: ") {
			shares++
		}
		if f.Severity == "medium" {
			medium++
		}
	}
	if shares != 3 {
		t.Errorf("want 3 shares (no spinner noise), got %d: %+v", shares, fs)
	}
	if medium != 1 {
		t.Errorf("a READ, WRITE share should be medium severity, got %d", medium)
	}
}

func TestParseTestssl(t *testing.T) {
	out := `[{"id":"BREACH","severity":"MEDIUM","finding":"potentially vulnerable"},` +
		`{"id":"cipherlist","severity":"OK","finding":"fine"},` +
		`{"id":"SSLv3","severity":"HIGH","finding":"offered"}]`
	fs := parseTestssl([]byte(out), Request{Target: "h"})
	if len(fs) != 2 {
		t.Fatalf("OK findings should be dropped; want 2, got %d: %+v", len(fs), fs)
	}
}

func TestParseSslscanXML(t *testing.T) {
	out := `<document><ssltest host="h" port="443">` +
		`<protocol type="tls" version="1.0" enabled="1"/>` +
		`<protocol type="tls" version="1.3" enabled="1"/>` +
		`<protocol type="ssl" version="3" enabled="0"/>` +
		`<cipher status="accepted" sslversion="TLSv1.3" bits="256" cipher="TLS_AES_256_GCM_SHA384"/>` +
		`</ssltest></document>`
	fs := parseSslscanXML([]byte(out), Request{})
	if len(fs) != 3 {
		t.Fatalf("want 2 protocols + 1 cipher, got %d: %+v", len(fs), fs)
	}
	// TLS 1.0 must be flagged at least medium.
	var flagged bool
	for _, f := range fs {
		if strings.Contains(f.Title, "tls1.0") && f.Severity == "medium" {
			flagged = true
		}
	}
	if !flagged {
		t.Errorf("TLS 1.0 should be medium severity: %+v", fs)
	}
}
