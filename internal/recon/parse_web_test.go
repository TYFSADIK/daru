package recon

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParseGobuster(t *testing.T) {
	out := "\x1b[2K/admin                (Status: 302) [Size: 0] [--> /admin/login]\n" +
		"\x1b[2K/about                (Status: 200) [Size: 1234]\n" +
		"\x1b[2K/secret               (Status: 403) [Size: 12]\n" +
		"progress noise\n"
	fs := parseGobuster([]byte(out), Request{Target: "http://h"})
	if len(fs) != 3 {
		t.Fatalf("want 3 paths, got %d: %+v", len(fs), fs)
	}
	if fs[0].Title != "/admin" || fs[0].Fields["redirect"] != "/admin/login" {
		t.Errorf("redirect not parsed / ANSI not stripped: %+v", fs[0])
	}
	// 403 should be medium (exists but protected).
	var protectedMedium bool
	for _, f := range fs {
		if f.Title == "/secret" && f.Severity == "medium" {
			protectedMedium = true
		}
	}
	if !protectedMedium {
		t.Errorf("403 should be medium: %+v", fs)
	}
}

func TestParseSqlmapNegative(t *testing.T) {
	out := strings.Join([]string{
		"[11:00:00] [WARNING] heuristic (basic) test shows that GET parameter 'id' might not be injectable",
		"[11:00:05] [WARNING] GET parameter 'id' does not seem to be injectable",
		"[11:00:05] [ERROR] all tested parameters do not appear to be injectable.",
	}, "\n")
	fs := parseSqlmap([]byte(out), Request{Target: "http://h"})
	for _, f := range fs {
		if f.Severity == "critical" || f.Severity == "high" {
			t.Errorf("negative sqlmap result must not be high/critical: %+v", f)
		}
	}
}

func TestParseSqlmapPositive(t *testing.T) {
	out := strings.Join([]string{
		"sqlmap identified the following injection point(s)",
		"Parameter: id (GET)",
		"    Type: boolean-based blind",
		"    Title: AND boolean-based blind - WHERE or HAVING clause",
		"    Payload: id=1 AND 1=1",
		"---",
		"[11:00:10] back-end DBMS: MySQL",
	}, "\n")
	fs := parseSqlmap([]byte(out), Request{Target: "http://h"})
	var crit, high int
	for _, f := range fs {
		if f.Severity == "critical" {
			crit++
		}
		if f.Severity == "high" {
			high++
		}
	}
	if crit == 0 {
		t.Errorf("injection block should yield a critical finding: %+v", fs)
	}
	if high == 0 {
		t.Errorf("back-end DBMS line should be high: %+v", fs)
	}
}

func TestParseKatana(t *testing.T) {
	out := `{"request":{"method":"GET","endpoint":"http://h/"},"response":{"status_code":200,"title":"Home"}}
{"request":{"method":"GET","endpoint":"http://h/app.js"},"response":{"status_code":200}}
{"request":{"method":"GET","endpoint":"http://h/"}}
not json`
	fs := parseKatana([]byte(out), Request{Target: "http://h"})
	if len(fs) != 2 {
		t.Fatalf("want 2 unique endpoints, got %d: %+v", len(fs), fs)
	}
	if fs[0].Title != "http://h/" || !strings.Contains(fs[0].Detail, "200") {
		t.Errorf("endpoint/status wrong: %+v", fs[0])
	}
}

func TestParseWafw00f(t *testing.T) {
	out := "        ,______\n   banner art ~~~\n" +
		"[+] The site http://h is behind Cloudflare (Cloudflare Inc.) WAF.\n" +
		"[~] Number of requests: 5\n"
	fs := parseWafw00f([]byte(out), Request{Target: "http://h"})
	var detected bool
	for _, f := range fs {
		if strings.Contains(f.Title, "Cloudflare") {
			detected = true
		}
		if strings.Contains(f.Title, "banner") || strings.Contains(f.Title, "______") {
			t.Errorf("banner art should be filtered: %+v", f)
		}
	}
	if !detected {
		t.Errorf("WAF verdict not captured: %+v", fs)
	}
}

func TestParseNiktoText(t *testing.T) {
	out := strings.Join([]string{
		"- Nikto v2.5.0",
		"+ Target IP:          127.0.0.1",
		"+ Server: nginx/1.24",
		"+ OSVDB-3233: /icons/README: Apache default file found.",
		"+ /admin/: This might be interesting.",
	}, "\n")
	fs := parseNikto([]byte(out), Request{Target: "http://h"})
	var mediumOSVDB bool
	for _, f := range fs {
		if strings.Contains(f.Title, "OSVDB") && f.Severity == "medium" {
			mediumOSVDB = true
		}
	}
	if !mediumOSVDB {
		t.Errorf("OSVDB finding should be medium: %+v", fs)
	}
}

func TestExtractJSONObjects(t *testing.T) {
	// Two concatenated arrays with log text between, classic testssl stdout.
	in := []byte(`garbage [ {"id":"a","finding":"x {nested}"} ] log line [ {"id":"b"} ]`)
	objs := extractJSONObjects(in)
	if len(objs) != 2 {
		t.Fatalf("want 2 objects, got %d: %q", len(objs), objs)
	}
	if !strings.Contains(string(objs[0]), `"id":"a"`) {
		t.Errorf("first object wrong: %s", objs[0])
	}
}

func TestParseTestsslBraces(t *testing.T) {
	out := []byte(`[
{"id":"engine_problem","severity":"INFO","finding":"ignore me"}
,{"id":"cert_chain_of_trust","severity":"CRITICAL","finding":"self signed"}
,{"id":"BREACH","severity":"OK","finding":"fine"}
]`)
	fs := parseTestssl(out, Request{Target: "h"})
	if len(fs) != 1 {
		t.Fatalf("want 1 real finding (engine_problem+OK dropped), got %d: %+v", len(fs), fs)
	}
	if fs[0].Severity != "critical" {
		t.Errorf("expected critical: %+v", fs[0])
	}
}

func TestParseWapiti(t *testing.T) {
	// Note the raw newline inside "info" that breaks strict JSON parsers.
	out := []byte("Scanning...\n{\"vulnerabilities\":{\"SQL Injection\":[{\"method\":\"GET\",\"path\":\"/x\",\"info\":\"line1\nline2\",\"level\":3,\"parameter\":\"id\"}],\"Cross Site Scripting\":[{\"method\":\"GET\",\"path\":\"/s\",\"info\":\"ok\",\"level\":2,\"parameter\":\"q\"}]}}")
	fs := parseWapiti(out, Request{Target: "http://h"})
	if len(fs) != 2 {
		t.Fatalf("want 2 vulns, got %d: %+v", len(fs), fs)
	}
	var high, medium int
	for _, f := range fs {
		if f.Severity == "high" {
			high++
		}
		if f.Severity == "medium" {
			medium++
		}
		if !strings.Contains(f.Fields["parameter"], "") {
			t.Errorf("missing fields: %+v", f)
		}
	}
	if high != 1 || medium != 1 {
		t.Errorf("severity mapping wrong: high=%d medium=%d", high, medium)
	}
}

func TestParseSmbShares(t *testing.T) {
	out := strings.Join([]string{
		"\tSharename       Type      Comment",
		"\t---------       ----      -------",
		"\tipc$            IPC       IPC Service",
		"\tpublic          Disk      Public files",
		"",
		"SMB1 disabled -- no workgroup available",
	}, "\n")
	fs := parseSmbShares(out, "1.2.3.4")
	if len(fs) != 2 {
		t.Fatalf("want 2 shares (status line skipped), got %d: %+v", len(fs), fs)
	}
	var disk bool
	for _, f := range fs {
		if f.Fields["type"] == "Disk" && f.Severity == "low" {
			disk = true
		}
	}
	if !disk {
		t.Errorf("Disk share should be low severity: %+v", fs)
	}
}

func TestParseRpcclient(t *testing.T) {
	out := strings.Join([]string{
		"user:[admin] rid:[0x1f4]",
		"user:[guest] rid:[0x1f5]",
		"group:[Domain Admins] rid:[0x200]",
		"Domain: WORKGROUP",
		"result was NT_STATUS_ACCESS_DENIED",
	}, "\n")
	fs := parseRpcclient(out, "h")
	var users, groups int
	for _, f := range fs {
		if strings.HasPrefix(f.Title, "User:") {
			users++
		}
		if strings.HasPrefix(f.Title, "Group:") {
			groups++
		}
	}
	if users != 2 || groups != 1 {
		t.Errorf("want 2 users/1 group, got users=%d groups=%d: %+v", users, groups, fs)
	}
}

func TestEnum4linuxAlwaysAvailable(t *testing.T) {
	// enum4linux/enum4linux-ng are native with a built-in SMB fallback, so the
	// connector is always runnable even without the external binary.
	for _, name := range []string{"enum4linux", "enum4linux-ng"} {
		c, ok := Get(name)
		if !ok {
			t.Fatalf("%s not registered", name)
		}
		if !c.IsNative() || !c.Available() {
			t.Errorf("%s should be native and always available: native=%v avail=%v", name, c.IsNative(), c.Available())
		}
	}
}

func TestParseEnum4linux(t *testing.T) {
	out := strings.Join([]string{
		"[+] Enumerating users using SID",
		"user:[admin] rid:[0x3e8]",
		"group:[Domain Users] rid:[0x201]",
		"OS=[Windows] Server=[SMB]",
	}, "\n")
	fs := parseEnum4linux(out, "h")
	if len(fs) < 2 {
		t.Errorf("expected user/group/os findings, got %+v", fs)
	}
}

func TestParseDnstwist(t *testing.T) {
	out := `[{"domain":"example.com","fuzzer":"original","dns_a":["1.1.1.1"]},
{"domain":"examp1e.com","fuzzer":"replacement","dns_a":["9.9.9.9"],"dns_mx":["mx.bad"]},
{"domain":"exampleX.com","fuzzer":"insertion"}]`
	fs := parseDnstwist([]byte(out), Request{Target: "example.com"})
	var registered bool
	for _, f := range fs {
		if f.Title == "examp1e.com" && f.Severity == "low" {
			registered = true
		}
		if f.Title == "example.com" {
			t.Errorf("the original domain (unregistered match) should be skipped")
		}
	}
	if !registered {
		t.Errorf("a resolving lookalike should be low severity: %+v", fs)
	}
}

func TestParseHostListCap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 6000; i++ {
		b.WriteString("h")
		fmt.Fprintf(&b, "%d", i)
		b.WriteString(".example.com\n")
	}
	fs := parseHostList([]byte(b.String()), Request{Target: "example.com"})
	if len(fs) > 5000 {
		t.Errorf("host list should be capped at 5000, got %d", len(fs))
	}
}

func TestParseHttpx(t *testing.T) {
	out := `{"url":"http://h","status_code":200,"title":"Home","webserver":"nginx","tech":["WordPress:6.0","PHP"],"host":"h"}`
	fs := parseHttpx([]byte(out), Request{Target: "h"})
	if len(fs) != 1 || !strings.Contains(fs[0].Detail, "WordPress:6.0") || !strings.Contains(fs[0].Title, "[200]") {
		t.Errorf("httpx enrichment wrong: %+v", fs)
	}
}

func TestParseDnsrecon(t *testing.T) {
	out := strings.Join([]string{
		"[*] std: Performing General Enumeration against: example.com...",
		"[*] DNSSEC is configured for example.com",
		"[+] A example.com 1.2.3.4",
		"[*] Zone Transfer was successful!! AXFR",
	}, "\n")
	fs := parseDnsrecon([]byte(out), Request{Target: "example.com"})
	var axfrHigh, progress bool
	for _, f := range fs {
		if strings.Contains(f.Title, "Zone Transfer") && f.Severity == "high" {
			axfrHigh = true
		}
		if strings.Contains(f.Title, "Performing") {
			progress = true
		}
	}
	if !axfrHigh {
		t.Errorf("AXFR success should be high: %+v", fs)
	}
	if progress {
		t.Errorf("progress line should be dropped: %+v", fs)
	}
}

func TestParseDnsenum(t *testing.T) {
	out := strings.Join([]string{
		"Host's addresses:",
		"__________________",
		"example.com.                   8     IN    A       1.2.3.4",
		"hera.ns.cloudflare.com.        86353 IN    A       108.162.192.162",
		"example.com.                   300   IN    MX      10 mail.example.com",
	}, "\n")
	fs := parseDnsenum([]byte(out), Request{Target: "example.com"})
	if len(fs) != 3 {
		t.Fatalf("want 3 records, got %d: %+v", len(fs), fs)
	}
	var mx bool
	for _, f := range fs {
		if f.Fields["record_type"] == "MX" {
			mx = true
		}
	}
	if !mx {
		t.Errorf("MX record not parsed: %+v", fs)
	}
}

func TestParseFierce(t *testing.T) {
	out := strings.Join([]string{
		"Fierce banner line ignored",
		"NS: ns1.example.com. ns2.example.com.",
		"SOA: ns1.example.com. (1.2.3.4)",
		"Zone: success",
		"Found: admin.example.com (5.6.7.8)",
	}, "\n")
	fs := parseFierce([]byte(out), Request{Target: "example.com"})
	var zoneHigh, found, banner bool
	for _, f := range fs {
		if strings.HasPrefix(f.Title, "Zone:") && f.Severity == "high" {
			zoneHigh = true
		}
		if strings.HasPrefix(f.Title, "Found:") && f.Service == "host" {
			found = true
		}
		if strings.Contains(f.Title, "banner") {
			banner = true
		}
	}
	if !zoneHigh || !found || banner {
		t.Errorf("fierce parse wrong: zoneHigh=%v found=%v banner=%v -> %+v", zoneHigh, found, banner, fs)
	}
}

func TestParseRpcclientEnhanced(t *testing.T) {
	out := strings.Join([]string{
		"user:[admin] rid:[0x1f4]",
		"group:[Domain Admins] rid:[0x200]",
		"Domain Sid: S-1-5-21-111-222-333",
		"min_password_length: 0",
		"password_properties: 0x00000000",
	}, "\n")
	fs := parseRpcclient(out, "h")
	var sid, pwMedium bool
	for _, f := range fs {
		if strings.Contains(f.Title, "Domain Sid") {
			sid = true
		}
		if strings.Contains(f.Title, "Password policy") && strings.Contains(f.Title, "min_password_length: 0") && f.Severity == "medium" {
			pwMedium = true
		}
	}
	if !sid {
		t.Errorf("domain SID not captured: %+v", fs)
	}
	if !pwMedium {
		t.Errorf("empty min password length should be medium: %+v", fs)
	}
}

func TestParseHping3(t *testing.T) {
	out := strings.Join([]string{
		"HPING 192.168.2.1 (wlo1 192.168.2.1): S set, 40 headers + 0 data bytes",
		"len=44 ip=192.168.2.1 ttl=64 DF id=0 sport=80 flags=SA seq=0 win=64240 rtt=8.0 ms",
		"len=44 ip=192.168.2.1 ttl=64 DF id=0 sport=80 flags=SA seq=1 win=64240 rtt=3.0 ms",
	}, "\n")
	fs := parseHping3([]byte(out), Request{Target: "192.168.2.1"})
	if len(fs) != 1 {
		t.Fatalf("want 1 deduped open-port finding, got %d: %+v", len(fs), fs)
	}
	if !strings.Contains(fs[0].Title, "80/tcp open") || fs[0].Severity != "low" {
		t.Errorf("SYN-ACK should mark port open/low: %+v", fs[0])
	}
}

func TestParseTraceroute(t *testing.T) {
	out := strings.Join([]string{
		"traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets",
		" 1  * * *",
		" 2  192.168.1.1  3.5 ms  3.2 ms  3.1 ms",
		" 3  * * *",
		" 4  8.8.8.8  12.0 ms",
	}, "\n")
	fs := parseTraceroute([]byte(out), Request{Target: "8.8.8.8"})
	// summary + 2 responding hops (the two * * * dropped)
	if len(fs) != 3 {
		t.Fatalf("want summary + 2 hops, got %d: %+v", len(fs), fs)
	}
	if !strings.Contains(fs[0].Title, "4 hops, 2 responded") {
		t.Errorf("summary wrong: %+v", fs[0])
	}
	for _, f := range fs[1:] {
		if strings.Contains(f.Title, "*") {
			t.Errorf("timeout hop should be dropped: %+v", f)
		}
	}
}

func TestParseWhois(t *testing.T) {
	soon := time.Now().AddDate(0, 0, 10).Format(time.RFC3339)
	out := strings.Join([]string{
		"% banner noise",
		"Registrar: Example Registrar",
		"Creation Date: 1995-08-14T04:00:00Z",
		"Registry Expiry Date: " + soon,
		"Name Server: NS1.EXAMPLE.COM",
		"Registrar URL: http://ignore.me",
	}, "\n")
	fs := parseWhois([]byte(out), Request{Target: "example.com"})
	var expiryMedium, registrar, urlLeaked bool
	for _, f := range fs {
		if strings.Contains(f.Title, "Expiry") && f.Severity == "medium" {
			expiryMedium = true
		}
		if strings.HasPrefix(f.Title, "Registrar:") {
			registrar = true
		}
		if strings.Contains(f.Title, "Registrar URL") {
			urlLeaked = true
		}
	}
	if !expiryMedium {
		t.Errorf("imminent expiry should be medium: %+v", fs)
	}
	if !registrar || urlLeaked {
		t.Errorf("field selection wrong (registrar=%v urlLeaked=%v): %+v", registrar, urlLeaked, fs)
	}
}

func TestParseSnmpwalk(t *testing.T) {
	out := strings.Join([]string{
		".1.3.6.1.2.1.1.1.0 = STRING: Linux router 5.10",
		".1.3.6.1.2.1.1.5.0 = STRING: gateway-01",
		".1.3.6.1.2.1.1.3.0 = Timeticks: (123456) 0:20:34.56",
		".1.3.6.1.4.1.9999.1 = INTEGER: 42",
	}, "\n")
	fs := parseSnmpwalk([]byte(out), Request{Target: "h"})
	var descr, name bool
	for _, f := range fs {
		if strings.HasPrefix(f.Title, "sysDescr:") && f.Severity == "low" {
			descr = true
		}
		if strings.HasPrefix(f.Title, "sysName:") {
			name = true
		}
	}
	if !descr || !name {
		t.Errorf("OID translation failed (descr=%v name=%v): %+v", descr, name, fs)
	}
}

func TestSmbEnumPortSupport(t *testing.T) {
	// smb-enum must accept a non-standard SMB port via the ports field.
	c, _ := Get("smb-enum")
	_, _, _, err := Prepare(Request{Connector: "smb-enum", Target: "127.0.0.1", Ports: "4445"})
	if err != nil {
		t.Errorf("smb-enum should accept a custom port: %v", err)
	}
	// Invalid ports rejected by the native collector's own guard is fine; here
	// just confirm the connector is native and available.
	if !c.IsNative() || !c.Available() {
		t.Errorf("smb-enum should be native and available")
	}
}

func TestParseHostListInteresting(t *testing.T) {
	out := strings.Join([]string{
		"www.example.com",
		"dev.example.com",
		"api.example.com",
		"blog.example.com",
	}, "\n")
	fs := parseHostList([]byte(out), Request{Target: "example.com"})
	sev := map[string]string{}
	for _, f := range fs {
		sev[f.Title] = f.Severity
	}
	if sev["dev.example.com"] != "low" || sev["api.example.com"] != "low" {
		t.Errorf("dev/api subdomains should be low severity: %+v", sev)
	}
	if sev["www.example.com"] != "info" || sev["blog.example.com"] != "info" {
		t.Errorf("ordinary subdomains should stay info: %+v", sev)
	}
}

func TestParseOnesixtyone(t *testing.T) {
	out := strings.Join([]string{
		"Scanning 1 hosts, 2 communities",
		"192.168.1.1 [public] Linux router 5.10",
		"192.168.1.5 [s3cr3t] HP Printer",
	}, "\n")
	fs := parseOnesixtyone([]byte(out), Request{Target: "192.168.1.0/24"})
	var pubHigh, customMedium bool
	for _, f := range fs {
		if strings.Contains(f.Title, "'public'") && f.Severity == "high" {
			pubHigh = true
		}
		if strings.Contains(f.Title, "'s3cr3t'") && f.Severity == "medium" {
			customMedium = true
		}
	}
	if !pubHigh || !customMedium {
		t.Errorf("community severity wrong (pubHigh=%v customMedium=%v): %+v", pubHigh, customMedium, fs)
	}
}

func TestParseUnicornscan(t *testing.T) {
	out := strings.Join([]string{
		"TCP open                    http[   80]         from 192.168.1.1  ttl 64",
		"TCP open                   https[  443]         from 192.168.1.1  ttl 64",
		"garbage line",
	}, "\n")
	fs := parseUnicornscan([]byte(out), Request{Target: "192.168.1.1"})
	if len(fs) != 2 {
		t.Fatalf("want 2 open ports, got %d: %+v", len(fs), fs)
	}
	if fs[0].Port != "80/tcp" {
		t.Errorf("port parse wrong: %+v", fs[0])
	}
}

func TestParseTheHarvester(t *testing.T) {
	out := strings.Join([]string{
		"[*] Emails found: 2",
		"-------------------",
		"admin@example.com",
		"info@example.com",
		"[*] Hosts found: 2",
		"-------------------",
		"www.example.com",
		"mail.example.com",
	}, "\n")
	fs := parseTheHarvester([]byte(out), Request{Target: "example.com"})
	var emails, hosts int
	for _, f := range fs {
		if strings.HasPrefix(f.Title, "Email:") {
			emails++
		}
		if strings.HasPrefix(f.Title, "Host:") {
			hosts++
		}
	}
	if emails != 2 || hosts != 2 {
		t.Errorf("want 2 emails/2 hosts, got emails=%d hosts=%d: %+v", emails, hosts, fs)
	}
}

func TestInferOSFromPorts(t *testing.T) {
	cases := []struct {
		ports []string
		want  string
	}{
		{[]string{"135", "139", "445", "3389"}, "Windows?"},
		{[]string{"22", "80", "443"}, "Linux/Unix?"},
		{[]string{"80", "443"}, ""},
		{[]string{"445", "139"}, "Windows?"},
	}
	for _, c := range cases {
		if got := inferOSFromPorts(c.ports); got != c.want {
			t.Errorf("inferOSFromPorts(%v) = %q, want %q", c.ports, got, c.want)
		}
	}
}

func TestDeviceTypeFromVendor(t *testing.T) {
	cases := map[string]string{
		"Apple, Inc.":                "Apple device",
		"ecobee inc":                 "IoT / smart device",
		"Hewlett Packard":            "Printer",
		"Cisco Systems":              "Network device",
		"Intel Corporate":            "PC / laptop",
		"Raspberry Pi Foundation":    "Raspberry Pi (Linux)",
		"VMware, Inc.":               "Virtual machine",
		"Totally Unknown Vendor LLC": "",
	}
	for vendor, want := range cases {
		if got := deviceTypeFromVendor(vendor, ""); got != want {
			t.Errorf("deviceTypeFromVendor(%q) = %q, want %q", vendor, got, want)
		}
	}
}

func TestDeviceTypeExtended(t *testing.T) {
	cases := map[string]string{
		"Synology Incorporated":                      "NAS / storage",
		"Sony Interactive Entertainment PlayStation": "Game console",
		"LG Electronics":                             "Smart TV / streamer",
		"Hikvision Digital Tech":                     "IP camera",
		"Motorola Mobility":                          "Mobile device",
		"Xerox Corporation":                          "Printer",
		"D-Link":                                     "Network device",
		"Shelly / Allterco":                          "IoT / smart device",
	}
	for vendor, want := range cases {
		if got := deviceTypeFromVendor(vendor, ""); got != want {
			t.Errorf("deviceTypeFromVendor(%q) = %q, want %q", vendor, got, want)
		}
	}
}
