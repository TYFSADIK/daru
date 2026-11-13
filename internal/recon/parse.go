package recon

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
)

// --- nmap XML ---

type nmapRun struct {
	Hosts []struct {
		Status struct {
			State string `xml:"state,attr"`
		} `xml:"status"`
		Address []struct {
			Addr   string `xml:"addr,attr"`
			Type   string `xml:"addrtype,attr"`
			Vendor string `xml:"vendor,attr"`
		} `xml:"address"`
		Os struct {
			OsMatch []struct {
				Name     string `xml:"name,attr"`
				Accuracy string `xml:"accuracy,attr"`
			} `xml:"osmatch"`
		} `xml:"os"`
		Hostnames struct {
			Hostname []struct {
				Name string `xml:"name,attr"`
			} `xml:"hostname"`
		} `xml:"hostnames"`
		Ports struct {
			Port []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   string `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
				} `xml:"service"`
				Script []struct {
					ID     string `xml:"id,attr"`
					Output string `xml:"output,attr"`
				} `xml:"script"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

// inferOSFromPorts guesses an OS family from the open-port fingerprint, used
// when nmap's own OS detection is unavailable (it requires root). It is a
// best-effort hint, suffixed with "?" to signal it is inferred, not confirmed.
func inferOSFromPorts(ports []string) string {
	set := map[string]bool{}
	for _, p := range ports {
		set[p] = true
	}
	switch {
	case set["3389"] || set["135"] || (set["445"] && set["139"]):
		return "Windows?"
	case set["445"] && !set["22"]:
		return "Windows/Samba?"
	case set["62078"]: // iOS lockdown
		return "iOS/Apple?"
	case set["548"] || set["5009"]: // AFP / AirPort
		return "macOS/Apple?"
	case set["9100"] || set["515"] || set["631"] && len(ports) <= 2: // printer ports
		return "Printer?"
	case set["23"] && set["80"] && !set["22"]: // telnet+http, no ssh
		return "Network device?"
	case set["22"]:
		return "Linux/Unix?"
	}
	return ""
}

func parseNmapXML(out []byte, r Request) []Finding {
	var run nmapRun
	if err := xml.Unmarshal(out, &run); err != nil {
		return genericParse(out, r)
	}
	var findings []Finding
	for _, h := range run.Hosts {
		addr, mac, vendor := "", "", ""
		for _, a := range h.Address {
			switch a.Type {
			case "ipv4", "ipv6":
				addr = a.Addr
			case "mac":
				mac = strings.ToLower(a.Addr)
				vendor = a.Vendor
			}
		}
		hostname := ""
		if len(h.Hostnames.Hostname) > 0 {
			hostname = h.Hostnames.Hostname[0].Name
		}
		osName := ""
		if len(h.Os.OsMatch) > 0 {
			osName = h.Os.OsMatch[0].Name
		}
		if addr == "" {
			continue
		}
		// One host-level device finding per up host, used to build inventory.
		if h.Status.State == "up" {
			var openPorts []string
			for _, p := range h.Ports.Port {
				if p.State.State == "open" {
					openPorts = append(openPorts, p.PortID)
				}
			}
			title := addr
			if hostname != "" {
				title += " (" + hostname + ")"
			}
			// When nmap's own OS scan is unavailable (it needs root), infer the
			// OS family passively from the open-port fingerprint.
			osGuess := osName
			if osGuess == "" {
				osGuess = inferOSFromPorts(openPorts)
			}
			fields := map[string]string{"_kind": "host", "ip": addr, "mac": mac, "vendor": vendor,
				"hostname": hostname, "os": osGuess, "ports": strings.Join(openPorts, ",")}
			detail := strings.TrimSpace(vendor + " " + osGuess)
			findings = append(findings, Finding{
				Title: title, Severity: "info", Target: addr, Service: "device", Detail: detail, Fields: fields,
			})
		}
		host := hostname
		if host == "" {
			host = addr
		}
		for _, p := range h.Ports.Port {
			if p.State.State != "open" {
				continue
			}
			svc := p.Service.Name
			ver := strings.TrimSpace(p.Service.Product + " " + p.Service.Version)
			title := fmt.Sprintf("%s/%s open", p.PortID, p.Protocol)
			if svc != "" {
				title += " (" + svc + ")"
			}
			f := Finding{
				Title: title, Severity: "info", Target: addr,
				Port: p.PortID + "/" + p.Protocol, Service: svc,
				Detail: ver,
				Fields: map[string]string{"host": host, "port": p.PortID, "proto": p.Protocol, "service": svc, "version": ver},
			}
			findings = append(findings, f)
			for _, s := range p.Script {
				sev := "medium"
				if strings.Contains(strings.ToLower(s.ID), "vuln") && strings.Contains(strings.ToUpper(s.Output), "VULNERABLE") {
					sev = "high"
				}
				findings = append(findings, Finding{
					Title: s.ID + " on " + p.PortID, Severity: sev, Target: addr,
					Port: p.PortID, Detail: strings.TrimSpace(s.Output),
				})
			}
		}
	}
	return findings
}

// --- masscan JSON ---

func parseMasscanJSON(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ","))
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec struct {
			IP    string `json:"ip"`
			Ports []struct {
				Port   int    `json:"port"`
				Proto  string `json:"proto"`
				Status string `json:"status"`
			} `json:"ports"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		for _, p := range rec.Ports {
			findings = append(findings, Finding{
				Title: fmt.Sprintf("%d/%s %s", p.Port, p.Proto, p.Status), Severity: "info",
				Target: rec.IP, Port: fmt.Sprintf("%d/%s", p.Port, p.Proto),
				Fields: map[string]string{"host": rec.IP, "port": fmt.Sprintf("%d", p.Port), "proto": p.Proto},
			})
		}
	}
	return findings
}

// --- nuclei JSONL ---

func parseNucleiJSONL(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec struct {
			TemplateID string `json:"template-id"`
			Info       struct {
				Name     string `json:"name"`
				Severity string `json:"severity"`
			} `json:"info"`
			Host      string `json:"host"`
			MatchedAt string `json:"matched-at"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		sev := rec.Info.Severity
		if sev == "" {
			sev = "info"
		}
		findings = append(findings, Finding{
			Title: rec.Info.Name, Severity: sev, Target: rec.Host,
			Detail: rec.MatchedAt,
			Fields: map[string]string{"template": rec.TemplateID, "matched_at": rec.MatchedAt},
		})
	}
	return findings
}

// --- generic JSON lines ---

func parseJSONLines(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var obj map[string]any
		if json.Unmarshal([]byte(line), &obj) != nil {
			continue
		}
		title := firstStr(obj, "url", "host", "input", "name", "domain", "fqdn", "target", "address")
		if title == "" {
			title = line
			if len(title) > 160 {
				title = title[:160]
			}
		}
		fields := map[string]string{}
		for k, v := range obj {
			switch vv := v.(type) {
			case string:
				fields[k] = vv
			case float64:
				fields[k] = fmt.Sprintf("%v", vv)
			case bool:
				fields[k] = fmt.Sprintf("%v", vv)
			}
			if len(fields) >= 40 {
				break
			}
		}
		findings = append(findings, Finding{Title: title, Severity: "info", Target: r.Target, Fields: fields})
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// parseDnsx expands dnsx's merged JSON (one object per name, each record type an
// array) into one finding per DNS record, so an A/AAAA/CNAME/MX/NS/TXT sweep is
// fully enumerated instead of collapsed into a single host entry. Returns nil
// when the output holds no DNS records, so callers can fall back.
func parseDnsx(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var obj map[string]any
		if json.Unmarshal([]byte(line), &obj) != nil {
			continue
		}
		host := firstStr(obj, "host", "name", "input", "fqdn")
		if host == "" {
			host = r.Target
		}
		// strVals pulls a string, or a []string/[]any of strings, from a key.
		strVals := func(key string) []string {
			switch vv := obj[key].(type) {
			case string:
				if vv != "" {
					return []string{vv}
				}
			case []any:
				var out []string
				for _, e := range vv {
					if s, ok := e.(string); ok && s != "" {
						out = append(out, s)
					}
				}
				return out
			}
			return nil
		}
		emit := func(kind, sev string, vals []string) {
			for _, v := range vals {
				findings = append(findings, Finding{
					Title: kind + " " + host + " → " + v, Severity: sev, Target: r.Target,
					Service: "dns", Fields: map[string]string{
						"host": host, "record_type": kind, "value": v, strings.ToLower(kind): v,
					},
				})
			}
		}
		emit("A", "info", strVals("a"))
		emit("AAAA", "info", strVals("aaaa"))
		emit("CNAME", "info", strVals("cname"))
		emit("MX", "info", strVals("mx"))
		emit("NS", "info", strVals("ns"))
		for _, txt := range strVals("txt") {
			sev := "info"
			if strings.Contains(txt, "v=spf1") || strings.HasPrefix(txt, "v=DMARC1") {
				sev = "low"
			}
			findings = append(findings, Finding{
				Title: "TXT " + host + " → " + txt, Severity: sev, Target: r.Target,
				Service: "dns", Fields: map[string]string{"host": host, "record_type": "TXT", "value": txt},
			})
		}
	}
	return findings
}

// --- sslyze (one large JSON object; summarize instead of flooding) ---

func parseSslyze(out []byte, r Request) []Finding {
	start := bytes.IndexByte(out, '{')
	end := bytes.LastIndexByte(out, '}')
	if start < 0 || end <= start {
		return genericParse(out, r)
	}
	var doc struct {
		ServerScanResults []struct {
			ServerLocation struct {
				Hostname string `json:"hostname"`
				Port     int    `json:"port"`
			} `json:"server_location"`
			// RawMessage values so a 2048-bit RSA modulus doesn't overflow
			// float64; we only need the scan_result keys.
			ScanResult map[string]json.RawMessage `json:"scan_result"`
		} `json:"server_scan_results"`
	}
	if json.Unmarshal(out[start:end+1], &doc) != nil || len(doc.ServerScanResults) == 0 {
		return genericParse(out, r)
	}
	var findings []Finding
	for _, s := range doc.ServerScanResults {
		host := s.ServerLocation.Hostname
		if s.ServerLocation.Port != 0 {
			host = fmt.Sprintf("%s:%d", host, s.ServerLocation.Port)
		}
		// Report which TLS protocol scans were performed/supported.
		for key := range s.ScanResult {
			sev := "info"
			k := strings.ToLower(key)
			if strings.Contains(k, "ssl_2") || strings.Contains(k, "ssl_3") || strings.Contains(k, "tls_1_0") || strings.Contains(k, "tls_1_1") {
				sev = "low"
			}
			if strings.Contains(k, "heartbleed") || strings.Contains(k, "robot") || strings.Contains(k, "ccs_injection") {
				sev = "medium"
			}
			findings = append(findings, Finding{
				Title: key, Severity: sev, Target: firstNonEmptyStr(host, r.Target), Service: "tls",
			})
		}
	}
	if len(findings) == 0 {
		findings = append(findings, Finding{Title: "sslyze scan completed", Severity: "info", Target: r.Target, Service: "tls"})
	}
	return findings
}

// --- hping3 (interpret TCP response flags: SA=open, RA=closed) ---

var hping3Re = regexp.MustCompile(`ip=(\S+).*?sport=(\d+)\s+flags=(\S+)`)

func parseHping3(out []byte, r Request) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	responses := 0
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(line)
		m := hping3Re.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		responses++
		ip, port, flags := m[1], m[2], m[3]
		key := ip + ":" + port
		if seen[key] {
			continue
		}
		seen[key] = true
		title := fmt.Sprintf("%s:%s", ip, port)
		sev := "info"
		state := flags
		switch {
		case strings.Contains(flags, "SA"): // SYN-ACK → open
			state = "open (SYN-ACK)"
			sev = "low"
			title = fmt.Sprintf("%s/tcp open", port)
		case strings.Contains(flags, "RA") || strings.Contains(flags, "R"): // RST → closed
			state = "closed (RST)"
			title = fmt.Sprintf("%s/tcp closed", port)
		}
		findings = append(findings, Finding{
			Title: title, Severity: sev, Target: ip, Port: port + "/tcp", Service: "tcp",
			Detail: "response flags: " + state,
			Fields: map[string]string{"ip": ip, "port": port, "flags": flags, "state": state},
		})
	}
	if responses == 0 {
		findings = append(findings, Finding{
			Title: "No TCP responses (port filtered or host silent)", Severity: "info", Target: r.Target, Service: "tcp",
		})
	}
	return findings
}

// --- fierce (text: NS/SOA/Zone/Wildcard/Found lines) ---

func parseFierce(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(stripANSI(line))
		if t == "" {
			continue
		}
		low := strings.ToLower(t)
		sev := "info"
		switch {
		case strings.HasPrefix(low, "zone:") && strings.Contains(low, "success"):
			sev = "high" // a successful zone transfer is a real finding
		case strings.HasPrefix(low, "ns:") || strings.HasPrefix(low, "soa:") ||
			strings.HasPrefix(low, "found:") || strings.HasPrefix(low, "zone:") ||
			strings.HasPrefix(low, "wildcard:") || strings.HasPrefix(low, "nearby:"):
		default:
			continue // skip banners/progress
		}
		svc := "dns"
		if strings.HasPrefix(low, "found:") {
			svc = "host"
		}
		findings = append(findings, Finding{Title: t, Severity: sev, Target: r.Target, Service: svc})
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// --- dnsenum (text; extract "name TTL IN TYPE value" DNS records) ---

var dnsenumRecordRe = regexp.MustCompile(`^(\S+?)\.?\s+\d+\s+IN\s+(A|AAAA|MX|NS|CNAME|TXT|SOA|PTR|SRV)\s+(.+)$`)

func parseDnsenum(out []byte, r Request) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		m := dnsenumRecordRe.FindStringSubmatch(strings.TrimSpace(stripANSI(line)))
		if m == nil {
			continue
		}
		name, typ, val := m[1], m[2], strings.TrimSpace(m[3])
		key := typ + " " + name + " " + val
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, Finding{
			Title: fmt.Sprintf("%s %s → %s", typ, name, val), Severity: "info", Target: r.Target, Service: strings.ToLower(typ),
			Fields: map[string]string{"record_type": typ, "name": name, "value": val},
		})
		if len(findings) >= 3000 {
			break
		}
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// --- dnsrecon (text; keep records/security findings, drop pure progress) ---

func parseDnsrecon(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		t := stripANSI(line)
		if t == "" {
			continue
		}
		// Strip the leading [*]/[+]/[-] marker.
		body := t
		if len(t) >= 3 && t[0] == '[' && t[2] == ']' {
			body = strings.TrimSpace(t[3:])
		}
		low := strings.ToLower(body)
		// Drop pure progress chatter.
		if strings.Contains(low, "performing") || strings.Contains(low, "records found") ||
			strings.HasPrefix(low, "checking") || strings.HasPrefix(low, "resolving") ||
			strings.HasPrefix(low, "trying") || strings.HasSuffix(body, "...") || body == "" {
			continue
		}
		sev := "info"
		switch {
		case strings.Contains(low, "zone transfer") && (strings.Contains(low, "success") || strings.Contains(low, "axfr")):
			sev = "high" // an open AXFR is a real finding
		case strings.Contains(low, "dnssec is not configured") || strings.Contains(low, "no dnssec"):
			sev = "low"
		}
		findings = append(findings, Finding{Title: truncate(body, 200), Severity: sev, Target: r.Target, Service: "dns"})
		if len(findings) >= 3000 {
			break
		}
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// --- httpx (rich HTTP probe: status, title, technologies) ---

func parseHttpx(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec struct {
			URL           string   `json:"url"`
			Title         string   `json:"title"`
			StatusCode    int      `json:"status_code"`
			Webserver     string   `json:"webserver"`
			Tech          []string `json:"tech"`
			ContentLength int      `json:"content_length"`
			Host          string   `json:"host"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil || rec.URL == "" {
			continue
		}
		title := rec.URL
		if rec.StatusCode != 0 {
			title += fmt.Sprintf(" [%d]", rec.StatusCode)
		}
		var parts []string
		if rec.Title != "" {
			parts = append(parts, rec.Title)
		}
		if rec.Webserver != "" {
			parts = append(parts, "server="+rec.Webserver)
		}
		if len(rec.Tech) > 0 {
			parts = append(parts, "tech: "+strings.Join(rec.Tech, ", "))
		}
		sev := "info"
		if rec.StatusCode >= 500 {
			sev = "low"
		}
		findings = append(findings, Finding{
			Title: title, Severity: sev, Target: firstNonEmptyStr(rec.Host, r.Target), Service: "http",
			Detail: truncate(strings.Join(parts, " · "), 300),
			Fields: map[string]string{"url": rec.URL, "status": fmt.Sprintf("%d", rec.StatusCode),
				"title": rec.Title, "webserver": rec.Webserver, "tech": strings.Join(rec.Tech, ", "),
				"content_length": fmt.Sprintf("%d", rec.ContentLength)},
		})
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// --- whatweb (fingerprint: detected technologies from the plugins map) ---

func parseWhatweb(out []byte, r Request) []Finding {
	var findings []Finding
	for _, obj := range extractJSONObjects(out) {
		var rec struct {
			Target     string                     `json:"target"`
			HTTPStatus int                        `json:"http_status"`
			Plugins    map[string]json.RawMessage `json:"plugins"`
		}
		if json.Unmarshal(obj, &rec) != nil || rec.Target == "" {
			continue
		}
		// Decode each plugin's value (whatweb stores {"string":[...],
		// "version":[...]}), so we keep "WordPress 6.4" / "nginx/1.24.0", not
		// just the plugin name.
		pluginVal := func(raw json.RawMessage) string {
			var p struct {
				String  []string `json:"string"`
				Version []string `json:"version"`
			}
			_ = json.Unmarshal(raw, &p)
			v := ""
			if len(p.String) > 0 {
				v = strings.TrimSpace(p.String[0])
			}
			if len(p.Version) > 0 {
				ver := strings.TrimSpace(p.Version[0])
				if v == "" {
					v = ver
				} else if !strings.Contains(v, ver) {
					v += " " + ver
				}
			}
			return v
		}
		var techs []string
		var server, pageTitle, cms, poweredBy string
		for name, raw := range rec.Plugins {
			v := pluginVal(raw)
			switch name {
			case "HTTPServer":
				server = v
			case "Title":
				pageTitle = v
			case "PoweredBy":
				poweredBy = v
			case "WordPress", "Joomla", "Drupal", "MetaGenerator":
				if cms == "" {
					cms = strings.TrimSpace(name + " " + v)
				}
			}
			if v != "" {
				techs = append(techs, name+": "+v)
			} else {
				techs = append(techs, name)
			}
		}
		sort.Strings(techs)
		title := rec.Target
		if rec.HTTPStatus != 0 {
			title += fmt.Sprintf(" [%d]", rec.HTTPStatus)
		}
		// Lead with the most useful identity in the title.
		var lead []string
		if pageTitle != "" {
			lead = append(lead, pageTitle)
		}
		if server != "" {
			lead = append(lead, "server="+server)
		}
		if cms != "" {
			lead = append(lead, cms)
		}
		detail := strings.Join(techs, " · ")
		if len(lead) > 0 {
			detail = strings.Join(lead, " · ") + " · " + detail
		}
		findings = append(findings, Finding{
			Title: title, Severity: "info", Target: r.Target, Service: "http",
			Detail: truncate(detail, 500),
			Fields: map[string]string{
				"status": fmt.Sprintf("%d", rec.HTTPStatus), "tech": strings.Join(techs, ", "),
				"server": server, "title": pageTitle, "cms": cms, "powered_by": poweredBy,
			},
		})
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// --- host/subdomain lists ---

// interestingSubdomain flags subdomains whose leftmost label suggests a
// sensitive or non-production surface worth prioritizing.
var interestingSubdomain = map[string]bool{
	"dev": true, "develop": true, "development": true, "staging": true, "stage": true,
	"test": true, "testing": true, "qa": true, "uat": true, "admin": true, "adminer": true,
	"api": true, "internal": true, "intranet": true, "vpn": true, "portal": true,
	"git": true, "gitlab": true, "jenkins": true, "jira": true, "db": true, "database": true,
	"backup": true, "old": true, "legacy": true, "beta": true, "demo": true, "secure": true,
	"mail": true, "webmail": true, "remote": true, "citrix": true, "owa": true, "phpmyadmin": true,
}

func parseHostList(out []byte, r Request) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		h := strings.TrimSpace(line)
		if h == "" || seen[h] || !hostName(h) {
			continue
		}
		seen[h] = true
		sev := "info"
		label := h
		if i := strings.IndexByte(h, '.'); i > 0 {
			label = h[:i]
		}
		if interestingSubdomain[strings.ToLower(label)] {
			sev = "low" // non-production / sensitive surface worth a look
		}
		findings = append(findings, Finding{
			Title: h, Severity: sev, Target: r.Target, Service: "subdomain",
			Fields: map[string]string{"subdomain": h, "label": label},
		})
		if len(findings) >= hostListCap { // bound results so a huge domain can't flood storage
			findings = append(findings, Finding{
				Title:    fmt.Sprintf("Results truncated at %d subdomains (refine the target or source list)", hostListCap),
				Severity: "info", Target: r.Target, Service: "subdomain",
			})
			break
		}
	}
	return findings
}

// hostListCap bounds subdomain enumeration output so a wildcard or heavily
// catalogued domain cannot flood the store/UI with thousands of rows.
const hostListCap = 2000

// --- tshark fields (tab-separated) ---

func parseTsharkFields(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		get := func(i int) string {
			if i < len(cols) {
				return strings.TrimSpace(cols[i])
			}
			return ""
		}
		src, dst, proto, port, info := get(1), get(2), get(3), get(4), get(5)
		title := fmt.Sprintf("%s -> %s %s", src, dst, proto)
		findings = append(findings, Finding{
			Title: title, Severity: "info", Target: r.Target, Service: proto, Port: port,
			Detail: info,
			Fields: map[string]string{"src_ip": src, "dst_ip": dst, "proto": proto, "dst_port": port},
		})
		if len(findings) >= 20000 {
			break
		}
	}
	return findings
}

// --- alive-host lists (fping) : one IP per line, feeds the asset inventory ---

func parseAliveHosts(out []byte, r Request) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		ip := strings.TrimSpace(line)
		// fping may append timing after the address; keep the first field.
		if i := strings.IndexByte(ip, ' '); i > 0 {
			ip = ip[:i]
		}
		if ip == "" || seen[ip] || net.ParseIP(ip) == nil {
			continue
		}
		seen[ip] = true
		findings = append(findings, Finding{
			Title: ip, Severity: "info", Target: ip, Service: "device", Detail: "host is up",
			Fields: map[string]string{"_kind": "host", "ip": ip, "status": "up"},
		})
	}
	return findings
}

// --- zmap: "saddr,sport" CSV with a header line ---

func parseZmap(out []byte, r Request) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "saddr") {
			continue
		}
		cols := strings.Split(line, ",")
		ip := strings.TrimSpace(cols[0])
		if net.ParseIP(ip) == nil {
			continue
		}
		port := ""
		if len(cols) > 1 {
			port = strings.TrimSpace(cols[1])
		}
		key := ip + ":" + port
		if seen[key] {
			continue
		}
		seen[key] = true
		title := ip
		if port != "" {
			title = fmt.Sprintf("%s:%s open", ip, port)
		}
		findings = append(findings, Finding{
			Title: title, Severity: "info", Target: ip, Port: port, Service: "open-port",
			Fields: map[string]string{"_kind": "host", "ip": ip, "port": port, "status": "up"},
		})
	}
	return findings
}

// --- smbmap share listing ---

func parseSmbmap(out []byte, r Request) []Finding {
	var findings []Finding
	inShares := false
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimRight(raw, "\r")
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		// Host/status lines from smbmap begin with a [+]/[!]/[*] marker.
		if strings.HasPrefix(t, "[+]") || strings.HasPrefix(t, "[!]") {
			msg := strings.TrimSpace(t[3:])
			low := strings.ToLower(msg)
			// Translate smbmap's internal errors into an actionable message
			// instead of surfacing "Something weird happened ... line 1015".
			if strings.Contains(low, "something weird") || strings.Contains(low, "error occurs while reading") ||
				strings.Contains(low, "traceback") || strings.Contains(low, "stackmap") {
				msg = "Could not enumerate shares (host refused anonymous access or closed the connection)"
			}
			findings = append(findings, Finding{
				Title: msg, Severity: "info", Target: r.Target, Service: "smb",
			})
			continue
		}
		low := strings.ToLower(t)
		if strings.HasPrefix(low, "disk") && strings.Contains(low, "permissions") {
			inShares = true
			continue
		}
		if strings.HasPrefix(t, "---") {
			continue
		}
		if !inShares {
			continue
		}
		// A real share row always carries a permission phrase; this skips
		// smbmap's spinner and status lines ("[|]", "Authenticating...").
		hasPerm := strings.Contains(low, "read") || strings.Contains(low, "write") || strings.Contains(low, "no access")
		if !hasPerm {
			continue
		}
		fields := strings.Fields(t)
		if len(fields) < 2 {
			continue
		}
		share := fields[0]
		sev := "info"
		switch {
		case strings.Contains(low, "read, write") || strings.Contains(low, "write only"):
			sev = "medium"
		case strings.Contains(low, "read only"):
			sev = "low"
		}
		findings = append(findings, Finding{
			Title: "Share: " + share, Severity: sev, Target: r.Target, Service: "smb",
			Detail: strings.TrimSpace(strings.TrimPrefix(t, share)),
			Fields: map[string]string{"share": share},
		})
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// --- testssl JSON ---

func parseTestssl(out []byte, r Request) []Finding {
	// testssl writes JSON to /dev/stdout but may fragment or concatenate it
	// with log text, so parse each top-level {...} object independently via
	// brace matching rather than assuming one clean array.
	type rec struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
		Finding  string `json:"finding"`
	}
	var findings []Finding
	for _, obj := range extractJSONObjects(out) {
		var rc rec
		if json.Unmarshal(obj, &rc) != nil || rc.ID == "" {
			continue
		}
		if rc.ID == "engine_problem" || rc.ID == "scanProblem" || rc.ID == "scanTime" || rc.ID == "service" {
			continue
		}
		sev := mapTestsslSeverity(rc.Severity)
		if sev == "" {
			continue // skip OK/INFO/DEBUG noise
		}
		findings = append(findings, Finding{
			Title: rc.ID + ": " + truncate(rc.Finding, 160), Severity: sev, Target: r.Target, Service: "tls",
			Detail: rc.Finding, Fields: map[string]string{"id": rc.ID, "testssl_severity": rc.Severity},
		})
	}
	if len(findings) == 0 {
		findings = append(findings, Finding{Title: "TLS scan completed; no weaknesses flagged", Severity: "info", Target: r.Target, Service: "tls"})
	}
	return findings
}

// extractJSONObjects returns each top-level {...} object in a byte stream using
// brace matching, ignoring braces inside strings. It tolerates fragmented or
// concatenated JSON (as some tools emit to /dev/stdout).
func extractJSONObjects(out []byte) [][]byte {
	var objs [][]byte
	depth := 0
	start := -1
	inStr := false
	esc := false
	for i := 0; i < len(out); i++ {
		c := out[i]
		if inStr {
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 && start >= 0 {
					objs = append(objs, out[start:i+1])
					start = -1
				}
			}
		}
	}
	return objs
}

func mapTestsslSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	case "WARN":
		return "low"
	}
	return "" // OK, INFO, DEBUG, etc.
}

// --- nbtscan: "IP   NETBIOS-NAME ..." feeds the asset inventory ---

func parseNbtscan(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 || net.ParseIP(f[0]) == nil {
			continue
		}
		ip, name := f[0], f[1]
		findings = append(findings, Finding{
			Title: ip + " (" + name + ")", Severity: "info", Target: ip, Service: "netbios",
			Detail: strings.Join(f[1:], " "),
			Fields: map[string]string{"_kind": "host", "ip": ip, "hostname": name, "status": "up"},
		})
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// --- naabu JSON port scan ---

func parseNaabu(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec struct {
			Host string `json:"host"`
			IP   string `json:"ip"`
			Port int    `json:"port"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		target := rec.IP
		if target == "" {
			target = rec.Host
		}
		findings = append(findings, Finding{
			Title: fmt.Sprintf("%d/tcp open", rec.Port), Severity: "info", Target: target,
			Port: fmt.Sprintf("%d", rec.Port), Service: "open-port",
			Fields: map[string]string{"host": rec.Host, "ip": rec.IP, "port": fmt.Sprintf("%d", rec.Port)},
		})
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// --- sslscan XML ---

func parseSslscanXML(out []byte, r Request) []Finding {
	start := bytes.IndexByte(out, '<')
	if start < 0 {
		return genericParse(out, r)
	}
	var doc struct {
		SSLTest []struct {
			Host    string `xml:"host,attr"`
			Port    string `xml:"port,attr"`
			Ciphers []struct {
				Status string `xml:"status,attr"`
				SSLV   string `xml:"sslversion,attr"`
				Bits   string `xml:"bits,attr"`
				Cipher string `xml:"cipher,attr"`
			} `xml:"cipher"`
			Certificate struct {
				Expired  string `xml:"expired"`
				NotAfter string `xml:"not-valid-after"`
			} `xml:"certificate"`
			Protocols []struct {
				Type    string `xml:"type,attr"`
				Version string `xml:"version,attr"`
				Enabled string `xml:"enabled,attr"`
			} `xml:"protocol"`
		} `xml:"ssltest"`
	}
	if xml.Unmarshal(out[start:], &doc) != nil {
		return genericParse(out, r)
	}
	var findings []Finding
	for _, t := range doc.SSLTest {
		for _, p := range t.Protocols {
			if p.Enabled != "1" {
				continue
			}
			sev := "info"
			name := strings.ToLower(p.Type) + p.Version
			if p.Type == "ssl" || p.Version == "1.0" || p.Version == "1.1" {
				sev = "medium"
			}
			findings = append(findings, Finding{
				Title: "Protocol enabled: " + name, Severity: sev, Target: t.Host, Port: t.Port, Service: "tls",
			})
		}
		for _, c := range t.Ciphers {
			if c.Status != "accepted" {
				continue
			}
			sev := "info"
			if c.SSLV == "SSLv2" || c.SSLV == "SSLv3" || c.SSLV == "TLSv1.0" {
				sev = "medium"
			}
			findings = append(findings, Finding{
				Title: "Cipher: " + c.Cipher + " (" + c.SSLV + ", " + c.Bits + " bit)", Severity: sev,
				Target: t.Host, Port: t.Port, Service: "tls",
			})
		}
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// --- wapiti JSON report ---

// sanitizeJSONControl replaces raw control bytes (which wapiti emits unescaped
// inside description strings, making the JSON invalid) with spaces. Outside
// strings these bytes are only whitespace, so structure is preserved.
func sanitizeJSONControl(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c < 0x20 && c != '\n' && c != '\t' || c == '\n' || c == '\t' || c == '\r' {
			out[i] = ' '
		} else {
			out[i] = c
		}
	}
	return out
}

func parseWapiti(out []byte, r Request) []Finding {
	type wapitiReport struct {
		Vulnerabilities map[string][]struct {
			Method    string `json:"method"`
			Path      string `json:"path"`
			Info      string `json:"info"`
			Level     int    `json:"level"`
			Parameter string `json:"parameter"`
		} `json:"vulnerabilities"`
	}
	// wapiti prints an ASCII banner before its JSON and log lines after it, so
	// take the first balanced {...} object that actually holds a
	// "vulnerabilities" map rather than slicing from the first brace to EOF
	// (which includes trailing logs and fails to parse, dumping raw output).
	var report wapitiReport
	found := false
	for _, obj := range extractJSONObjects(out) {
		var candidate wapitiReport
		if json.Unmarshal(sanitizeJSONControl(obj), &candidate) == nil && candidate.Vulnerabilities != nil {
			report = candidate
			found = true
			break
		}
	}
	if !found {
		// No report object parsed: say so cleanly instead of dumping the banner.
		return []Finding{{Title: "wapiti scan produced no parseable report", Severity: "info", Target: r.Target, Service: "http"}}
	}
	var findings []Finding
	for category, items := range report.Vulnerabilities {
		for _, it := range items {
			sev := "low"
			switch {
			case it.Level >= 3:
				sev = "high"
			case it.Level == 2:
				sev = "medium"
			}
			detail := it.Info
			if it.Parameter != "" {
				detail = "param " + it.Parameter + ": " + detail
			}
			findings = append(findings, Finding{
				Title: category + " at " + it.Path, Severity: sev, Target: r.Target, Service: "http",
				Detail: truncate(detail, 240),
				Fields: map[string]string{"category": category, "method": it.Method, "path": it.Path, "parameter": it.Parameter},
			})
		}
	}
	if len(findings) == 0 {
		findings = append(findings, Finding{Title: "wapiti scan completed; no vulnerabilities reported", Severity: "info", Target: r.Target, Service: "http"})
	}
	return findings
}

// --- nikto (text output: lines begin with "+ ") ---

func parseNikto(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		t := stripANSI(line)
		if !strings.HasPrefix(t, "+ ") {
			continue
		}
		msg := strings.TrimSpace(t[2:])
		if msg == "" {
			continue
		}
		low := strings.ToLower(msg)
		// Skip pure banner/preamble lines that carry no finding value.
		if strings.HasPrefix(low, "target ip") || strings.HasPrefix(low, "target hostname") ||
			strings.HasPrefix(low, "target port") || strings.HasPrefix(low, "start time") ||
			strings.HasPrefix(low, "end time") || strings.HasPrefix(low, "host(s) tested") ||
			strings.HasPrefix(low, "ssl info") || strings.HasPrefix(low, "nikto ") ||
			(strings.HasPrefix(low, "server:") && len(msg) < 10) {
			continue
		}
		sev := "low"
		if strings.Contains(low, "osvdb") || strings.Contains(low, "cve-") || strings.Contains(low, "vulnerab") ||
			strings.Contains(low, "injection") || strings.Contains(low, "xss") || strings.Contains(low, "disclosure") {
			sev = "medium"
		}
		findings = append(findings, Finding{Title: msg, Severity: sev, Target: r.Target, Service: "http"})
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// --- sqlmap (verbose text; keep verdicts, drop banner) ---

// sqlmapPrefixRe matches sqlmap's "[HH:MM:SS] [LEVEL] " log line prefix.
var sqlmapPrefixRe = regexp.MustCompile(`^\[\d{2}:\d{2}:\d{2}\]\s*\[[A-Z]+\]\s*`)

func stripSqlmapPrefix(s string) string {
	return strings.TrimSpace(sqlmapPrefixRe.ReplaceAllString(s, ""))
}

func parseSqlmap(out []byte, r Request) []Finding {
	var findings []Finding
	var block []string
	inResult := false
	flush := func() {
		if len(block) > 0 {
			findings = append(findings, Finding{
				Title: "SQL injection detected", Severity: "critical", Target: r.Target, Service: "http",
				Detail: strings.Join(block, " | "),
			})
			block = nil
		}
	}
	for _, line := range strings.Split(string(out), "\n") {
		t := stripANSI(line)
		if t == "" {
			continue
		}
		low := strings.ToLower(t)
		// Capture the injection report block ("Parameter: ... / Type: / Title: / Payload:").
		if strings.HasPrefix(t, "Parameter:") {
			flush()
			inResult = true
		}
		if inResult {
			if strings.HasPrefix(t, "Parameter:") || strings.HasPrefix(t, "Type:") ||
				strings.HasPrefix(t, "Title:") || strings.HasPrefix(t, "Payload:") {
				block = append(block, t)
				continue
			}
			if strings.HasPrefix(t, "---") {
				continue
			}
			inResult = false
			flush()
		}
		// Skip sqlmap's preliminary heuristic chatter; the definitive verdict
		// ("is injectable" / "not injectable") follows and is captured below.
		if strings.Contains(low, "heuristic") {
			continue
		}
		clean := stripSqlmapPrefix(t)
		// Notable single-line verdicts. Check negatives first so "not
		// injectable" is never mistaken for a positive result.
		negative := strings.Contains(low, "not injectable") || strings.Contains(low, "might not be injectable") ||
			strings.Contains(low, "do not appear to be injectable") || strings.Contains(low, "does not seem to be injectable")
		switch {
		case negative:
			findings = append(findings, Finding{Title: clean, Severity: "info", Target: r.Target, Service: "http"})
		case strings.Contains(low, "is vulnerable") || (strings.Contains(low, "parameter") && strings.Contains(low, "is injectable")):
			findings = append(findings, Finding{Title: clean, Severity: "critical", Target: r.Target, Service: "http"})
		case strings.Contains(low, "back-end dbms") || strings.Contains(low, "the following injection point"):
			findings = append(findings, Finding{Title: clean, Severity: "high", Target: r.Target, Service: "http"})
		case strings.Contains(low, "[warning]") && (strings.Contains(low, "waf") || strings.Contains(low, "protection")):
			findings = append(findings, Finding{Title: clean, Severity: "low", Target: r.Target, Service: "http"})
		}
	}
	flush()
	if len(findings) == 0 {
		findings = append(findings, Finding{Title: "sqlmap completed; no injection confirmed at this level/risk", Severity: "info", Target: r.Target, Service: "http"})
	}
	return findings
}

func firstNonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// ansiRe matches ANSI/VT control sequences (colors, cursor moves, line clears
// like "\x1b[2K") that CLI tools emit even in quiet mode.
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

func stripANSI(s string) string {
	s = ansiRe.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\r", "")
	// Some tools emit a bare "[2K" without the ESC prefix after \r stripping.
	s = strings.TrimPrefix(s, "[2K")
	return strings.TrimSpace(s)
}

// --- unicornscan ("TCP open <port> ... from <ip>") ---

var unicornOpenRe = regexp.MustCompile(`(?i)(TCP|UDP)\s+open\s+(?:\S+\s*\[?\s*)?(\d+)`)

func parseUnicornscan(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(stripANSI(line))
		m := unicornOpenRe.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		proto, port := strings.ToLower(m[1]), m[2]
		findings = append(findings, Finding{
			Title: fmt.Sprintf("%s/%s open", port, proto), Severity: "info", Target: r.Target,
			Port: port + "/" + proto, Service: "open-port", Detail: t,
			Fields: map[string]string{"port": port, "proto": proto},
		})
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// --- theHarvester (emails, hosts, IPs from its text report) ---

var emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

func parseTheHarvester(out []byte, r Request) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	section := ""
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(stripANSI(line))
		if t == "" {
			continue
		}
		low := strings.ToLower(t)
		switch {
		case strings.HasPrefix(low, "[*] emails found") || low == "emails:":
			section = "email"
			continue
		case strings.HasPrefix(low, "[*] hosts found") || low == "hosts:":
			section = "host"
			continue
		case strings.HasPrefix(low, "[*] ips found") || strings.HasPrefix(low, "[*] ip addresses"):
			section = "ip"
			continue
		case strings.HasPrefix(t, "---") || strings.HasPrefix(t, "==="):
			continue // separator under a section header; keep the section
		case strings.HasPrefix(t, "[*]") || strings.HasPrefix(t, "***"):
			section = "" // a different section/status line ends the current one
			continue
		}
		// Emails can appear anywhere; capture them regardless of section.
		if e := emailRe.FindString(t); e != "" && !seen["email:"+e] {
			seen["email:"+e] = true
			findings = append(findings, Finding{Title: "Email: " + e, Severity: "low", Target: r.Target, Service: "osint",
				Fields: map[string]string{"email": e}})
			continue
		}
		if section == "host" || section == "ip" {
			v := strings.Fields(t)[0]
			if (hostName(v) || net.ParseIP(v) != nil) && !seen[v] {
				seen[v] = true
				kind := "host"
				if net.ParseIP(v) != nil {
					kind = "ip"
				}
				findings = append(findings, Finding{Title: strings.Title(kind) + ": " + v, Severity: "info", Target: r.Target, Service: "osint",
					Fields: map[string]string{kind: v}})
			}
		}
		if len(findings) >= 5000 {
			break
		}
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// --- tcpdump interface capture (decode each line into a packet finding) ---

func parseTcpdumpText(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		p, ok := parseTcpdump(line)
		if !ok {
			continue
		}
		title := p.SrcIP
		if p.DstIP != "" {
			title = p.SrcIP + " → " + p.DstIP
		}
		findings = append(findings, Finding{
			Title: title, Severity: "info", Target: r.Target, Service: p.Protocol, Port: p.DstPort,
			Detail: p.Info,
			Fields: map[string]string{"src_ip": p.SrcIP, "dst_ip": p.DstIP, "proto": p.Protocol,
				"src_port": p.SrcPort, "dst_port": p.DstPort, "src_mac": p.SrcMAC, "dst_mac": p.DstMAC},
		})
		if len(findings) >= 20000 {
			break
		}
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// --- onesixtyone (SNMP community scanner: "<ip> [community] sysDescr") ---

var onesixtyoneRe = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+\[([^\]]+)\]\s*(.*)$`)

func parseOnesixtyone(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(stripANSI(line))
		if t == "" {
			continue
		}
		m := onesixtyoneRe.FindStringSubmatch(t)
		if m == nil {
			continue // skip the "Scanning N hosts" progress line
		}
		ip, community, descr := m[1], m[2], strings.TrimSpace(m[3])
		// A valid SNMP community is a real exposure; default strings worse.
		sev := "medium"
		lc := strings.ToLower(community)
		if lc == "public" || lc == "private" || lc == "community" {
			sev = "high"
		}
		findings = append(findings, Finding{
			Title: fmt.Sprintf("SNMP community '%s' valid on %s", community, ip), Severity: sev,
			Target: ip, Service: "snmp", Detail: descr,
			Fields: map[string]string{"ip": ip, "community": community, "sysdescr": descr},
		})
	}
	if len(findings) == 0 {
		findings = append(findings, Finding{Title: "No SNMP community strings accepted", Severity: "info", Target: r.Target, Service: "snmp"})
	}
	return findings
}

// --- snmpwalk (translate common OIDs to readable names) ---

// snmpOIDNames maps well-known SNMPv2-MIB/IF-MIB OID prefixes to labels so a
// numeric walk reads meaningfully even without MIBs installed.
var snmpOIDNames = map[string]string{
	"1.3.6.1.2.1.1.1":        "sysDescr",
	"1.3.6.1.2.1.1.2":        "sysObjectID",
	"1.3.6.1.2.1.1.3":        "sysUpTime",
	"1.3.6.1.2.1.1.4":        "sysContact",
	"1.3.6.1.2.1.1.5":        "sysName",
	"1.3.6.1.2.1.1.6":        "sysLocation",
	"1.3.6.1.2.1.1.7":        "sysServices",
	"1.3.6.1.2.1.2.2.1.2":    "ifDescr",
	"1.3.6.1.2.1.2.2.1.6":    "ifPhysAddress",
	"1.3.6.1.2.1.25.1.1":     "hrSystemUptime",
	"1.3.6.1.2.1.25.4.2.1.2": "hrSWRunName",
}

var snmpLineRe = regexp.MustCompile(`^\.?([0-9.]+?)(?:\.\d+)?\s*=\s*(?:[A-Za-z0-9-]+:\s*)?(.*)$`)

func parseSnmpwalk(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(stripANSI(line))
		if t == "" {
			continue
		}
		low := strings.ToLower(t)
		if strings.Contains(low, "timeout") || strings.Contains(low, "no response") {
			findings = append(findings, Finding{Title: t, Severity: "info", Target: r.Target, Service: "snmp"})
			continue
		}
		m := snmpLineRe.FindStringSubmatch(t)
		if m == nil {
			findings = append(findings, Finding{Title: truncate(t, 200), Severity: "info", Target: r.Target, Service: "snmp"})
			continue
		}
		oid, val := m[1], strings.Trim(strings.TrimSpace(m[2]), `"`)
		label := snmpLabel(oid)
		title := val
		sev := "info"
		if label != "" {
			title = label + ": " + val
			// System identity values leaked anonymously are worth noting.
			if label == "sysDescr" || label == "sysName" || label == "sysContact" || label == "sysLocation" {
				sev = "low"
			}
		} else {
			title = oid + " = " + val
		}
		findings = append(findings, Finding{
			Title: truncate(title, 220), Severity: sev, Target: r.Target, Service: "snmp",
			Fields: map[string]string{"oid": oid, "name": label, "value": val},
		})
		if len(findings) >= 5000 {
			break
		}
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// snmpLabel returns the known name for an OID, matching the longest known prefix.
func snmpLabel(oid string) string {
	if n, ok := snmpOIDNames[oid]; ok {
		return n
	}
	for prefix, name := range snmpOIDNames {
		if strings.HasPrefix(oid, prefix+".") || oid == prefix {
			return name
		}
	}
	return ""
}

// --- whois (extract key registration fields; flag imminent expiry) ---

func parseWhois(out []byte, r Request) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(stripANSI(line))
		if t == "" || strings.HasPrefix(t, "%") || strings.HasPrefix(t, ">>>") || strings.HasPrefix(t, "NOTICE") || strings.HasPrefix(t, "TERMS") {
			continue
		}
		i := strings.Index(t, ":")
		if i <= 0 {
			continue
		}
		key := strings.TrimSpace(t[:i])
		val := strings.TrimSpace(t[i+1:])
		if val == "" {
			continue
		}
		lk := strings.ToLower(key)
		keep := false
		sev := "info"
		switch {
		case strings.Contains(lk, "registrar") && !strings.Contains(lk, "url") && !strings.Contains(lk, "whois") && !strings.Contains(lk, "abuse"):
			keep = true
		case strings.Contains(lk, "creation date") || lk == "created" || strings.Contains(lk, "registered on"):
			keep = true
		case strings.Contains(lk, "updated date"):
			keep = true
		case strings.Contains(lk, "expir"):
			keep = true
			if daysUntil(val) >= 0 && daysUntil(val) < 30 {
				sev = "medium" // domain expiring soon
			}
		case strings.Contains(lk, "name server") || lk == "nserver":
			keep = true
		case strings.Contains(lk, "domain status") || lk == "status":
			keep = true
		case lk == "registrant organization" || lk == "org" || lk == "registrant":
			keep = true
		}
		if !keep {
			continue
		}
		dedup := key + "=" + val
		if seen[dedup] {
			continue
		}
		seen[dedup] = true
		findings = append(findings, Finding{
			Title: key + ": " + val, Severity: sev, Target: r.Target, Service: "whois",
			Fields: map[string]string{"field": key, "value": val},
		})
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// daysUntil parses an RFC3339-ish date and returns days from now, or -1.
func daysUntil(s string) int {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02", "02-Jan-2006"} {
		if tm, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return int(time.Until(tm).Hours() / 24)
		}
	}
	return -1
}

// --- traceroute (keep responding hops, drop timeouts and header) ---

var tracerouteHopRe = regexp.MustCompile(`^\s*(\d+)\s+(.*)$`)
var tracerouteIPRe = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)

func parseTraceroute(out []byte, r Request) []Finding {
	var findings []Finding
	hops, responded := 0, 0
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(stripANSI(line))
		if t == "" || strings.HasPrefix(t, "traceroute to") {
			continue
		}
		m := tracerouteHopRe.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		hops++
		rest := m[2]
		// A hop that only timed out shows "* * *".
		if !tracerouteIPRe.MatchString(rest) {
			continue
		}
		responded++
		ip := tracerouteIPRe.FindString(rest)
		findings = append(findings, Finding{
			Title: "Hop " + m[1] + ": " + ip, Severity: "info", Target: r.Target, Service: "route",
			Detail: rest, Fields: map[string]string{"hop": m[1], "ip": ip},
		})
	}
	// Prepend a concise summary.
	summary := Finding{
		Title:    fmt.Sprintf("Traceroute to %s: %d hops, %d responded", r.Target, hops, responded),
		Severity: "info", Target: r.Target, Service: "route",
	}
	if len(findings) == 0 {
		summary.Detail = "no intermediate hops responded (path filters probes)"
		return []Finding{summary}
	}
	return append([]Finding{summary}, findings...)
}

// --- ffuf JSON results (extracted via brace matching; banner is ignored) ---

func parseFfuf(out []byte, r Request) []Finding {
	var findings []Finding
	for _, obj := range extractJSONObjects(out) {
		var doc struct {
			Results []struct {
				Input  map[string]string `json:"input"`
				URL    string            `json:"url"`
				Status int               `json:"status"`
				Length int               `json:"length"`
			} `json:"results"`
		}
		if json.Unmarshal(obj, &doc) != nil || len(doc.Results) == 0 {
			continue
		}
		for _, res := range doc.Results {
			path := res.Input["FUZZ"]
			sev := "info"
			switch {
			case res.Status >= 200 && res.Status < 400:
				sev = "low"
			case res.Status == 401 || res.Status == 403:
				sev = "medium"
			}
			findings = append(findings, Finding{
				Title: firstNonEmptyStr(path, res.URL), Severity: sev, Target: r.Target, Service: "http-path",
				Detail: fmt.Sprintf("status %d, size %d", res.Status, res.Length),
				Fields: map[string]string{"path": path, "url": res.URL, "status": fmt.Sprintf("%d", res.Status), "size": fmt.Sprintf("%d", res.Length)},
			})
		}
		break
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// --- gobuster directory results ---

var gobusterRe = regexp.MustCompile(`^(/\S*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?(?:\s+\[-->\s*([^\]]+)\])?`)

func parseGobuster(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		t := stripANSI(line)
		if t == "" {
			continue
		}
		m := gobusterRe.FindStringSubmatch(t)
		if m == nil {
			continue
		}
		path, status, size, redir := m[1], m[2], m[3], m[4]
		sev := "info"
		switch status {
		case "200", "301", "302", "307":
			sev = "low"
		case "401", "403":
			sev = "medium" // exists but protected, worth noting
		}
		detail := "status " + status
		if size != "" {
			detail += ", size " + size
		}
		if redir != "" {
			detail += " → " + redir
		}
		findings = append(findings, Finding{
			Title: path, Severity: sev, Target: r.Target, Service: "http-path", Detail: detail,
			Fields: map[string]string{"path": path, "status": status, "size": size, "redirect": redir},
		})
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// --- wafw00f WAF detection ---

func parseWafw00f(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		t := stripANSI(line)
		low := strings.ToLower(t)
		// The meaningful lines contain a verdict; everything else is banner art.
		if strings.Contains(low, "is behind") {
			findings = append(findings, Finding{
				Title: t, Severity: "low", Target: r.Target, Service: "waf", Detail: "WAF detected",
			})
		} else if strings.Contains(low, "no waf detected") || strings.Contains(low, "seems to be behind a waf") || strings.Contains(low, "generic detection") {
			findings = append(findings, Finding{
				Title: t, Severity: "info", Target: r.Target, Service: "waf",
			})
		} else if strings.Contains(low, "number of requests") {
			findings = append(findings, Finding{Title: t, Severity: "info", Target: r.Target, Service: "waf"})
		}
	}
	if len(findings) == 0 {
		findings = append(findings, Finding{Title: "No WAF detected", Severity: "info", Target: r.Target, Service: "waf"})
	}
	return findings
}

// --- katana crawl (JSONL with nested request.endpoint) ---

func parseKatana(out []byte, r Request) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec struct {
			Request struct {
				Method   string `json:"method"`
				Endpoint string `json:"endpoint"`
			} `json:"request"`
			Response struct {
				StatusCode int    `json:"status_code"`
				Title      string `json:"title"`
			} `json:"response"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil || rec.Request.Endpoint == "" {
			continue
		}
		if seen[rec.Request.Endpoint] {
			continue
		}
		seen[rec.Request.Endpoint] = true
		detail := ""
		if rec.Response.StatusCode != 0 {
			detail = fmt.Sprintf("status %d", rec.Response.StatusCode)
		}
		if rec.Response.Title != "" {
			detail += " · " + rec.Response.Title
		}
		findings = append(findings, Finding{
			Title: rec.Request.Endpoint, Severity: "info", Target: r.Target, Service: "endpoint",
			Detail: strings.TrimSpace(detail),
			Fields: map[string]string{"url": rec.Request.Endpoint, "method": rec.Request.Method,
				"status": fmt.Sprintf("%d", rec.Response.StatusCode)},
		})
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// parseDnstwist parses dnstwist JSON (array or JSONL), reporting registered
// lookalike/typosquat domains (those that resolve) as low-severity findings.
func parseDnstwist(out []byte, r Request) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	for _, obj := range extractJSONObjects(out) {
		var rec struct {
			Domain string   `json:"domain"`
			Fuzzer string   `json:"fuzzer"`
			DNSA   []string `json:"dns_a"`
			DNSMX  []string `json:"dns_mx"`
			DNSNS  []string `json:"dns_ns"`
		}
		if json.Unmarshal(obj, &rec) != nil || rec.Domain == "" || seen[rec.Domain] {
			continue
		}
		seen[rec.Domain] = true
		// Skip the original domain itself; it is not a lookalike.
		if rec.Domain == r.Target || strings.EqualFold(rec.Fuzzer, "original") || strings.Contains(strings.ToLower(rec.Fuzzer), "*original*") {
			continue
		}
		registered := len(rec.DNSA) > 0 || len(rec.DNSMX) > 0 || len(rec.DNSNS) > 0
		sev := "info"
		detail := rec.Fuzzer
		if registered {
			sev = "low" // a resolving lookalike is a potential phishing domain
			if len(rec.DNSA) > 0 {
				detail += " · A=" + strings.Join(rec.DNSA, ",")
			}
			if len(rec.DNSMX) > 0 {
				detail += " · has MX"
			}
		}
		findings = append(findings, Finding{
			Title: rec.Domain, Severity: sev, Target: r.Target, Service: "lookalike",
			Detail: strings.TrimSpace(detail),
			Fields: map[string]string{"domain": rec.Domain, "fuzzer": rec.Fuzzer, "registered": fmt.Sprintf("%v", registered)},
		})
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

// parseTsharkRich decodes tshark field output (the same layout the live
// capture engine uses) into findings, surfacing DNS queries, TLS SNI, and
// HTTP hosts so a pcap analysis reads like Wireshark.
func parseTsharkRich(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		p, ok := parseLive(line)
		if !ok {
			continue
		}
		info := p.Info
		svc := p.Protocol
		switch {
		case p.SNI != "":
			info = "TLS SNI: " + p.SNI + spacePrefix(info)
		case p.DNSQuery != "":
			info = "DNS: " + p.DNSQuery + spacePrefix(info)
		case p.HTTPHost != "":
			info = "HTTP host: " + p.HTTPHost + spacePrefix(info)
		}
		title := p.SrcIP
		if p.DstIP != "" {
			title = p.SrcIP + " → " + p.DstIP
		}
		fields := map[string]string{
			"src_ip": p.SrcIP, "dst_ip": p.DstIP, "proto": p.Protocol,
			"src_port": p.SrcPort, "dst_port": p.DstPort,
		}
		if p.SNI != "" {
			fields["sni"] = p.SNI
		}
		if p.DNSQuery != "" {
			fields["dns_query"] = p.DNSQuery
		}
		if p.HTTPHost != "" {
			fields["http_host"] = p.HTTPHost
		}
		findings = append(findings, Finding{
			Title: title, Severity: "info", Target: r.Target, Service: svc, Port: p.DstPort,
			Detail: strings.TrimSpace(info), Fields: fields,
		})
		if len(findings) >= 20000 {
			break
		}
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

func spacePrefix(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return " · " + s
}

func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
