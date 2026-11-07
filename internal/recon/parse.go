package recon

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"strings"
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
			fields := map[string]string{"_kind": "host", "ip": addr, "mac": mac, "vendor": vendor,
				"hostname": hostname, "os": osName, "ports": strings.Join(openPorts, ",")}
			detail := strings.TrimSpace(vendor + " " + osName)
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

// --- host/subdomain lists ---

func parseHostList(out []byte, r Request) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		h := strings.TrimSpace(line)
		if h == "" || seen[h] || !hostName(h) {
			continue
		}
		seen[h] = true
		findings = append(findings, Finding{
			Title: h, Severity: "info", Target: r.Target,
			Fields: map[string]string{"subdomain": h},
		})
	}
	return findings
}

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
			findings = append(findings, Finding{
				Title: strings.TrimSpace(t[3:]), Severity: "info", Target: r.Target, Service: "smb",
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
	// testssl emits a JSON array of {id, ip, port, severity, finding}.
	start := bytes.IndexByte(out, '[')
	if start < 0 {
		return genericParse(out, r)
	}
	var recs []struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
		Finding  string `json:"finding"`
	}
	if json.Unmarshal(out[start:], &recs) != nil {
		return genericParse(out, r)
	}
	var findings []Finding
	for _, rec := range recs {
		sev := mapTestsslSeverity(rec.Severity)
		if sev == "" {
			continue // skip OK/INFO/DEBUG noise
		}
		findings = append(findings, Finding{
			Title: rec.ID + ": " + truncate(rec.Finding, 160), Severity: sev, Target: r.Target, Service: "tls",
			Detail: rec.Finding, Fields: map[string]string{"id": rec.ID, "testssl_severity": rec.Severity},
		})
	}
	if len(findings) == 0 {
		findings = append(findings, Finding{Title: "TLS scan completed; no weaknesses flagged", Severity: "info", Target: r.Target, Service: "tls"})
	}
	return findings
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

// --- nikto JSON ---

func parseNikto(out []byte, r Request) []Finding {
	start := bytes.IndexByte(out, '{')
	arrStart := bytes.IndexByte(out, '[')
	if arrStart >= 0 && (start < 0 || arrStart < start) {
		start = arrStart
	}
	if start < 0 {
		return genericParse(out, r)
	}
	trimmed := bytes.TrimSpace(out[start:])
	type vuln struct {
		ID     string `json:"id"`
		URL    string `json:"url"`
		Method string `json:"method"`
		Msg    string `json:"msg"`
	}
	collect := func(host string, vs []vuln) []Finding {
		var fs []Finding
		for _, v := range vs {
			fs = append(fs, Finding{
				Title: truncate(v.Msg, 200), Severity: "low", Target: firstNonEmptyStr(host, r.Target),
				Detail: v.URL, Fields: map[string]string{"id": v.ID, "method": v.Method, "url": v.URL},
			})
		}
		return fs
	}
	var findings []Finding
	// Nikto JSON can be a single object or an array of host objects.
	parseOne := func(b []byte) bool {
		var obj struct {
			Host  string `json:"host"`
			IP    string `json:"ip"`
			Vulns []vuln `json:"vulnerabilities"`
		}
		if json.Unmarshal(b, &obj) != nil {
			return false
		}
		findings = append(findings, collect(firstNonEmptyStr(obj.Host, obj.IP), obj.Vulns)...)
		return true
	}
	if trimmed[0] == '[' {
		var arr []json.RawMessage
		if json.Unmarshal(trimmed, &arr) == nil {
			for _, m := range arr {
				parseOne(m)
			}
		}
	} else {
		parseOne(trimmed)
	}
	if len(findings) == 0 {
		return genericParse(out, r)
	}
	return findings
}

func firstNonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
