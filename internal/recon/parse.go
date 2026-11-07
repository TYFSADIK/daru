package recon

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
)

// --- nmap XML ---

type nmapRun struct {
	Hosts []struct {
		Status struct {
			State string `xml:"state,attr"`
		} `xml:"status"`
		Address []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
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
		addr := ""
		for _, a := range h.Address {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				addr = a.Addr
			}
		}
		host := addr
		if len(h.Hostnames.Hostname) > 0 {
			host = h.Hostnames.Hostname[0].Name
		}
		if h.Status.State == "up" && len(h.Ports.Port) == 0 {
			findings = append(findings, Finding{Title: "Host up: " + host, Severity: "info", Target: addr})
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
		title := firstStr(obj, "url", "host", "input", "name", "domain", "fqdn")
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

func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
