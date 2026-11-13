package recon

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Native, passive OSINT connectors folded in from the osint-recon-dashboard
// project. They need no external binary and only query public data or the
// target's own published records. They still pass the authorization gate.
func init() {
	register(&Connector{
		Name: "crtsh", Binary: "", Category: CatDNS, TargetKind: TgtDomain,
		Desc:     "Certificate Transparency subdomain discovery via crt.sh (passive).",
		Profiles: []Profile{{"subdomains", "Find subdomains from CT logs"}},
		native:   crtshCollect,
	})
	register(&Connector{
		Name: "dns-records", Binary: "", Category: CatDNS, TargetKind: TgtDomain,
		Desc:     "Resolve A, AAAA, MX, NS, and TXT records (passive).",
		Profiles: []Profile{{"all", "All common record types"}},
		native:   dnsCollect,
	})
	register(&Connector{
		Name: "tls-cert", Binary: "", Category: CatTLS, TargetKind: TgtHost,
		Desc:     "Inspect a server's TLS certificate: issuer, SANs, and expiry.",
		Profiles: []Profile{{"inspect", "Read the presented certificate"}},
		native:   tlsCollect,
	})
	register(&Connector{
		Name: "rdap", Binary: "", Category: CatOSINT, TargetKind: TgtDomain,
		Desc:     "Registration data (RDAP) for a domain (passive).",
		Profiles: []Profile{{"lookup", "Query the RDAP bootstrap service"}},
		native:   rdapCollect,
	})
}

// OSINT services such as crt.sh can be slow, so allow a generous timeout; the
// scan's own context still bounds the overall run.
var httpClient = &http.Client{Timeout: 90 * time.Second}

func crtshCollect(ctx context.Context, r Request) ([]Finding, error) {
	url := "https://crt.sh/?q=%25." + r.Target + "&output=json"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "daru-recon")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	type certRec struct {
		NameValue string `json:"name_value"`
		Issuer    string `json:"issuer_name"`
	}
	var records []certRec
	trimmed := strings.TrimSpace(string(body))
	if err := json.Unmarshal([]byte(trimmed), &records); err != nil {
		// crt.sh sometimes returns newline-delimited objects rather than an
		// array. Parse line by line as a fallback.
		records = nil
		for _, line := range strings.Split(trimmed, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "{") {
				continue
			}
			var one certRec
			if json.Unmarshal([]byte(strings.TrimSuffix(line, ",")), &one) == nil {
				records = append(records, one)
			}
		}
		if len(records) == 0 {
			if strings.HasPrefix(trimmed, "<") {
				return nil, fmt.Errorf("crt.sh is rate-limiting or returned HTML; try again shortly")
			}
			return nil, fmt.Errorf("crt.sh returned unexpected data")
		}
	}
	seen := map[string]bool{}
	var findings []Finding
	for _, rec := range records {
		for _, name := range strings.Split(rec.NameValue, "\n") {
			name = strings.TrimSpace(strings.TrimPrefix(name, "*."))
			if name == "" || seen[name] || !hostName(name) {
				continue
			}
			seen[name] = true
			findings = append(findings, Finding{
				Title: name, Severity: "info", Target: r.Target,
				Detail: "from CT log", Fields: map[string]string{"subdomain": name},
			})
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Title < findings[j].Title })
	if len(findings) == 0 {
		findings = append(findings, Finding{Title: "No subdomains found in CT logs", Severity: "info", Target: r.Target})
	}
	return findings, nil
}

// dnsxRun runs the ProjectDiscovery dnsx binary (feeding the domain on stdin)
// when it is installed and actually resolves, and otherwise falls back to
// Daru's native resolver, so DNS resolution always returns results.
func dnsxRun(ctx context.Context, r Request) ([]Finding, error) {
	if bin := resolveBinary("dnsx"); bin != "" {
		cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		cmd := exec.CommandContext(cctx, bin, "-json", "-silent", "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-resp")
		cmd.Stdin = strings.NewReader(r.Target + "\n")
		var buf bytes.Buffer
		cmd.Stdout = capWriter(&buf, MaxToolOutputBytes)
		_ = cmd.Run()
		out := buf.Bytes()
		cancel()
		// dnsx emits one merged JSON object per name, with each record type as a
		// JSON array. Expand those arrays into individual findings so the result
		// is as detailed as the native resolver (A/AAAA/CNAME/MX/NS/TXT each
		// listed), rather than a single near-empty host record.
		if f := parseDnsx(out, r); len(f) > 0 {
			return f, nil
		}
	}
	// Binary absent or could not resolve: native resolver.
	return dnsCollect(ctx, r)
}

func dnsCollect(ctx context.Context, r Request) ([]Finding, error) {
	res := &net.Resolver{}
	var findings []Finding
	add := func(kind, val string) {
		findings = append(findings, Finding{
			Title: kind + " " + val, Severity: "info", Target: r.Target, Service: kind,
			Fields: map[string]string{"record_type": kind, "value": val},
		})
	}
	if ips, err := res.LookupIPAddr(ctx, r.Target); err == nil {
		for _, ip := range ips {
			kind := "A"
			if ip.IP.To4() == nil {
				kind = "AAAA"
			}
			add(kind, ip.IP.String())
		}
	}
	if mxs, err := res.LookupMX(ctx, r.Target); err == nil {
		for _, mx := range mxs {
			add("MX", fmt.Sprintf("%d %s", mx.Pref, strings.TrimSuffix(mx.Host, ".")))
		}
	}
	if nss, err := res.LookupNS(ctx, r.Target); err == nil {
		for _, ns := range nss {
			add("NS", strings.TrimSuffix(ns.Host, "."))
		}
	}
	if txts, err := res.LookupTXT(ctx, r.Target); err == nil {
		for _, txt := range txts {
			sev := "info"
			if strings.Contains(txt, "v=spf1") || strings.HasPrefix(txt, "v=DMARC1") {
				sev = "low"
			}
			findings = append(findings, Finding{Title: "TXT " + truncate(txt, 120), Severity: sev, Target: r.Target, Service: "TXT",
				Fields: map[string]string{"record_type": "TXT", "value": txt}})
		}
	}
	if len(findings) == 0 {
		return nil, fmt.Errorf("no DNS records resolved for %s", r.Target)
	}
	return findings, nil
}

func tlsCollect(ctx context.Context, r Request) ([]Finding, error) {
	host := r.Target
	port := "443"
	if r.Ports != "" && validPorts(r.Ports) {
		port = r.Ports
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, port), &tls.Config{InsecureSkipVerify: true, ServerName: host})
	if err != nil {
		return nil, fmt.Errorf("TLS connect failed: %w", err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("server presented no certificate")
	}
	cert := state.PeerCertificates[0]
	var findings []Finding
	findings = append(findings, Finding{
		Title: "Subject: " + cert.Subject.CommonName, Severity: "info", Target: host, Service: "tls",
		Detail: "Issuer: " + cert.Issuer.CommonName,
		Fields: map[string]string{"subject": cert.Subject.CommonName, "issuer": cert.Issuer.CommonName,
			"tls_version": tlsVersion(state.Version)},
	})
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	sev := "info"
	if daysLeft < 0 {
		sev = "high"
	} else if daysLeft < 15 {
		sev = "medium"
	} else if daysLeft < 30 {
		sev = "low"
	}
	findings = append(findings, Finding{
		Title: fmt.Sprintf("Certificate expires in %d days", daysLeft), Severity: sev, Target: host, Service: "tls",
		Detail: cert.NotAfter.Format("2006-01-02"), Fields: map[string]string{"not_after": cert.NotAfter.Format(time.RFC3339)},
	})
	for _, san := range cert.DNSNames {
		findings = append(findings, Finding{Title: "SAN: " + san, Severity: "info", Target: host, Service: "tls",
			Fields: map[string]string{"san": san}})
	}
	return findings, nil
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return "unknown"
}

func rdapCollect(ctx context.Context, r Request) ([]Finding, error) {
	url := "https://rdap.org/domain/" + r.Target
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "daru-recon")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RDAP request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return []Finding{{Title: "No RDAP record for " + r.Target, Severity: "info", Target: r.Target}}, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var data struct {
		Handle string   `json:"handle"`
		Status []string `json:"status"`
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
		Nameservers []struct {
			LDHName string `json:"ldhName"`
		} `json:"nameservers"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("RDAP returned unexpected data")
	}
	var findings []Finding
	if data.Handle != "" {
		findings = append(findings, Finding{Title: "Registry handle: " + data.Handle, Severity: "info", Target: r.Target})
	}
	for _, e := range data.Events {
		findings = append(findings, Finding{Title: e.Action + ": " + e.Date, Severity: "info", Target: r.Target, Service: "rdap"})
	}
	if len(data.Status) > 0 {
		findings = append(findings, Finding{Title: "Status: " + strings.Join(data.Status, ", "), Severity: "info", Target: r.Target})
	}
	for _, ns := range data.Nameservers {
		findings = append(findings, Finding{Title: "Nameserver: " + ns.LDHName, Severity: "info", Target: r.Target, Service: "rdap",
			Fields: map[string]string{"nameserver": ns.LDHName}})
	}
	if len(findings) == 0 {
		findings = append(findings, Finding{Title: "RDAP record found but empty", Severity: "info", Target: r.Target})
	}
	return findings, nil
}
