package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// New connectors added after the hard audit: fast port scanning, XSS and
// WordPress scanning, subdomain and URL discovery, crawling, and secret
// scanning. Every connector stays behind the same authorization gate and
// scope guard, and every parser is bounded by the central MaxFindings cap
// in runParse.
func init() {
	register(&Connector{
		Name: "rustscan", Binary: "rustscan", Category: CatPortScan, TargetKind: TgtCIDR,
		Desc:     "Fast port scanner (Rust, wraps nmap for service detection).",
		Profiles: []Profile{{"quick", "Ports 1-1000"}, {"full", "All 65535 ports"}, {"custom", "Use the ports field"}},
		build: func(c *Connector, r Request) ([]string, error) {
			rng := "1-1000"
			switch profileOr(c, r.Profile) {
			case "full":
				rng = "1-65535"
			case "custom":
				if !validPorts(r.Ports) || r.Ports == "" {
					return nil, fmt.Errorf("provide ports for the custom profile")
				}
				rng = r.Ports
			}
			return []string{"-a", r.Target, "-r", rng, "--ulimit", "5000", "-g", "--", "-Pn", "-sV"}, nil
		},
		parse:  parseRustscan,
		verify: verifyName("rustscan"),
	})

	register(&Connector{
		Name: "dalfox", Binary: "dalfox", Category: CatVulnScan, TargetKind: TgtURL,
		Desc:     "XSS scanner (parameter analysis, blind XSS, DOM XSS).",
		Profiles: []Profile{{"default", "Standard XSS scan"}, {"blind", "Include blind XSS callbacks"}},
		build: func(c *Connector, r Request) ([]string, error) {
			args := []string{"url", r.Target, "--silence", "--format", "json"}
			if profileOr(c, r.Profile) == "blind" {
				args = append(args, "--blind", "https://example.invalid")
			}
			return args, nil
		},
		parse:  parseDalfox,
		verify: verifyName("dalfox"),
	})

	register(&Connector{
		Name: "wpscan", Binary: "wpscan", Category: CatVulnScan, TargetKind: TgtURL,
		Desc:     "WordPress vulnerability scanner (core, plugins, themes).",
		Profiles: []Profile{{"default", "Passive enumeration"}, {"aggressive", "Aggressive plugin enumeration"}},
		build: func(c *Connector, r Request) ([]string, error) {
			args := []string{"--url", r.Target, "--format", "json", "--no-update"}
			if profileOr(c, r.Profile) == "aggressive" {
				args = append(args, "--enumerate", "ap")
			}
			return args, nil
		},
		parse:  parseWpscan,
		verify: verifyName("wpscan"),
	})

	register(&Connector{
		Name: "assetfinder", Binary: "assetfinder", Category: CatDNS, TargetKind: TgtDomain,
		Desc:     "Subdomain discovery from public sources.",
		Profiles: []Profile{{"subs", "Subdomains only"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"--subs-only", r.Target}, nil
		},
		parse:  parseHostList,
		verify: verifyName("assetfinder"),
	})

	register(&Connector{
		Name: "waybackurls", Binary: "waybackurls", Category: CatWebScan, TargetKind: TgtDomain,
		Desc:     "URL discovery from the Wayback Machine.",
		Profiles: []Profile{{"urls", "Known URLs for the domain"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{r.Target}, nil
		},
		parse:  parseURLList,
		verify: verifyName("waybackurls"),
	})

	register(&Connector{
		Name: "gau", Binary: "gau", Category: CatWebScan, TargetKind: TgtDomain,
		Desc:     "URL discovery from AlienVault, Wayback, Common Crawl, and URLScan.",
		Profiles: []Profile{{"urls", "Known URLs, including subdomains"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"--subs", r.Target}, nil
		},
		parse:  parseURLList,
		verify: verifyName("gau"),
	})

	register(&Connector{
		Name: "hakrawler", Binary: "hakrawler", Category: CatWebScan, TargetKind: TgtURL,
		Desc:     "Web crawler that lists endpoints, forms, and JavaScript files.",
		Profiles: []Profile{{"crawl", "Crawl links, forms, and scripts"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-url", r.Target, "-plain", "-depth", "2"}, nil
		},
		parse:  parseURLList,
		verify: verifyName("hakrawler"),
	})

	register(&Connector{
		Name: "trufflehog", Binary: "trufflehog", Category: CatVulnScan, TargetKind: TgtURL,
		Desc:     "Secret scanning of a git repository (verified findings only).",
		Profiles: []Profile{{"verified", "Only verified secrets"}, {"all", "All candidate secrets"}},
		build: func(c *Connector, r Request) ([]string, error) {
			args := []string{"git", r.Target, "--json", "--no-update"}
			if profileOr(c, r.Profile) != "all" {
				args = append(args, "--only-verified")
			}
			return args, nil
		},
		parse:  parseTrufflehog,
		verify: verifyName("trufflehog"),
	})

	// Posture aggregates the MITRE ATT&CK coverage of every registered
	// connector into one finding per tactic, so the dashboard can show
	// which tactics Daru can test for. It needs no target and runs no tool.
	register(&Connector{
		Name: "posture", Binary: "", Category: CatVulnScan, TargetKind: TgtNone,
		AllowEmptyTarget: true,
		Desc:             "MITRE ATT&CK posture summary: aggregates registered connectors by tactic and technique.",
		Profiles:         []Profile{{"summary", "One finding per MITRE tactic"}},
		native:           postureCollect,
	})
}

var rustscanLineRe = regexp.MustCompile(`(?i)^open\s+(\S+):(\d+)\s*$`)

// parseRustscan reads rustscan grepable output ("Open 10.0.0.1:80").
func parseRustscan(out []byte, r Request) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		m := rustscanLineRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		key := m[1] + ":" + m[2]
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, Finding{
			Title: fmt.Sprintf("%s:%s open", m[1], m[2]), Severity: "info",
			Target: m[1], Port: m[2], Service: "open-port",
			Fields: map[string]string{"host": m[1], "port": m[2]},
		})
		if len(findings) >= MaxFindings {
			break
		}
	}
	return findings
}

// parseDalfox reads dalfox JSON output, one object per line or a single
// object, and turns each XSS finding into a Daru finding.
func parseDalfox(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec struct {
			Type     string `json:"type"`
			Severity string `json:"severity"`
			URL      string `json:"url"`
			Payload  string `json:"payload"`
			Evidence string `json:"evidence"`
			PoC      string `json:"poc"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		title := rec.Type
		if title == "" {
			title = "XSS"
		}
		sev := strings.ToLower(rec.Severity)
		if sev == "" {
			sev = "medium"
		}
		detail := firstNonEmptyStr(rec.Evidence, firstNonEmptyStr(rec.PoC, rec.Payload))
		findings = append(findings, Finding{
			Title: title + " on " + rec.URL, Severity: sev, Target: r.Target,
			Detail: truncate(detail, 400),
			Fields: map[string]string{"url": rec.URL, "payload": rec.Payload, "type": rec.Type},
		})
		if len(findings) >= MaxFindings {
			break
		}
	}
	return findings
}

// parseWpscan reads wpscan JSON output: version, interesting findings, and
// vulnerabilities for the core, plugins, and themes.
func parseWpscan(out []byte, r Request) []Finding {
	var findings []Finding
	add := func(sev, title, detail string) {
		findings = append(findings, Finding{Title: title, Severity: sev, Target: r.Target, Detail: truncate(detail, 400)})
	}
	var data struct {
		Version struct {
			Number string `json:"number"`
		} `json:"version"`
		InterestingFindings []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"interesting_findings"`
		Vulnerabilities []struct {
			Title string `json:"title"`
		} `json:"vulnerabilities"`
	}
	trimmed := strings.TrimSpace(string(out))
	if err := json.Unmarshal([]byte(trimmed), &data); err != nil {
		// wpscan may print banner lines before the JSON; find the object.
		if i := strings.Index(trimmed, "{"); i >= 0 {
			_ = json.Unmarshal([]byte(trimmed[i:]), &data)
		}
	}
	if data.Version.Number != "" {
		add("info", "WordPress "+data.Version.Number, "")
	}
	for _, f := range data.InterestingFindings {
		add("low", "Interesting finding: "+f.Type, f.URL)
	}
	for _, v := range data.Vulnerabilities {
		add("high", "WordPress vulnerability: "+v.Title, "")
	}
	if len(findings) >= MaxFindings {
		findings = findings[:MaxFindings]
	}
	return findings
}

// parseURLList reads one URL per line (waybackurls, gau, hakrawler output)
// and records each as an info finding, bounded and deduplicated.
func parseURLList(out []byte, r Request) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		u := strings.TrimSpace(line)
		if u == "" || seen[u] {
			continue
		}
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			continue
		}
		seen[u] = true
		findings = append(findings, Finding{
			Title: u, Severity: "info", Target: r.Target, Service: "url",
			Fields: map[string]string{"url": u},
		})
		if len(findings) >= MaxFindings {
			break
		}
	}
	return findings
}

// parseTrufflehog reads trufflehog JSONL secret findings.
func parseTrufflehog(out []byte, r Request) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec struct {
			DetectorName   string `json:"DetectorName"`
			Verified       bool   `json:"Verified"`
			Raw            string `json:"Raw"`
			SourceMetadata struct {
				Data struct {
					Git struct {
						Repository string `json:"repository"`
						Commit     string `json:"commit"`
						File       string `json:"file"`
						Line       int    `json:"line"`
					} `json:"Git"`
				} `json:"Data"`
			} `json:"SourceMetadata"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil || rec.DetectorName == "" {
			continue
		}
		sev := "medium"
		if rec.Verified {
			sev = "high"
		}
		detail := rec.SourceMetadata.Data.Git.File
		if rec.SourceMetadata.Data.Git.Repository != "" {
			detail = rec.SourceMetadata.Data.Git.Repository + " " + detail
		}
		findings = append(findings, Finding{
			Title: "Secret found: " + rec.DetectorName, Severity: sev, Target: r.Target,
			Detail: truncate(strings.TrimSpace(detail), 400),
			Fields: map[string]string{"detector": rec.DetectorName, "verified": fmt.Sprintf("%v", rec.Verified), "file": rec.SourceMetadata.Data.Git.File},
		})
		if len(findings) >= MaxFindings {
			break
		}
	}
	return findings
}

// postureCollect aggregates the MITRE mapping of every registered connector
// into one finding per tactic, listing the techniques and connectors that
// cover it. It runs no external tool.
func postureCollect(ctx context.Context, r Request) ([]Finding, error) {
	byTactic := map[string]map[string][]string{}
	for name := range Registry {
		tactic, tech := mitreForConnector(name)
		if byTactic[tactic] == nil {
			byTactic[tactic] = map[string][]string{}
		}
		byTactic[tactic][tech] = append(byTactic[tactic][tech], name)
	}
	var tactics []string
	for t := range byTactic {
		tactics = append(tactics, t)
	}
	sort.Strings(tactics)
	var findings []Finding
	for _, tactic := range tactics {
		var techs []string
		for tech := range byTactic[tactic] {
			techs = append(techs, tech)
		}
		sort.Strings(techs)
		var parts []string
		for _, tech := range techs {
			names := byTactic[tactic][tech]
			sort.Strings(names)
			parts = append(parts, tech+" ("+strings.Join(names, ", ")+")")
		}
		findings = append(findings, Finding{
			Title:    "MITRE " + tactic + ": " + strings.Join(parts, "; "),
			Severity: "info", Target: r.Target, Service: "posture",
			MitreTactic: tactic,
			Fields:      map[string]string{"tactic": tactic, "techniques": strings.Join(techs, ", ")},
		})
	}
	return findings, nil
}
