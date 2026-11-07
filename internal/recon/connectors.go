package recon

import "fmt"

// profile returns the requested profile name or the first as default.
func profileOr(c *Connector, name string) string {
	if name == "" && len(c.Profiles) > 0 {
		return c.Profiles[0].Name
	}
	return name
}

func init() {
	// ---- Port & host discovery ----
	register(&Connector{
		Name: "nmap", Binary: "nmap", Category: CatPortScan, TargetKind: TgtCIDR,
		Desc: "Network exploration and port/service scanner.",
		Profiles: []Profile{
			{"quick", "Top 100 ports, fast"},
			{"default", "Top 1000 ports with service detection"},
			{"full", "All 65535 ports"},
			{"service", "Service and version detection"},
			{"vuln", "Run nmap's vuln NSE scripts"},
			{"discovery", "Ping sweep, no port scan"},
		},
		build: func(c *Connector, r Request) ([]string, error) {
			args := []string{"-oX", "-", "-Pn", "--host-timeout", "15m"}
			switch profileOr(c, r.Profile) {
			case "quick":
				args = append(args, "-T4", "--top-ports", "100")
			case "full":
				args = append(args, "-T4", "-p-")
			case "service":
				args = append(args, "-T4", "-sV", "--top-ports", "1000")
			case "vuln":
				args = append(args, "-T4", "-sV", "--script", "vuln", "--top-ports", "1000")
			case "discovery":
				args = append(args, "-sn")
			default:
				args = append(args, "-T4", "-sV", "--top-ports", "1000")
			}
			if r.Ports != "" {
				if !validPorts(r.Ports) {
					return nil, fmt.Errorf("invalid port spec")
				}
				args = append(args, "-p", r.Ports)
			}
			return append(args, r.Target), nil
		},
		parse: parseNmapXML,
	})

	register(&Connector{
		Name: "masscan", Binary: "masscan", Category: CatPortScan, TargetKind: TgtCIDR,
		Desc: "Asynchronous high-speed TCP port scanner.", NeedsRoot: true,
		Profiles: []Profile{{"top", "Common ports"}, {"web", "80,443,8080,8443"}, {"custom", "Use the ports field"}},
		build: func(c *Connector, r Request) ([]string, error) {
			ports := "80,443,22,21,25,3389,8080,8443,445,3306,5432"
			switch profileOr(c, r.Profile) {
			case "web":
				ports = "80,443,8080,8443"
			case "custom":
				if !validPorts(r.Ports) || r.Ports == "" {
					return nil, fmt.Errorf("provide ports for the custom profile")
				}
				ports = r.Ports
			}
			return []string{"-p", ports, "--rate", "1000", "-oJ", "-", r.Target}, nil
		},
		parse: parseMasscanJSON,
	})

	register(&Connector{
		Name: "zmap", Binary: "zmap", Category: CatPortScan, TargetKind: TgtCIDR,
		Desc: "Single-port, high-speed network scanner for research.", NeedsRoot: true,
		Profiles: []Profile{{"port", "Scan one port across the range (set ports)"}},
		build: func(c *Connector, r Request) ([]string, error) {
			port := r.Ports
			if !validPorts(port) || port == "" {
				return nil, fmt.Errorf("set a single target port")
			}
			return []string{"-p", port, "-o", "-", "-f", "saddr,sport", r.Target}, nil
		},
	})

	register(&Connector{
		Name: "fping", Binary: "fping", Category: CatPortScan, TargetKind: TgtCIDR,
		Desc:     "Fast ICMP host discovery across many hosts.",
		Profiles: []Profile{{"sweep", "Ping sweep, show alive hosts"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-a", "-q", "-g", r.Target}, nil
		},
	})

	register(&Connector{
		Name: "hping3", Binary: "hping3", Category: CatPortScan, TargetKind: TgtHost,
		Desc: "Custom TCP/IP packet crafting and probing.", NeedsRoot: true,
		Profiles: []Profile{{"syn", "TCP SYN probe to a port"}},
		build: func(c *Connector, r Request) ([]string, error) {
			port := r.Ports
			if port == "" {
				port = "80"
			}
			if !validPorts(port) {
				return nil, fmt.Errorf("invalid port")
			}
			return []string{"-S", "-p", port, "-c", "5", r.Target}, nil
		},
	})

	// ---- Service enumeration ----
	register(&Connector{
		Name: "unicornscan", Binary: "unicornscan", Category: CatEnum, TargetKind: TgtHost,
		Desc:     "Asynchronous stimulus/response TCP/IP scanner.",
		Profiles: []Profile{{"tcp", "TCP scan"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{r.Target}, nil },
	})
	register(&Connector{
		Name: "smbmap", Binary: "smbmap", Category: CatEnum, TargetKind: TgtHost,
		Desc:     "SMB share enumeration.",
		Profiles: []Profile{{"list", "List shares and permissions"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{"-H", r.Target}, nil },
	})

	// ---- Vulnerability scanning ----
	register(&Connector{
		Name: "nuclei", Binary: "nuclei", Category: CatVulnScan, TargetKind: TgtURL,
		Desc:     "Template-based vulnerability scanner.",
		Profiles: []Profile{{"default", "Run community templates"}, {"cves", "CVE templates only"}},
		build: func(c *Connector, r Request) ([]string, error) {
			args := []string{"-u", r.Target, "-jsonl", "-silent"}
			if profileOr(c, r.Profile) == "cves" {
				args = append(args, "-tags", "cve")
			}
			return args, nil
		},
		parse: parseNucleiJSONL,
	})
	register(&Connector{
		Name: "nikto", Binary: "nikto", Category: CatVulnScan, TargetKind: TgtURL,
		Desc:     "Web server misconfiguration and known-issue scanner.",
		Profiles: []Profile{{"default", "Standard scan"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-host", r.Target, "-Format", "json", "-output", "-", "-nointeractive"}, nil
		},
	})
	register(&Connector{
		Name: "wapiti", Binary: "wapiti", Category: CatVulnScan, TargetKind: TgtURL,
		Desc:     "Black-box web application vulnerability scanner.",
		Profiles: []Profile{{"default", "Standard scan"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-u", r.Target, "-f", "json", "-o", "/dev/stdout"}, nil
		},
	})
	register(&Connector{
		Name: "openvas", Binary: "gvm-cli", Category: CatVulnScan, TargetKind: TgtHost,
		Desc:     "OpenVAS/GVM vulnerability scan (requires a configured GVM).",
		Profiles: []Profile{{"info", "Show how to connect (configuration required)"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return nil, fmt.Errorf("OpenVAS needs a configured GVM endpoint; this connector is a placeholder for your GVM integration")
		},
	})

	// ---- Web scanning ----
	register(&Connector{
		Name: "httpx", Binary: "httpx", Category: CatWebScan, TargetKind: TgtURL,
		Desc:     "Fast HTTP probing: status, title, tech.",
		Profiles: []Profile{{"probe", "Probe and fingerprint"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-u", r.Target, "-json", "-silent", "-title", "-tech-detect", "-status-code"}, nil
		},
		parse: parseJSONLines,
	})
	register(&Connector{
		Name: "whatweb", Binary: "whatweb", Category: CatWebScan, TargetKind: TgtURL,
		Desc:     "Website fingerprinter.",
		Profiles: []Profile{{"default", "Identify technologies"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"--log-json=-", "--no-errors", r.Target}, nil
		},
		parse: parseJSONLines,
	})
	register(&Connector{
		Name: "wafw00f", Binary: "wafw00f", Category: CatWebScan, TargetKind: TgtURL,
		Desc:     "Web application firewall fingerprinter.",
		Profiles: []Profile{{"default", "Detect a WAF"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{r.Target}, nil },
	})

	// ---- DNS & subdomains ----
	register(&Connector{
		Name: "subfinder", Binary: "subfinder", Category: CatDNS, TargetKind: TgtDomain,
		Desc:     "Passive subdomain discovery.",
		Profiles: []Profile{{"passive", "Passive sources"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{"-d", r.Target, "-silent"}, nil },
		parse:    parseHostList,
	})
	register(&Connector{
		Name: "amass", Binary: "amass", Category: CatDNS, TargetKind: TgtDomain,
		Desc:     "Subdomain enumeration and attack surface mapping.",
		Profiles: []Profile{{"passive", "Passive enumeration"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"enum", "-passive", "-d", r.Target}, nil
		},
		parse: parseHostList,
	})
	register(&Connector{
		Name: "dnsrecon", Binary: "dnsrecon", Category: CatDNS, TargetKind: TgtDomain,
		Desc:     "DNS enumeration and zone checks.",
		Profiles: []Profile{{"std", "Standard records"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{"-d", r.Target, "-j", "-"}, nil },
	})
	register(&Connector{
		Name: "dnsx", Binary: "dnsx", Category: CatDNS, TargetKind: TgtDomain,
		Desc:     "Fast DNS resolver and probe.",
		Profiles: []Profile{{"resolve", "Resolve records"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-d", r.Target, "-json", "-silent"}, nil
		},
		parse: parseJSONLines,
	})
	register(&Connector{
		Name: "dnstwist", Binary: "dnstwist", Category: CatDNS, TargetKind: TgtDomain,
		Desc:     "Typosquatting and lookalike domain detection.",
		Profiles: []Profile{{"registered", "Only registered permutations"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"--format", "json", "-r", r.Target}, nil
		},
		parse: parseJSONLines,
	})

	// ---- OSINT ----
	register(&Connector{
		Name: "theharvester", Binary: "theHarvester", Category: CatOSINT, TargetKind: TgtDomain,
		Desc:     "Emails, hosts, and names from public sources.",
		Profiles: []Profile{{"all", "All free sources"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-d", r.Target, "-b", "all"}, nil
		},
	})
	register(&Connector{
		Name: "spiderfoot", Binary: "sfcli", Category: CatOSINT, TargetKind: TgtDomain,
		Desc:     "Multi-source OSINT automation (requires a running SpiderFoot server).",
		Profiles: []Profile{{"scan", "Start a scan via sfcli"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return nil, fmt.Errorf("SpiderFoot runs as its own server; point this connector at your SpiderFoot instance")
		},
	})
	register(&Connector{
		Name: "recon-ng", Binary: "recon-ng", Category: CatOSINT, TargetKind: TgtDomain,
		Desc:     "Full-featured web reconnaissance framework.",
		Profiles: []Profile{{"info", "Framework is interactive; use workspaces"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return nil, fmt.Errorf("recon-ng is interactive; run modules in a workspace and send results to Daru via HEC")
		},
	})

	// ---- TLS/SSL ----
	register(&Connector{
		Name: "sslyze", Binary: "sslyze", Category: CatTLS, TargetKind: TgtHost,
		Desc:     "TLS/SSL configuration analyzer.",
		Profiles: []Profile{{"default", "Full TLS analysis"}},
		build: func(c *Connector, r Request) ([]string, error) {
			t := r.Target
			if r.Ports != "" {
				if !validPorts(r.Ports) {
					return nil, fmt.Errorf("invalid port")
				}
				t = r.Target + ":" + r.Ports
			}
			return []string{"--json_out=-", t}, nil
		},
		parse: parseJSONLines,
	})
	register(&Connector{
		Name: "testssl", Binary: "testssl.sh", Category: CatTLS, TargetKind: TgtHost,
		Desc:     "Check a server's TLS ciphers, protocols, and flaws.",
		Profiles: []Profile{{"default", "Standard checks"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"--jsonfile-pretty", "/dev/stdout", "--quiet", r.Target}, nil
		},
	})

	// ---- Traffic & protocol analysis ----
	register(&Connector{
		Name: "tshark-capture", Binary: "tshark", Category: CatTraffic, TargetKind: TgtIface,
		Desc: "Live packet capture summary on an interface.", NeedsRoot: true,
		Profiles: []Profile{{"60s", "Capture for 60 seconds"}, {"30s", "Capture for 30 seconds"}},
		build: func(c *Connector, r Request) ([]string, error) {
			dur := "60"
			if profileOr(c, r.Profile) == "30s" {
				dur = "30"
			}
			return []string{"-i", r.Target, "-a", "duration:" + dur, "-T", "fields",
				"-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol",
				"-e", "tcp.dstport", "-e", "_ws.col.Info", "-E", "separator=\t"}, nil
		},
		parse: parseTsharkFields,
	})
	register(&Connector{
		Name: "tshark-pcap", Binary: "tshark", Category: CatTraffic, TargetKind: TgtPcap,
		Desc:     "Read and summarize an existing capture file.",
		Profiles: []Profile{{"summary", "Per-packet summary"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-r", r.Target, "-T", "fields",
				"-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol",
				"-e", "tcp.dstport", "-e", "_ws.col.Info", "-E", "separator=\t"}, nil
		},
		parse: parseTsharkFields,
	})
	register(&Connector{
		Name: "tcpdump", Binary: "tcpdump", Category: CatTraffic, TargetKind: TgtIface,
		Desc: "Capture packet headers on an interface.", NeedsRoot: true,
		Profiles: []Profile{{"100", "Capture 100 packets"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-i", r.Target, "-c", "100", "-nn", "-tttt"}, nil
		},
	})
}
