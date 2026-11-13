package recon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// zmapRouteParams resolves the outgoing interface, source IP, and gateway MAC
// the kernel would use to reach a target (CIDR or host), via `ip route get`
// and `ip neigh`. Used to pin zmap on a multi-homed/WiFi host.
func zmapRouteParams(target string) (iface, src, gwmac string) {
	ip := strings.SplitN(strings.TrimSpace(target), "/", 2)[0]
	if ip == "" {
		return "", "", ""
	}
	ipBin := firstExisting("ip", "/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, ipBin, "route", "get", ip).Output() // #nosec G204 -- recon tools run as an argv list (no shell) from a vetted binary path
	if err != nil {
		return "", "", ""
	}
	var via string
	fields := strings.Fields(string(out))
	for i := 0; i < len(fields)-1; i++ {
		switch fields[i] {
		case "dev":
			iface = fields[i+1]
		case "src":
			src = fields[i+1]
		case "via":
			via = fields[i+1]
		}
	}
	// Gateway MAC: look up the next-hop (via) or the default gateway in the
	// neighbor table.
	gw := via
	if gw == "" {
		gw = defaultGateway(ipBin, iface)
	}
	if gw != "" {
		nctx, ncancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer ncancel()
		if nb, err := exec.CommandContext(nctx, ipBin, "neigh", "show", gw).Output(); err == nil { // #nosec G204 -- recon tools run as an argv list (no shell) from a vetted binary path
			if m := macRe.FindString(string(nb)); m != "" {
				gwmac = m
			}
		}
	}
	return iface, src, gwmac
}

var macRe = regexp.MustCompile(`(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}`)

func defaultGateway(ipBin, iface string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, ipBin, "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		var via, dev string
		for i := 0; i < len(f)-1; i++ {
			if f[i] == "via" {
				via = f[i+1]
			}
			if f[i] == "dev" {
				dev = f[i+1]
			}
		}
		if via != "" && (iface == "" || dev == iface) {
			return via
		}
	}
	return ""
}

// setupGuide returns a native collector that emits structured setup guidance

// setupGuide returns a native collector that emits structured setup guidance
// for a tool that runs as its own server/framework rather than a one-shot CLI.
// This gives such tools a clean, informative dashboard instead of a bare error.
func setupGuide(tool string, steps []string) func(context.Context, Request) ([]Finding, error) {
	return func(_ context.Context, r Request) ([]Finding, error) {
		findings := []Finding{{
			Title:    tool + " runs as its own server/framework, see the setup steps below",
			Severity: "info", Target: r.Target, Service: "setup",
		}}
		for i, s := range steps {
			findings = append(findings, Finding{
				Title: s, Severity: "info", Target: r.Target, Service: "setup",
				Fields: map[string]string{"step": fmt.Sprintf("%d", i)},
			})
		}
		return findings, nil
	}
}

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
			args := []string{"-oX", "-", "--host-timeout", "15m"}
			prof := profileOr(c, r.Profile)
			// -Pn treats every host as online, which is right for a port scan
			// of a host that blocks pings but wrong for host discovery, where
			// it would report every address in the range as "up". So -Pn is
			// added for every profile except discovery.
			if prof != "discovery" {
				args = append(args, "-Pn")
			}
			switch prof {
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
			return append(args, "--", r.Target), nil
		},
		parse:  parseNmapXML,
		verify: verifyName("nmap", "network exploration"),
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
		parse:  parseMasscanJSON,
		verify: verifyName("masscan"),
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
			// zmap's default blocklist excludes RFC1918 ranges, so an
			// out-of-the-box scan of a home/office LAN finds nothing. An empty
			// blocklist lets it scan the private range the operator asked for;
			// the scope guard already restricts the target to authorized nets.
			args := []string{"-p", port, "-b", os.DevNull, "-o", "-", "-f", "saddr,sport", "--cooldown-time=2"}
			// zmap auto-selects an interface by the default route, which is wrong
			// on a multi-homed host, and it needs the gateway MAC for its raw L2
			// sending (auto-detection often hangs, especially on WiFi). Pin the
			// interface, source IP, and gateway MAC derived from the routing table.
			if iface, src, gwmac := zmapRouteParams(r.Target); iface != "" {
				args = append(args, "-i", iface)
				if src != "" {
					args = append(args, "-S", src)
				}
				if gwmac != "" {
					args = append(args, "-G", gwmac)
				}
			}
			return append(args, r.Target), nil
		},
		parse:  parseZmap,
		verify: verifyName("zmap"),
	})

	register(&Connector{
		Name: "fping", Binary: "fping", Category: CatPortScan, TargetKind: TgtCIDR,
		Desc:     "Fast ICMP host discovery across many hosts.",
		Profiles: []Profile{{"sweep", "Ping sweep, show alive hosts"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-a", "-q", "-g", "--", r.Target}, nil
		},
		parse:  parseAliveHosts,
		verify: verifyName("fping"),
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
		parse:  parseHping3,
		verify: verifyName("hping3"),
	})

	// ---- Service enumeration ----
	register(&Connector{
		Name: "unicornscan", Binary: "unicornscan", Category: CatEnum, TargetKind: TgtHost,
		Desc:     "Asynchronous stimulus/response TCP/IP scanner.",
		Profiles: []Profile{{"tcp", "TCP scan"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{"--", r.Target}, nil },
		parse:    parseUnicornscan,
		verify:   verifyName("unicornscan"),
	})
	register(&Connector{
		Name: "smbmap", Binary: "smbmap", Category: CatEnum, TargetKind: TgtHost,
		Desc:     "SMB share enumeration.",
		Profiles: []Profile{{"list", "List shares and permissions"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-H", r.Target, "--no-banner", "--no-color"}, nil
		},
		parse:  parseSmbmap,
		verify: verifyName("smbmap"),
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
		parse:  parseNucleiJSONL,
		verify: verifyName("nuclei", "projectdiscovery"),
	})
	register(&Connector{
		Name: "nikto", Binary: "nikto", Category: CatVulnScan, TargetKind: TgtURL,
		Desc:     "Web server misconfiguration and known-issue scanner.",
		Profiles: []Profile{{"default", "Standard scan"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-host", r.Target, "-nointeractive"}, nil
		},
		parse:  parseNikto,
		verify: verifyName("nikto"),
	})
	register(&Connector{
		Name: "wapiti", Binary: "wapiti", Category: CatVulnScan, TargetKind: TgtURL,
		Desc:     "Black-box web application vulnerability scanner.",
		Profiles: []Profile{{"default", "Standard scan"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-u", r.Target, "-f", "json", "-o", "/dev/stdout", "--flush-session", "--max-scan-time", "600"}, nil
		},
		parse:  parseWapiti,
		verify: verifyName("wapiti"),
	})
	register(&Connector{
		Name: "openvas", Binary: "gvm-cli", Category: CatVulnScan, TargetKind: TgtHost,
		Desc:     "OpenVAS/GVM vulnerability scan (requires a configured GVM server).",
		Profiles: []Profile{{"info", "Setup guidance (GVM configuration required)"}},
		native: setupGuide("OpenVAS / GVM", []string{
			"OpenVAS runs as the Greenbone Vulnerability Manager (GVM) server, not a one-shot CLI.",
			"1. Install and provision GVM (e.g. `gvm-setup`) and sync the NVT/SCAP/CERT feeds.",
			"2. Start the services (gvmd, ospd-openvas, gsad) and note the GVMD socket or TLS endpoint.",
			"3. Create a target and a task via the Greenbone UI or `gvm-cli`.",
			"4. Export results to Daru by sending the report over HEC to /services/collector.",
		}),
	})

	// ---- Web scanning ----
	register(&Connector{
		Name: "httpx", Binary: "httpx", Category: CatWebScan, TargetKind: TgtURL,
		Desc:     "Fast HTTP probing: status, title, tech.",
		Profiles: []Profile{{"probe", "Probe and fingerprint"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-u", r.Target, "-json", "-silent", "-title", "-tech-detect", "-status-code", "-web-server"}, nil
		},
		parse: parseHttpx,
		// Reject the unrelated Python "httpx" HTTP client that often sits on
		// PATH; ProjectDiscovery's httpx help advertises these flags.
		verify: verifyHelpContains("-h", "-status-code", "-td,", "projectdiscovery"),
	})
	register(&Connector{
		Name: "whatweb", Binary: "whatweb", Category: CatWebScan, TargetKind: TgtURL,
		Desc:     "Website fingerprinter.",
		Profiles: []Profile{{"default", "Identify technologies"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"--log-json=-", "--no-errors", r.Target}, nil
		},
		parse:  parseWhatweb,
		verify: verifyName("whatweb"),
	})
	register(&Connector{
		Name: "wafw00f", Binary: "wafw00f", Category: CatWebScan, TargetKind: TgtURL,
		Desc:     "Web application firewall fingerprinter.",
		Profiles: []Profile{{"default", "Detect a WAF"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{r.Target}, nil },
		parse:    parseWafw00f,
		verify:   verifyName("wafw00f"),
	})

	// ---- DNS & subdomains ----
	register(&Connector{
		Name: "subfinder", Binary: "subfinder", Category: CatDNS, TargetKind: TgtDomain,
		Desc:     "Passive subdomain discovery.",
		Profiles: []Profile{{"passive", "Passive sources"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{"-d", r.Target, "-silent"}, nil },
		parse:    parseHostList,
		verify:   verifyName("subfinder", "projectdiscovery"),
	})
	register(&Connector{
		Name: "amass", Binary: "amass", Category: CatDNS, TargetKind: TgtDomain,
		Desc:     "Subdomain enumeration and attack surface mapping.",
		Profiles: []Profile{{"passive", "Passive enumeration"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"enum", "-passive", "-d", r.Target}, nil
		},
		parse:  parseHostList,
		verify: verifyName("amass", "owasp"),
	})
	register(&Connector{
		Name: "dnsrecon", Binary: "dnsrecon", Category: CatDNS, TargetKind: TgtDomain,
		Desc:     "DNS enumeration and zone checks.",
		Profiles: []Profile{{"std", "Standard records"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{"-d", r.Target}, nil },
		parse:    parseDnsrecon,
		verify:   verifyName("dnsrecon"),
	})
	register(&Connector{
		Name: "dnsx", Binary: "dnsx", Category: CatDNS, TargetKind: TgtDomain,
		Desc:     "Fast DNS resolver: A/AAAA/CNAME/MX/NS/TXT records. Uses the dnsx binary if it resolves, else Daru's native resolver.",
		Profiles: []Profile{{"resolve", "Resolve records"}},
		native:   dnsxRun,
	})
	register(&Connector{
		Name: "dnstwist", Binary: "dnstwist", Category: CatDNS, TargetKind: TgtDomain,
		Desc:     "Typosquatting and lookalike domain detection.",
		Profiles: []Profile{{"registered", "Only registered permutations"}},
		build: func(c *Connector, r Request) ([]string, error) {
			// -t 20 parallelizes the DNS lookups so the scan finishes promptly.
			return []string{"--format", "json", "-r", "-t", "20", r.Target}, nil
		},
		parse:  parseDnstwist,
		verify: verifyName("dnstwist"),
	})

	// ---- OSINT ----
	register(&Connector{
		Name: "theharvester", Binary: "theHarvester", Category: CatOSINT, TargetKind: TgtDomain,
		Desc:     "Emails, hosts, and names from public sources.",
		Profiles: []Profile{{"all", "All free sources"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-d", r.Target, "-b", "all"}, nil
		},
		parse:  parseTheHarvester,
		verify: verifyName("theharvester"),
	})
	register(&Connector{
		Name: "spiderfoot", Binary: "sfcli", Category: CatOSINT, TargetKind: TgtDomain,
		Desc:     "Multi-source OSINT automation (runs as its own SpiderFoot server).",
		Profiles: []Profile{{"scan", "Setup guidance (SpiderFoot server required)"}},
		native: setupGuide("SpiderFoot", []string{
			"SpiderFoot runs as a web server with its own scan engine and database.",
			"1. Start it: `python3 sf.py -l 127.0.0.1:5001` (installed under ~/.daru/tools/spiderfoot).",
			"2. Create a scan in the SpiderFoot UI or with `sfcli` against your target.",
			"3. Export the results (CSV/JSON) and forward them to Daru over HEC at /services/collector.",
		}),
	})
	register(&Connector{
		Name: "recon-ng", Binary: "recon-ng", Category: CatOSINT, TargetKind: TgtDomain,
		Desc:     "Full-featured web reconnaissance framework (interactive workspaces).",
		Profiles: []Profile{{"info", "Setup guidance (interactive framework)"}},
		native: setupGuide("recon-ng", []string{
			"recon-ng is an interactive framework driven by workspaces and modules.",
			"1. Launch `recon-ng` and create a workspace: `workspaces create <name>`.",
			"2. Add your domain: `db insert domains`, then load modules (e.g. `modules load recon/domains-hosts/hackertarget`).",
			"3. Run the modules and `show hosts`.",
			"4. Export (`modules load reporting/csv`) and forward the results to Daru over HEC.",
		}),
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
		parse:  parseSslyze,
		verify: verifyName("sslyze"),
	})
	register(&Connector{
		Name: "testssl", Binary: "testssl", Category: CatTLS, TargetKind: TgtHost,
		Desc:     "Check a server's TLS ciphers, protocols, and flaws.",
		Profiles: []Profile{{"default", "Standard checks"}},
		build: func(c *Connector, r Request) ([]string, error) {
			t := r.Target
			if r.Ports != "" {
				if !validPorts(r.Ports) {
					return nil, fmt.Errorf("invalid port")
				}
				t = r.Target + ":" + r.Ports
			}
			return []string{"--jsonfile", "/dev/stdout", "--quiet", "--color", "0", t}, nil
		},
		parse:  parseTestssl,
		verify: verifyName("testssl"),
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
		parse:  parseTsharkFields,
		verify: verifyName("tshark"),
	})
	register(&Connector{
		Name: "tshark-pcap", Binary: "tshark", Category: CatTraffic, TargetKind: TgtPcap,
		Desc:     "Deep-analyze a capture file: per-packet decode with DNS queries, TLS SNI, and HTTP hosts (reading a file needs no capture privilege).",
		Profiles: []Profile{{"summary", "Rich per-packet decode"}},
		build: func(c *Connector, r Request) ([]string, error) {
			args := []string{"-r", r.Target, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"}
			for _, fld := range liveFields {
				args = append(args, "-e", fld)
			}
			return args, nil
		},
		parse:  parseTsharkRich,
		verify: verifyName("tshark"),
	})
	register(&Connector{
		Name: "tcpdump", Binary: "tcpdump", Category: CatTraffic, TargetKind: TgtIface,
		Desc: "Capture and decode packet headers on an interface.", NeedsRoot: true,
		Profiles: []Profile{{"100", "Capture 100 packets"}},
		build: func(c *Connector, r Request) ([]string, error) {
			// -tt -e matches the layout parseTcpdump decodes (epoch + MAC).
			return []string{"-i", r.Target, "-c", "100", "-l", "-nn", "-tt", "-e"}, nil
		},
		parse:  parseTcpdumpText,
		verify: verifyName("tcpdump"),
	})
}
