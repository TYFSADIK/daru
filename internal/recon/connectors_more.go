package recon

import (
	"fmt"
	"os"
)

// Additional connectors for tools the install script already provides but that
// had no driver yet. Each stays behind the same authorization gate and scope
// guard as the rest; nothing here is DoS or mass-exploitation tooling.
func init() {
	// ---- Port & host discovery ----
	register(&Connector{
		Name: "naabu", Binary: "naabu", Category: CatPortScan, TargetKind: TgtCIDR,
		Desc: "Fast SYN/CONNECT port scanner (ProjectDiscovery).",
		Profiles: []Profile{
			{"top", "Top 100 ports"},
			{"full", "All 65535 ports"},
			{"custom", "Use the ports field"},
		},
		build: func(c *Connector, r Request) ([]string, error) {
			args := []string{"-host", r.Target, "-json", "-silent"}
			switch profileOr(c, r.Profile) {
			case "full":
				args = append(args, "-p", "-")
			case "custom":
				if !validPorts(r.Ports) || r.Ports == "" {
					return nil, fmt.Errorf("provide ports for the custom profile")
				}
				args = append(args, "-p", r.Ports)
			default:
				args = append(args, "-top-ports", "100")
			}
			return args, nil
		},
		parse: parseNaabu,
	})

	register(&Connector{
		Name: "nbtscan", Binary: "nbtscan", Category: CatPortScan, TargetKind: TgtCIDR,
		Desc:     "Scan a range for NetBIOS names and MACs (good LAN inventory).",
		Profiles: []Profile{{"range", "Scan the target range"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{r.Target}, nil },
		parse:    parseNbtscan,
	})

	register(&Connector{
		Name: "traceroute", Binary: "traceroute", Category: CatPortScan, TargetKind: TgtHost,
		Desc:     "Trace the network path to a host.",
		Profiles: []Profile{{"default", "ICMP/UDP trace"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{"-n", r.Target}, nil },
	})

	// ---- Service enumeration ----
	register(&Connector{
		Name: "enum4linux", Binary: "enum4linux", Category: CatEnum, TargetKind: TgtHost,
		Desc:     "SMB/NetBIOS enumeration: shares, users, groups, OS.",
		Profiles: []Profile{{"all", "Full enumeration (-a)"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{"-a", r.Target}, nil },
	})

	register(&Connector{
		Name: "snmpwalk", Binary: "snmpwalk", Category: CatEnum, TargetKind: TgtHost,
		Desc:     "Walk a device's SNMP tree (community defaults to public).",
		Profiles: []Profile{{"public", "SNMP v2c, community public"}},
		build: func(c *Connector, r Request) ([]string, error) {
			community := "public"
			if v := r.Options["community"]; v != "" && simpleToken(v) {
				community = v
			}
			return []string{"-v2c", "-c", community, "-On", "-t", "3", "-r", "1", r.Target}, nil
		},
	})

	register(&Connector{
		Name: "onesixtyone", Binary: "onesixtyone", Category: CatEnum, TargetKind: TgtHost,
		Desc:     "Fast SNMP community-string scanner.",
		Profiles: []Profile{{"default", "Try common community strings"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{r.Target}, nil },
	})

	// ---- Web scanning ----
	register(&Connector{
		Name: "katana", Binary: "katana", Category: CatWebScan, TargetKind: TgtURL,
		Desc:     "Crawl a site and enumerate endpoints (ProjectDiscovery).",
		Profiles: []Profile{{"crawl", "Standard crawl, depth 2"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-u", r.Target, "-silent", "-jsonl", "-d", "2"}, nil
		},
		parse: parseJSONLines,
	})

	register(&Connector{
		Name: "gobuster", Binary: "gobuster", Category: CatWebScan, TargetKind: TgtURL,
		Desc:     "Directory and file brute-forcing (needs an installed wordlist).",
		Profiles: []Profile{{"dir", "Content discovery"}},
		build: func(c *Connector, r Request) ([]string, error) {
			wl, err := findWordlist()
			if err != nil {
				return nil, err
			}
			return []string{"dir", "-u", r.Target, "-w", wl, "-q", "-t", "30", "--no-color"}, nil
		},
	})

	register(&Connector{
		Name: "ffuf", Binary: "ffuf", Category: CatWebScan, TargetKind: TgtURL,
		Desc:     "Web fuzzer for content discovery (needs an installed wordlist).",
		Profiles: []Profile{{"dir", "Fuzz FUZZ at the path"}},
		build: func(c *Connector, r Request) ([]string, error) {
			wl, err := findWordlist()
			if err != nil {
				return nil, err
			}
			u := r.Target
			if u[len(u)-1] != '/' {
				u += "/"
			}
			return []string{"-u", u + "FUZZ", "-w", wl, "-s", "-mc", "200,204,301,302,307,401,403"}, nil
		},
	})

	register(&Connector{
		Name: "sqlmap", Binary: "sqlmap", Category: CatWebScan, TargetKind: TgtURL,
		Desc:     "SQL injection detection on a single URL (authorized testing).",
		Profiles: []Profile{{"detect", "Batch detection, level 1 / risk 1"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-u", r.Target, "--batch", "--level=1", "--risk=1", "--flush-session", "--disable-coloring"}, nil
		},
	})

	// ---- TLS/SSL ----
	register(&Connector{
		Name: "sslscan", Binary: "sslscan", Category: CatTLS, TargetKind: TgtHost,
		Desc:     "Enumerate a server's SSL/TLS protocols and ciphers.",
		Profiles: []Profile{{"default", "Full protocol and cipher scan"}},
		build: func(c *Connector, r Request) ([]string, error) {
			t := r.Target
			if r.Ports != "" {
				if !validPorts(r.Ports) {
					return nil, fmt.Errorf("invalid port")
				}
				t = r.Target + ":" + r.Ports
			}
			return []string{"--xml=-", t}, nil
		},
		parse: parseSslscanXML,
	})

	// ---- DNS & subdomains ----
	register(&Connector{
		Name: "dnsenum", Binary: "dnsenum", Category: CatDNS, TargetKind: TgtDomain,
		Desc:     "DNS enumeration: records, zone transfer attempts, brute force.",
		Profiles: []Profile{{"std", "Standard enumeration (no brute force)"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"--nocolor", "--noreverse", "--enum", r.Target}, nil
		},
	})

	register(&Connector{
		Name: "fierce", Binary: "fierce", Category: CatDNS, TargetKind: TgtDomain,
		Desc:     "Locate non-contiguous IP space and hostnames for a domain.",
		Profiles: []Profile{{"default", "Standard scan"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"--domain", r.Target}, nil
		},
	})

	// ---- OSINT ----
	register(&Connector{
		Name: "whois", Binary: "whois", Category: CatOSINT, TargetKind: TgtDomain,
		Desc:     "Domain registration lookup.",
		Profiles: []Profile{{"lookup", "Query the whois record"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{r.Target}, nil },
	})
}

// findWordlist returns the first installed content-discovery wordlist, or an
// error telling the operator how to install one.
func findWordlist() (string, error) {
	candidates := []string{
		"/usr/share/wordlists/dirb/common.txt",
		"/usr/share/dirb/wordlists/common.txt",
		"/usr/share/seclists/Discovery/Web-Content/common.txt",
		"/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
		"/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("no wordlist found; install one with: sudo apt-get install -y dirb seclists")
}

// simpleToken allows only safe characters in an SNMP community string.
func simpleToken(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}
