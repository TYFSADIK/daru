package recon

import (
	"fmt"
	"os"
	"path/filepath"
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
		parse:  parseNaabu,
		verify: verifyName("naabu", "projectdiscovery"),
	})

	register(&Connector{
		Name: "nbtscan", Binary: "nbtscan", Category: CatPortScan, TargetKind: TgtCIDR,
		Desc:     "Scan a range for NetBIOS names and MACs (good LAN inventory).",
		Profiles: []Profile{{"range", "Scan the target range"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{"--", r.Target}, nil },
		parse:    parseNbtscan,
		verify:   verifyName("nbtscan"),
	})

	register(&Connector{
		Name: "traceroute", Binary: "traceroute", Category: CatPortScan, TargetKind: TgtHost,
		Desc:     "Trace the network path to a host.",
		Profiles: []Profile{{"default", "ICMP/UDP trace"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{"-n", "--", r.Target}, nil },
		parse:    parseTraceroute,
		verify:   verifyName("traceroute"),
	})

	// ---- Service enumeration ----
	// enum4linux and enum4linux-ng run the real binary when installed, and
	// otherwise fall back to Daru's native SMB enumeration (smb-enum), so the
	// connector always produces results. Native, with the fallback baked in.
	register(&Connector{
		Name: "enum4linux", Binary: "enum4linux", Category: CatEnum, TargetKind: TgtHost,
		Desc:     "SMB/NetBIOS enumeration: shares, users, groups, OS. Uses the enum4linux binary if installed, else native SMB enumeration.",
		Profiles: []Profile{{"all", "Full enumeration"}},
		native:   enum4linuxRun("enum4linux", "-a"),
	})
	register(&Connector{
		Name: "enum4linux-ng", Binary: "enum4linux-ng", Category: CatEnum, TargetKind: TgtHost,
		Desc:     "SMB/NetBIOS enumeration (modern). Uses the enum4linux-ng binary if installed, else native SMB enumeration.",
		Profiles: []Profile{{"all", "Full enumeration"}},
		native:   enum4linuxRun("enum4linux-ng", "-A"),
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
		parse:  parseSnmpwalk,
		verify: verifyName("snmpwalk"),
	})

	register(&Connector{
		Name: "onesixtyone", Binary: "onesixtyone", Category: CatEnum, TargetKind: TgtHost,
		Desc:     "Fast SNMP community-string scanner.",
		Profiles: []Profile{{"default", "Try common community strings"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{r.Target, "public"}, nil },
		parse:    parseOnesixtyone,
		verify:   verifyName("onesixtyone"),
	})

	// ---- Web scanning ----
	register(&Connector{
		Name: "katana", Binary: "katana", Category: CatWebScan, TargetKind: TgtURL,
		Desc:     "Crawl a site and enumerate endpoints (ProjectDiscovery).",
		Profiles: []Profile{{"crawl", "Standard crawl, depth 2"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-u", r.Target, "-silent", "-jsonl", "-d", "2"}, nil
		},
		parse:  parseKatana,
		verify: verifyName("katana", "projectdiscovery"),
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
		parse:  parseGobuster,
		verify: verifyName("gobuster"),
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
			if u == "" {
				return nil, fmt.Errorf("a target URL is required")
			}
			if u[len(u)-1] != '/' {
				u += "/"
			}
			return []string{"-u", u + "FUZZ", "-w", wl, "-mc", "200,204,301,302,307,401,403", "-of", "json", "-o", "/dev/stdout", "-s"}, nil
		},
		parse:  parseFfuf,
		verify: verifyName("ffuf"),
	})

	register(&Connector{
		Name: "sqlmap", Binary: "sqlmap", Category: CatWebScan, TargetKind: TgtURL,
		Desc:     "SQL injection detection on a single URL (authorized testing).",
		Profiles: []Profile{{"detect", "Batch detection, level 1 / risk 1"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"-u", r.Target, "--batch", "--level=1", "--risk=1", "--flush-session", "--disable-coloring"}, nil
		},
		parse:  parseSqlmap,
		verify: verifyName("sqlmap"),
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
		parse:  parseSslscanXML,
		verify: verifyName("sslscan"),
	})

	// ---- DNS & subdomains ----
	register(&Connector{
		Name: "dnsenum", Binary: "dnsenum", Category: CatDNS, TargetKind: TgtDomain,
		Desc:     "DNS enumeration: records, zone transfer attempts, brute force.",
		Profiles: []Profile{{"std", "Standard enumeration (no brute force)"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"--nocolor", "--noreverse", "--enum", r.Target}, nil
		},
		parse:  parseDnsenum,
		verify: verifyName("dnsenum"),
	})

	register(&Connector{
		Name: "fierce", Binary: "fierce", Category: CatDNS, TargetKind: TgtDomain,
		Desc:     "Locate non-contiguous IP space and hostnames for a domain.",
		Profiles: []Profile{{"default", "Standard scan"}},
		build: func(c *Connector, r Request) ([]string, error) {
			return []string{"--domain", r.Target}, nil
		},
		parse:  parseFierce,
		verify: verifyName("fierce"),
	})

	// ---- OSINT ----
	register(&Connector{
		Name: "whois", Binary: "whois", Category: CatOSINT, TargetKind: TgtDomain,
		Desc:     "Domain registration lookup.",
		Profiles: []Profile{{"lookup", "Query the whois record"}},
		build:    func(c *Connector, r Request) ([]string, error) { return []string{r.Target}, nil },
		parse:    parseWhois,
		verify:   verifyName("whois"),
	})
}

// findWordlist returns the first installed content-discovery wordlist. If none
// is installed, it writes a built-in common-paths list to ~/.daru and uses
// that, so gobuster/ffuf work out of the box without seclists.
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
	return builtinWordlist()
}

// builtinWordlist materializes a bundled common-paths list on disk and returns
// its path. It is small but covers the paths that matter for a quick sweep.
func builtinWordlist() (string, error) {
	home, _ := os.UserHomeDir()
	if home == "" {
		home = os.TempDir()
	}
	dir := filepath.Join(home, ".daru", "wordlists")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("could not create wordlist dir: %w", err)
	}
	path := filepath.Join(dir, "common.txt")
	if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
		return path, nil
	}
	if err := os.WriteFile(path, []byte(commonPaths), 0o600); err != nil {
		return "", fmt.Errorf("could not write built-in wordlist: %w", err)
	}
	return path, nil
}

// commonPaths is a compact content-discovery wordlist bundled with Daru.
const commonPaths = `admin
administrator
login
logout
register
signup
signin
dashboard
api
api/v1
api/v2
graphql
health
healthz
status
metrics
debug
test
dev
staging
backup
backups
old
tmp
temp
config
config.php
configuration
settings
.env
.git
.git/config
.gitignore
.svn
.htaccess
.htpasswd
robots.txt
sitemap.xml
crossdomain.xml
phpinfo.php
info.php
server-status
server-info
wp-admin
wp-login.php
wp-content
wp-config.php
wp-json
xmlrpc.php
user
users
account
accounts
profile
upload
uploads
files
file
images
img
assets
static
css
js
download
downloads
console
shell
cmd
db
database
sql
phpmyadmin
pma
adminer
manager
management
portal
secure
private
internal
public
cgi-bin
includes
inc
lib
vendor
node_modules
.well-known
swagger
swagger-ui
swagger.json
openapi.json
docs
documentation
readme
readme.md
changelog
license
version
`

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
