// Package recon runs external security tools against authorized targets and
// turns their output into Daru findings and events. Every scan is gated behind
// an authorization reference and an explicit permission confirmation, and the
// target is checked against a scope guard. The package only ever runs a tool
// the operator already has installed; nothing is bundled.
//
// By design this package contains no denial-of-service tooling, no mass or
// untargeted exploitation, and no anti-virus evasion. It is for authorized
// assessment, CTFs, and security research on systems you own or may test.
package recon

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Category groups connectors for the UI.
type Category string

const (
	CatPortScan Category = "Port & host discovery"
	CatVulnScan Category = "Vulnerability scanning"
	CatWebScan  Category = "Web scanning"
	CatDNS      Category = "DNS & subdomains"
	CatOSINT    Category = "OSINT"
	CatTLS      Category = "TLS/SSL"
	CatTraffic  Category = "Traffic & protocol analysis"
	CatEnum     Category = "Service enumeration"
)

// TargetKind constrains and validates what a connector accepts.
type TargetKind string

const (
	TgtHost   TargetKind = "host"   // hostname or IP
	TgtCIDR   TargetKind = "cidr"   // host, IP, or CIDR range
	TgtURL    TargetKind = "url"    // http(s) URL
	TgtDomain TargetKind = "domain" // DNS domain
	TgtIface  TargetKind = "iface"  // capture interface
	TgtPcap   TargetKind = "pcap"   // path to a capture file
	TgtNone   TargetKind = "none"
)

// Request describes a scan the operator asked for.
type Request struct {
	Connector        string            `json:"connector"`
	Target           string            `json:"target"`
	Profile          string            `json:"profile"` // connector-specific preset
	Ports            string            `json:"ports"`   // optional port spec
	ExtraArgs        []string          `json:"-"`       // never taken from the client
	AuthorizationRef string            `json:"authorization_ref"`
	Confirmed        bool              `json:"confirmed"`      // operator confirmed permission
	AllowExternal    bool              `json:"allow_external"` // permit public (non-private) targets
	Options          map[string]string `json:"options"`
	// Scheduled marks a request created by the scheduler, not by an
	// interactive user. Scheduled requests are validated by
	// ValidateScheduled in run.go and never get a free pass.
	Scheduled bool   `json:"scheduled,omitempty"`
	Source    string `json:"source,omitempty"` // "ui", "schedule", "api"
}

// Finding is one structured result from a scan.
type Finding struct {
	Title    string            `json:"title"`
	Severity string            `json:"severity"` // info, low, medium, high, critical
	Target   string            `json:"target"`
	Port     string            `json:"port,omitempty"`
	Service  string            `json:"service,omitempty"`
	Detail   string            `json:"detail,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"`
	// MITRE ATT&CK mapping, populated centrally in runParse/runNative.
	MitreTactic    string `json:"mitre_tactic,omitempty"`
	MitreTechnique string `json:"mitre_technique,omitempty"`
}

// MaxFindings caps the findings any single scan may store.
const MaxFindings = 5000

// capFindings bounds a finding list and appends a truncation finding when
// the parser produced more than MaxFindings.
func capFindings(findings []Finding, target string) []Finding {
	if len(findings) <= MaxFindings {
		return findings
	}
	out := append([]Finding(nil), findings[:MaxFindings]...)
	out = append(out, Finding{
		Title:    fmt.Sprintf("Results truncated at %d findings (refine the target or profile)", MaxFindings),
		Severity: "info", Target: target, Service: "truncated",
	})
	return out
}

// mitreForConnector maps a connector to its MITRE ATT&CK tactic and
// technique. Unknown connectors fall back to Reconnaissance.
func mitreForConnector(name string) (string, string) {
	if m, ok := mitreMap[name]; ok {
		return m[0], m[1]
	}
	return "Reconnaissance", "TA0043"
}

var mitreMap = map[string][2]string{
	"nmap": {"Reconnaissance", "T1595.002"}, "masscan": {"Reconnaissance", "T1595.002"},
	"zmap": {"Reconnaissance", "T1595.002"}, "naabu": {"Reconnaissance", "T1595.002"},
	"rustscan": {"Reconnaissance", "T1595.002"}, "fping": {"Reconnaissance", "T1595.001"},
	"hping3": {"Reconnaissance", "T1595.001"}, "nbtscan": {"Reconnaissance", "T1595.001"},
	"traceroute": {"Reconnaissance", "T1595.001"}, "netdiscover": {"Reconnaissance", "T1595.001"},
	"deep-scan": {"Reconnaissance", "T1595.002"}, "unicornscan": {"Reconnaissance", "T1595.002"},
	"nuclei": {"Initial Access", "T1190"}, "nikto": {"Initial Access", "T1190"},
	"wapiti": {"Initial Access", "T1190"}, "sqlmap": {"Initial Access", "T1190"},
	"dalfox": {"Initial Access", "T1190"}, "wpscan": {"Initial Access", "T1190"},
	"httpx": {"Reconnaissance", "T1595.003"}, "whatweb": {"Reconnaissance", "T1595.003"},
	"wafw00f": {"Reconnaissance", "T1595.003"}, "katana": {"Reconnaissance", "T1595.003"},
	"gobuster": {"Reconnaissance", "T1595.003"}, "ffuf": {"Reconnaissance", "T1595.003"},
	"hakrawler": {"Reconnaissance", "T1595.003"}, "waybackurls": {"Reconnaissance", "T1595.003"},
	"gau": {"Reconnaissance", "T1595.003"}, "assetfinder": {"Reconnaissance", "T1595.002"},
	"subfinder": {"Reconnaissance", "T1595.002"}, "amass": {"Reconnaissance", "T1595.002"},
	"dnsrecon": {"Reconnaissance", "T1595.002"}, "dnsenum": {"Reconnaissance", "T1595.002"},
	"fierce": {"Reconnaissance", "T1595.002"}, "dnstwist": {"Reconnaissance", "T1595.002"},
	"crtsh": {"Reconnaissance", "T1595.002"}, "dns-records": {"Reconnaissance", "T1595.002"},
	"dnsx": {"Reconnaissance", "T1595.002"}, "theharvester": {"Reconnaissance", "T1595.002"},
	"whois": {"Reconnaissance", "T1595.002"}, "rdap": {"Reconnaissance", "T1595.002"},
	"sslyze": {"Credential Access", "T1552.004"}, "testssl": {"Credential Access", "T1552.004"},
	"sslscan": {"Credential Access", "T1552.004"}, "tls-cert": {"Credential Access", "T1552.004"},
	"smbmap": {"Discovery", "T1135"}, "smb-enum": {"Discovery", "T1135"},
	"enum4linux": {"Discovery", "T1135"}, "enum4linux-ng": {"Discovery", "T1135"},
	"snmpwalk": {"Discovery", "T1046"}, "onesixtyone": {"Discovery", "T1046"},
	"trufflehog":     {"Credential Access", "T1552.001"},
	"tshark-capture": {"Collection", "T1040"}, "tshark-pcap": {"Collection", "T1040"},
	"tcpdump": {"Collection", "T1040"},
}

// applyMitre fills MITRE fields on findings that do not already carry them.
func applyMitre(connector string, findings []Finding) []Finding {
	tactic, tech := mitreForConnector(connector)
	for i := range findings {
		if findings[i].MitreTactic == "" {
			findings[i].MitreTactic = tactic
		}
		if findings[i].MitreTechnique == "" {
			findings[i].MitreTechnique = tech
		}
	}
	return findings
}

// ExternalAllowlist is the server side allowlist of external targets an
// operator may scan without per-scan approval: exact hosts, IPs, or CIDRs.
// Empty means no allowlist is configured, so external scans still need a
// confirmation and an authorization reference. Set it with
// SetExternalAllowlist, for example from DARU_EXTERNAL_ALLOWLIST.
var ExternalAllowlist []string

// SetExternalAllowlist replaces the external target allowlist.
func SetExternalAllowlist(entries []string) {
	ExternalAllowlist = append([]string(nil), entries...)
}

// externalAllowed reports whether a target matches the allowlist.
func externalAllowed(target string) bool {
	if len(ExternalAllowlist) == 0 {
		return false
	}
	t := strings.TrimSpace(target)
	for _, e := range ExternalAllowlist {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.EqualFold(e, t) {
			return true
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			if ip := net.ParseIP(t); ip != nil && n.Contains(ip) {
				return true
			}
		}
		if strings.Contains(t, "/") {
			if _, n, err := net.ParseCIDR(t); err == nil {
				if _, en, err := net.ParseCIDR(e); err == nil && en.Contains(n.IP) {
					return true
				}
			}
		}
	}
	return false
}

// Connector describes one external tool Daru can drive.
type Connector struct {
	Name       string
	Binary     string
	Category   Category
	TargetKind TargetKind
	Desc       string
	Profiles   []Profile
	NeedsRoot  bool
	// AllowEmptyTarget lets a connector run with no target (e.g. netdiscover
	// auto-detecting the local network).
	AllowEmptyTarget bool
	// build returns the command arguments for a request.
	build func(c *Connector, r Request) ([]string, error)
	// parse turns stdout into findings. A nil parse uses genericParse.
	parse func(out []byte, r Request) []Finding
	// native, when set, collects findings in-process without an external
	// binary (for passive OSINT such as crt.sh, DNS, and TLS inspection).
	native func(ctx context.Context, r Request) ([]Finding, error)
	// verify, when set, confirms a resolved binary path is really the tool
	// this connector expects. It guards against an unrelated program of the
	// same name shadowing the right one on PATH (for example the Python
	// "httpx" HTTP client vs. ProjectDiscovery's "httpx" prober).
	verify func(path string) bool
	// stdinTarget, when true, feeds the validated target to the tool's stdin
	// instead of as an argument (for tools like dnsx that read hosts on stdin).
	stdinTarget bool
}

// IsNative reports whether the connector runs in-process.
func (c *Connector) IsNative() bool { return c.native != nil }

// Profile is a named preset for a connector.
type Profile struct {
	Name string `json:"name"`
	Desc string `json:"desc"`
}

// Available reports whether the connector can run: native connectors always
// can; external ones need their binary installed.
func (c *Connector) Available() bool {
	if c.native != nil {
		return true
	}
	return c.resolve() != ""
}

// resolve returns the path of the binary this connector should run, honoring
// an optional verifier that rejects a wrong same-named program.
func (c *Connector) resolve() string {
	return resolveBinaryVerified(c.Binary, c.verify)
}

// extraBinDirs lists common install locations a service PATH often misses:
// Go tools (~/go/bin), user/pipx installs (~/.local/bin), sbin dirs, snap,
// and Homebrew. Daru searches these so a tool installed by the recon script
// is found no matter how daru was launched.
// isRootOwnedDir reports whether a directory is owned by root and not
// writable by anyone other than root. A directory writable by the root
// group is still root-controlled; a world-writable one, or one owned by a
// non-root user, is not. Used when Daru runs as root, so a binary planted
// in a user-writable directory is never executed with privilege.
func isRootOwnedDir(dir string) bool {
	fi, err := os.Stat(dir) // #nosec G703 -- dir comes from PATH and well-known tool dirs, and is only stat'ed
	if err != nil || !fi.IsDir() {
		return false
	}
	uid, gid, ok := fileOwner(fi)
	if !ok {
		return false
	}
	if uid != 0 || fi.Mode().Perm()&0o002 != 0 {
		return false
	}
	if fi.Mode().Perm()&0o020 != 0 && gid != 0 {
		return false
	}
	return true
}

// extraBinDirs lists common install locations a service PATH often misses:
// Go tools (~/go/bin), user/pipx installs (~/.local/bin), sbin dirs, snap,
// and Homebrew. Daru searches these so a tool installed by the recon script
// is found no matter how daru was launched.
//
// When Daru runs as root (euid 0), user-writable directories and SUDO_USER
// home directories are excluded: a low-privilege user who can write their
// own ~/go/bin must never get a binary executed as root.
func extraBinDirs() []string {
	home, _ := os.UserHomeDir()
	root := os.Geteuid() == 0
	dirs := []string{}
	add := func(d string) {
		if d == "" {
			return
		}
		if root && !isRootOwnedDir(d) {
			return
		}
		dirs = append(dirs, d)
	}
	if gb := os.Getenv("GOBIN"); gb != "" {
		add(gb)
	}
	if gp := os.Getenv("GOPATH"); gp != "" {
		add(filepath.Join(gp, "bin"))
	}
	if home != "" {
		if !root || home == "/root" {
			add(filepath.Join(home, "go", "bin"))
			add(filepath.Join(home, ".local", "bin"))
		}
	}
	// SUDO_USER home directories are never trusted when running as root.
	if !root {
		if u := os.Getenv("SUDO_USER"); u != "" {
			uh := filepath.Join("/home", u)
			add(filepath.Join(uh, "go", "bin"))
			add(filepath.Join(uh, ".local", "bin"))
		}
	}
	dirs = append(dirs,
		"/root/go/bin", "/root/.local/bin",
		"/usr/local/bin", "/usr/local/sbin", "/usr/sbin", "/sbin",
		"/snap/bin", "/opt/homebrew/bin", "/opt/homebrew/sbin")
	return dirs
}

// binarySafeForRoot reports whether a candidate binary may be executed when
// Daru runs as root: owned by root, never world writable, and group
// writable only when the group is root.
func binarySafeForRoot(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return false
	}
	uid, gid, ok := fileOwner(fi)
	if !ok {
		return false
	}
	if uid != 0 || fi.Mode().Perm()&0o002 != 0 {
		return false
	}
	if fi.Mode().Perm()&0o020 != 0 && gid != 0 {
		return false
	}
	return true
}

// resolveBinary returns the absolute path of an executable found on PATH or in
// one of the extra bin dirs, or "" if it is not installed.
func resolveBinary(name string) string {
	return resolveBinaryVerified(name, nil)
}

// resolveBinaryVerified is like resolveBinary but, when verify is non-nil,
// returns the first candidate path that passes verify. If no candidate passes,
// it returns "" so the connector is reported as unavailable rather than
// running the wrong program.
func resolveBinaryVerified(name string, verify func(string) bool) string {
	if name == "" {
		return ""
	}
	var cands []string
	if p, err := exec.LookPath(name); err == nil {
		cands = append(cands, p)
	}
	for _, d := range extraBinDirs() {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			cands = append(cands, p)
		}
	}
	for _, p := range cands {
		if os.Geteuid() == 0 && !binarySafeForRoot(p) {
			continue
		}
		if verify == nil || verify(p) {
			return p
		}
	}
	return ""
}

// verifyName returns a verifier that runs "<path> -h" and requires the help
// text to mention the tool name (or one of the extra markers). It rejects a
// wrong same-named program shadowing the real tool. Fail closed: a tool
// whose help cannot be confirmed is reported as unavailable.
func verifyName(name string, extra ...string) func(string) bool {
	return verifyHelpContains("-h", append([]string{name}, extra...)...)
}

// binVerifyCache memoizes verifier results per path; List() calls Available()
// for every connector, and we do not want to exec a tool on each listing.
var binVerifyCache sync.Map // path -> bool

// verifyHelpContains runs "<path> <probeArg>" with a short timeout and reports
// whether the combined output contains any of the wanted markers (lowercased).
// It is used to tell same-named tools apart by their help/banner text.
func verifyHelpContains(probeArg string, wanted ...string) func(string) bool {
	return func(path string) bool {
		if v, ok := binVerifyCache.Load(path); ok {
			return v.(bool)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, _ := exec.CommandContext(ctx, path, probeArg).CombinedOutput() // #nosec G204 -- recon tools run as an argv list (no shell) from a vetted binary path
		low := strings.ToLower(string(out))
		ok := false
		for _, w := range wanted {
			if strings.Contains(low, strings.ToLower(w)) {
				ok = true
				break
			}
		}
		binVerifyCache.Store(path, ok)
		return ok
	}
}

// execPATH returns a PATH value that includes the extra bin dirs, so a tool
// that shells out to another tool (for example nuclei calling httpx) can find
// it even when daru was started with a minimal PATH.
func execPATH() string {
	parts := []string{}
	if p := os.Getenv("PATH"); p != "" {
		parts = append(parts, p)
	}
	parts = append(parts, extraBinDirs()...)
	return strings.Join(parts, string(os.PathListSeparator))
}

// Registry holds all connectors by name.
var Registry = map[string]*Connector{}

func register(c *Connector) {
	Registry[c.Name] = c
}

// List returns connectors sorted by category then name, with availability.
type Info struct {
	Name       string    `json:"name"`
	Binary     string    `json:"binary"`
	Category   string    `json:"category"`
	TargetKind string    `json:"target_kind"`
	Desc       string    `json:"desc"`
	Profiles   []Profile `json:"profiles"`
	Available  bool      `json:"available"`
	NeedsRoot  bool      `json:"needs_root"`
	AllowEmpty bool      `json:"allow_empty"` // target may be left blank
}

// List returns connector info for the UI.
func List() []Info {
	var out []Info
	for _, c := range Registry {
		out = append(out, Info{
			Name: c.Name, Binary: c.Binary, Category: string(c.Category),
			TargetKind: string(c.TargetKind), Desc: c.Desc, Profiles: c.Profiles,
			Available: c.Available(), NeedsRoot: c.NeedsRoot, AllowEmpty: c.AllowEmptyTarget,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Get returns a connector by name.
func Get(name string) (*Connector, bool) {
	c, ok := Registry[name]
	return c, ok
}

// genericParse records notable non-empty output lines as info findings.
func genericParse(out []byte, r Request) []Finding {
	var findings []Finding
	lines := strings.Split(string(out), "\n")
	for _, ln := range lines {
		t := stripANSI(ln)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		findings = append(findings, Finding{
			Title: t, Severity: "info", Target: r.Target,
		})
		if len(findings) >= 5000 {
			break
		}
	}
	return findings
}

func (c *Connector) runArgs(r Request) ([]string, error) {
	if c.build == nil {
		return nil, fmt.Errorf("connector %q has no argument builder", c.Name)
	}
	return c.build(c, r)
}

func (c *Connector) runParse(out []byte, r Request) []Finding {
	var findings []Finding
	if c.parse != nil {
		findings = c.parse(out, r)
	} else {
		findings = genericParse(out, r)
	}
	return applyMitre(c.Name, capFindings(findings, r.Target))
}
