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
	"fmt"
	"os/exec"
	"sort"
	"strings"
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
	// build returns the command arguments for a request.
	build func(c *Connector, r Request) ([]string, error)
	// parse turns stdout into findings. A nil parse uses genericParse.
	parse func(out []byte, r Request) []Finding
}

// Profile is a named preset for a connector.
type Profile struct {
	Name string `json:"name"`
	Desc string `json:"desc"`
}

// Available reports whether the connector's binary is installed.
func (c *Connector) Available() bool {
	_, err := exec.LookPath(c.Binary)
	return err == nil
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
}

// List returns connector info for the UI.
func List() []Info {
	var out []Info
	for _, c := range Registry {
		out = append(out, Info{
			Name: c.Name, Binary: c.Binary, Category: string(c.Category),
			TargetKind: string(c.TargetKind), Desc: c.Desc, Profiles: c.Profiles,
			Available: c.Available(), NeedsRoot: c.NeedsRoot,
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
		ln = strings.TrimRight(ln, "\r")
		t := strings.TrimSpace(ln)
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
	if c.parse != nil {
		return c.parse(out, r)
	}
	return genericParse(out, r)
}
