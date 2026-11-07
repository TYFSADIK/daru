package recon

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateTarget checks a target against its connector's kind and the scope
// guard. It returns a normalized target or an error.
func ValidateTarget(c *Connector, r Request) (string, error) {
	t := strings.TrimSpace(r.Target)
	switch c.TargetKind {
	case TgtNone:
		return "", nil
	case TgtPcap:
		if t == "" {
			return "", fmt.Errorf("a capture file path is required")
		}
		return t, nil
	case TgtIface:
		if !ifaceName(t) {
			return "", fmt.Errorf("invalid interface name")
		}
		return t, nil
	case TgtURL:
		u, err := url.Parse(t)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return "", fmt.Errorf("target must be an http or https URL")
		}
		if err := guardHost(u.Hostname(), r.AllowExternal); err != nil {
			return "", err
		}
		return t, nil
	case TgtDomain:
		if !domainName(t) {
			return "", fmt.Errorf("invalid domain name")
		}
		return t, nil
	case TgtHost, TgtCIDR:
		return guardHostOrCIDR(t, c.TargetKind == TgtCIDR, r.AllowExternal)
	}
	return "", fmt.Errorf("unsupported target kind")
}

// ScanIsLocal reports whether a scan stays on the local environment: a blank
// target for a local tool, a private or loopback IP or CIDR, a local file or
// interface, or a hostname that resolves only to private addresses. External
// scans (public IPs, domains, or allow_external) are not local and still go
// through the authorization gate.
func ScanIsLocal(c *Connector, r Request) bool {
	if r.AllowExternal {
		return false
	}
	t := strings.TrimSpace(r.Target)
	if t == "" {
		return c.AllowEmptyTarget
	}
	switch c.TargetKind {
	case TgtNone, TgtIface, TgtPcap:
		return true
	case TgtDomain:
		return false
	case TgtURL:
		u, err := url.Parse(t)
		if err != nil || u.Hostname() == "" {
			return false
		}
		return hostnameIsPrivate(u.Hostname())
	case TgtHost, TgtCIDR:
		if strings.Contains(t, "/") {
			_, ipnet, err := net.ParseCIDR(t)
			return err == nil && isPrivateNet(ipnet)
		}
		if ip := net.ParseIP(t); ip != nil {
			return isPrivateIP(ip)
		}
		return hostnameIsPrivate(t)
	}
	return false
}

// hostnameIsPrivate resolves a hostname and reports whether every address it
// maps to is private. An unresolvable name is treated as not private.
func hostnameIsPrivate(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return isPrivateIP(ip)
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !isPrivateIP(ip) {
			return false
		}
	}
	return true
}

func guardHostOrCIDR(t string, allowCIDR, allowExternal bool) (string, error) {
	kind := "a host or IP (e.g. 192.168.1.10)"
	if allowCIDR {
		kind = "a host, IP, or CIDR (e.g. 192.168.1.10 or 192.168.1.0/24)"
	}
	if t == "" {
		return "", fmt.Errorf("this tool needs a target: enter %s", kind)
	}
	if strings.Contains(t, "://") {
		return "", fmt.Errorf("enter %s, not a URL; remove the http:// part", kind)
	}
	// Accept host:port by keeping the host; the port belongs in the Ports field.
	if h, _, err := net.SplitHostPort(t); err == nil && h != "" {
		t = h
	}
	if strings.Contains(t, "/") {
		if !allowCIDR {
			return "", fmt.Errorf("this connector does not accept a CIDR range; enter a single host or IP")
		}
		_, ipnet, err := net.ParseCIDR(t)
		if err != nil {
			return "", fmt.Errorf("invalid CIDR range")
		}
		if !allowExternal && !isPrivateNet(ipnet) {
			return "", fmt.Errorf("target %s is outside private ranges; set allow_external only when you are authorized to scan it", t)
		}
		if ones, bits := ipnet.Mask.Size(); bits-ones > 20 {
			return "", fmt.Errorf("range %s is larger than /12; narrow the scope", t)
		}
		return t, nil
	}
	if ip := net.ParseIP(t); ip != nil {
		if err := guardIP(ip, allowExternal); err != nil {
			return "", err
		}
		return t, nil
	}
	// Hostname.
	if !hostName(t) {
		return "", fmt.Errorf("invalid target %q: enter %s", t, kind)
	}
	return guardResolvedHost(t, allowExternal)
}

func guardHost(host string, allowExternal bool) error {
	if ip := net.ParseIP(host); ip != nil {
		return guardIP(ip, allowExternal)
	}
	_, err := guardResolvedHost(host, allowExternal)
	return err
}

// guardResolvedHost resolves a hostname and rejects it if it only points at
// public addresses and external scanning was not authorized.
func guardResolvedHost(host string, allowExternal bool) (string, error) {
	if allowExternal {
		return host, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		// Cannot resolve now: allow, but the tool itself will fail if truly dead.
		return host, nil
	}
	for _, ip := range ips {
		if isPrivateIP(ip) {
			return host, nil
		}
	}
	return "", fmt.Errorf("host %s resolves only to public addresses; set allow_external when authorized", host)
}

func guardIP(ip net.IP, allowExternal bool) error {
	if allowExternal || isPrivateIP(ip) {
		return nil
	}
	return fmt.Errorf("target %s is a public address; set allow_external only when you are authorized to scan it", ip)
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}
	return false
}

func isPrivateNet(n *net.IPNet) bool {
	return isPrivateIP(n.IP)
}

func hostName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func domainName(s string) bool {
	return hostName(s) && strings.Contains(s, ".")
}

func ifaceName(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_') {
			return false
		}
	}
	return true
}

// validPorts allows specs like "80", "1-1000", "22,80,443", "U:53,T:80".
func validPorts(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r == ',' || r == '-' || r == ':' || r == 'U' || r == 'T' || r == '*') {
			return false
		}
	}
	return len(s) <= 256
}
