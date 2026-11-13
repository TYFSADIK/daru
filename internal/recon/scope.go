package recon

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// MaxCIDRBits is the largest range a scan may cover: /16 (65,536 addresses).
// Anything larger is rejected in the scope guard.
const MaxCIDRBits = 16

// ValidateTarget checks a target against its connector's kind and the scope
// guard. It returns a normalized target or an error.
func ValidateTarget(c *Connector, r Request) (string, error) {
	t := strings.TrimSpace(r.Target)
	if strings.HasPrefix(t, "-") {
		return "", fmt.Errorf("target must not start with '-'")
	}
	switch c.TargetKind {
	case TgtNone:
		return "", nil
	case TgtPcap:
		return validatePcapPath(t)
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
		if err := guardHost(t, r.AllowExternal); err != nil {
			return "", err
		}
		return t, nil
	case TgtHost, TgtCIDR:
		return guardHostOrCIDR(t, c.TargetKind == TgtCIDR, r.AllowExternal)
	}
	return "", fmt.Errorf("unsupported target kind")
}

// PcapAllowDirs returns the directories a direct tshark-pcap scan may read
// from: DARU_PCAP_DIR (comma separated) plus the default upload directory.
func PcapAllowDirs() []string {
	var dirs []string
	if v := strings.TrimSpace(os.Getenv("DARU_PCAP_DIR")); v != "" {
		for _, d := range strings.Split(v, ",") {
			if d = strings.TrimSpace(d); d != "" {
				dirs = append(dirs, d)
			}
		}
	}
	dirs = append(dirs, filepath.Join(os.TempDir(), "daru-pcap"))
	return dirs
}

// validatePcapPath checks a capture file path for a direct tshark-pcap scan.
// The path must exist, be a regular .pcap or .pcapng file, and live under an
// allowlisted directory after symlinks are resolved. Absolute paths outside
// the allowlist, and /etc, /dev, and /proc, are always rejected.
func validatePcapPath(t string) (string, error) {
	if t == "" {
		return "", fmt.Errorf("a capture file path is required")
	}
	lower := strings.ToLower(t)
	if !(strings.HasSuffix(lower, ".pcap") || strings.HasSuffix(lower, ".pcapng")) {
		return "", fmt.Errorf("capture file must end in .pcap or .pcapng")
	}
	for _, bad := range []string{"/etc/", "/etc", "/dev/", "/dev", "/proc/", "/proc"} {
		if t == bad || strings.HasPrefix(t, bad+"/") {
			return "", fmt.Errorf("capture file path is not allowed")
		}
	}
	resolved, err := filepath.EvalSymlinks(t)
	if err != nil {
		return "", fmt.Errorf("capture file not found or unreadable")
	}
	fi, err := os.Stat(resolved)
	if err != nil || fi.IsDir() || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("capture file not found or not a regular file")
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("capture file path is not allowed")
	}
	for _, dir := range PcapAllowDirs() {
		dabs, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		if abs == dabs || strings.HasPrefix(abs, dabs+string(filepath.Separator)) {
			return abs, nil
		}
	}
	return "", fmt.Errorf("capture file must be under an allowlisted directory (DARU_PCAP_DIR or the pcap upload directory)")
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
		return hostnameIsPrivate(t)
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
	if strings.Contains(t, "/") {
		if !allowCIDR {
			return "", fmt.Errorf("this connector does not accept a CIDR range")
		}
		_, ipnet, err := net.ParseCIDR(t)
		if err != nil {
			return "", fmt.Errorf("invalid CIDR range")
		}
		if !allowExternal && !isPrivateNet(ipnet) {
			return "", fmt.Errorf("target %s is outside private ranges; set allow_external only when you are authorized to scan it", t)
		}
		if ones, bits := ipnet.Mask.Size(); bits-ones > (32 - MaxCIDRBits) {
			return "", fmt.Errorf("range %s is larger than /%d; narrow the scope", t, MaxCIDRBits)
		}
		return t, nil
	}
	if ip := net.ParseIP(t); ip != nil {
		if err := guardIP(ip, allowExternal); err != nil {
			return "", err
		}
		return t, nil
	}
	if !hostName(t) {
		return "", fmt.Errorf("invalid host")
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

// guardResolvedHost resolves a hostname and rejects it unless every address
// it maps to is private (when external scanning was not authorized). An
// unresolvable name is rejected: fail closed, the tool must not resolve it
// again later to a different address.
func guardResolvedHost(host string, allowExternal bool) (string, error) {
	if allowExternal {
		return host, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("host %s could not be resolved; refusing to scan an unresolvable host", host)
	}
	for _, ip := range ips {
		if !isPrivateIP(ip) {
			return "", fmt.Errorf("host %s resolves to a public address %s; set allow_external when authorized", host, ip)
		}
	}
	return host, nil
}

// resolveHostIP resolves a hostname and returns its first private IP, or an
// error when it does not resolve or resolves to a public address. Used to pin
// a scan to the address that was checked, immediately before exec.
func resolveHostIP(host string, allowExternal bool) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if err := guardIP(ip, allowExternal); err != nil {
			return "", err
		}
		return ip.String(), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("host %s could not be resolved; refusing to scan an unresolvable host", host)
	}
	for _, ip := range ips {
		if !allowExternal && !isPrivateIP(ip) {
			return "", fmt.Errorf("host %s resolves to a public address %s; set allow_external when authorized", host, ip)
		}
	}
	return ips[0].String(), nil
}

func guardIP(ip net.IP, allowExternal bool) error {
	if allowExternal || isPrivateIP(ip) {
		return nil
	}
	return fmt.Errorf("target %s is a public address; set allow_external only when you are authorized to scan it", ip)
}

var privateNets []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "::1/128", "fe80::/10", "169.254.0.0/16",
	} {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			privateNets = append(privateNets, n)
		}
	}
}

// isPrivateIP reports whether an address is in an explicit RFC1918, loopback,
// or link-local range. It deliberately does not use net.IP.IsPrivate, which
// also covers CGNAT 100.64.0.0/10, benchmarking 198.18.0.0/15, and other
// space that is not the operator's own network.
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isPrivateNet(n *net.IPNet) bool {
	if n == nil {
		return false
	}
	if !isPrivateIP(n.IP) {
		return false
	}
	_, bits := n.Mask.Size()
	if bits == 0 {
		return false
	}
	last := lastIP(n)
	return isPrivateIP(last)
}

func lastIP(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	if ip == nil {
		ip = n.IP.To16()
		if ip == nil {
			return n.IP
		}
	}
	out := make(net.IP, len(ip))
	copy(out, ip)
	for i := range out {
		out[i] |= ^n.Mask[i]
	}
	return out
}

func hostName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if strings.HasPrefix(s, "-") || strings.HasPrefix(s, ".") || strings.HasSuffix(s, "-") || strings.HasSuffix(s, ".") {
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
