package recon

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// netdiscover is a native LAN device discovery connector. It finds live hosts
// without needing root by seeding the system ARP cache with a quick TCP sweep,
// then reading the ARP table for MAC addresses, resolving vendors from the
// nmap MAC-prefix database, and reverse-resolving hostnames.
func init() {
	register(&Connector{
		Name: "netdiscover", Binary: "", Category: CatPortScan, TargetKind: TgtCIDR,
		AllowEmptyTarget: true,
		Desc:             "Discover live devices on a local network (IP, MAC, vendor, hostname). Leave the target blank to scan your own network.",
		Profiles: []Profile{
			{"arp", "arp-scan when available (finds every device), else ARP cache plus a TCP sweep"},
			{"quick", "Sweep common ports to find more hosts"},
		},
		native: netDiscover,
	})
}

var sweepPorts = []string{"80", "443", "22", "53", "445", "139", "8080", "7", "23", "3389"}

func netDiscover(ctx context.Context, r Request) ([]Finding, error) {
	target := strings.TrimSpace(r.Target)
	var nets []*net.IPNet
	if target == "" {
		nets = dedupeNets(localNets())
		if len(nets) == 0 {
			return nil, fmt.Errorf("could not determine a local network; set a target CIDR such as 192.168.1.0/24")
		}
	} else {
		_, n, err := net.ParseCIDR(target)
		if err != nil {
			return nil, fmt.Errorf("target must be a CIDR such as 192.168.1.0/24")
		}
		nets = []*net.IPNet{n}
	}

	for _, ipnet := range nets {
		if ones, bits := ipnet.Mask.Size(); bits-ones > 16 {
			return nil, fmt.Errorf("range %s is too large for discovery; use /16 or smaller", ipnet.String())
		}
	}

	resolve := func(ip string) string { return reverseName(ctx, ip) }
	macs := map[string]string{}
	vendorOverride := map[string]string{}

	// Preferred path: arp-scan sends real ARP requests, so it finds every
	// layer-2 device including silent ones that answer no TCP. It needs
	// CAP_NET_RAW (see scripts/grant-capabilities.sh); if that is missing it
	// errors and we fall back to the TCP sweep below.
	if m, v, err := arpScan(ctx, nets); err == nil && len(m) > 0 {
		for ip, mac := range m {
			macs[ip] = mac
		}
		for ip, ven := range v {
			vendorOverride[ip] = ven
		}
	}

	// Fallback / supplement: seed the ARP cache with a quick TCP sweep, then
	// read the OS ARP table. This needs no privileges but only finds hosts
	// with an open port.
	if len(macs) == 0 {
		var allHosts []string
		for _, ipnet := range nets {
			allHosts = append(allHosts, enumerateHosts(ipnet)...)
		}
		sweepHosts(ctx, allHosts)
		select {
		case <-ctx.Done():
		case <-time.After(600 * time.Millisecond):
		}
	}
	for ip, mac := range readARPTable() {
		if _, ok := macs[ip]; !ok {
			macs[ip] = mac
		}
	}

	findings := devicesFromScan(macs, vendorOverride, nets, loadMACPrefixes(), resolve)
	if len(findings) == 0 {
		return nil, fmt.Errorf("no devices found. Install arp-scan and grant it CAP_NET_RAW (sh scripts/grant-capabilities.sh), or try the nmap discovery profile")
	}
	return findings, nil
}

// arpScan runs arp-scan against each network and parses ip, mac, and vendor.
// Returns an error if arp-scan is not installed or has no permission; callers
// fall back to the sweep method.
func arpScan(ctx context.Context, nets []*net.IPNet) (map[string]string, map[string]string, error) {
	bin := firstExisting("arp-scan", "/usr/sbin/arp-scan", "/usr/bin/arp-scan", "/opt/homebrew/bin/arp-scan")
	if _, err := exec.LookPath(bin); err != nil {
		if _, statErr := os.Stat(bin); statErr != nil {
			return nil, nil, fmt.Errorf("arp-scan not installed")
		}
	}
	macs := map[string]string{}
	vendors := map[string]string{}
	var lastErr error
	for _, n := range nets {
		cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		cmd := exec.CommandContext(cctx, bin, "--quiet", "--ignoredups", n.String()) // #nosec G204 -- recon tools run as an argv list (no shell) from a vetted binary path
		var buf bytes.Buffer
		cmd.Stdout = capWriter(&buf, MaxToolOutputBytes)
		cmd.Stderr = capWriter(&buf, MaxToolOutputBytes)
		err := cmd.Run()
		out := buf.Bytes()
		cancel()
		if err != nil && len(out) == 0 {
			lastErr = fmt.Errorf("arp-scan on %s: %v", n.String(), err)
			continue
		}
		m, v := parseArpScan(string(out))
		for ip, mac := range m {
			macs[ip] = mac
		}
		for ip, ven := range v {
			vendors[ip] = ven
		}
	}
	if len(macs) == 0 && lastErr != nil {
		return nil, nil, lastErr
	}
	return macs, vendors, nil
}

// parseArpScan reads arp-scan output lines of the form "IP\tMAC\tVendor".
func parseArpScan(text string) (map[string]string, map[string]string) {
	macs := map[string]string{}
	vendors := map[string]string{}
	for _, m := range arpScanLineRe.FindAllStringSubmatch(text, -1) {
		ip, mac, vendor := m[1], normalizeMAC(m[2]), strings.TrimSpace(m[3])
		if mac == "" || mac == "ff:ff:ff:ff:ff:ff" || strings.HasPrefix(mac, "01:00:5e") {
			continue
		}
		macs[ip] = mac
		if vendor != "" {
			vendors[ip] = vendor
		}
	}
	return macs, vendors
}

var arpScanLineRe = regexp.MustCompile(`(?m)^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s*(.*)$`)

// buildDevices is the pure core of discovery: it turns an ARP map into device
// findings for the in-scope networks. Separated from the exec call so it can
// be tested without touching the system.
func buildDevices(arp map[string]string, nets []*net.IPNet, vendors map[string]string, resolve func(string) string) []Finding {
	return devicesFromScan(arp, nil, nets, vendors, resolve)
}

// devicesFromScan builds device findings from an ip->mac map, preferring a
// per-ip vendor override (such as the name arp-scan reports) over the
// nmap-prefix lookup.
func devicesFromScan(arp, vendorOverride map[string]string, nets []*net.IPNet, vendors map[string]string, resolve func(string) string) []Finding {
	inScope := func(ipStr string) bool {
		ip := net.ParseIP(ipStr)
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	var findings []Finding
	seen := map[string]bool{}
	for ip, mac := range arp {
		if seen[ip] || !inScope(ip) {
			continue
		}
		seen[ip] = true
		vendor := vendorOverride[ip]
		if vendor == "" || vendor == "(Unknown)" {
			vendor = vendorFor(mac, vendors)
		}
		hostname := ""
		if resolve != nil {
			hostname = resolve(ip)
		}
		title := ip
		if hostname != "" {
			title = ip + " (" + hostname + ")"
		}
		fields := map[string]string{"_kind": "host", "ip": ip, "mac": mac, "vendor": vendor}
		if hostname != "" {
			fields["hostname"] = hostname
		}
		// Infer a device type / OS hint from the MAC vendor so ARP-discovered
		// devices (which have no open-port data) still show what they are.
		if dt := deviceTypeFromVendor(vendor, hostname); dt != "" {
			fields["os"] = dt
		}
		detail := strings.TrimSpace(vendor)
		if fields["os"] != "" {
			detail = strings.TrimSpace(vendor + " · " + fields["os"])
		}
		findings = append(findings, Finding{
			Title: title, Severity: "info", Target: ip, Service: "device",
			Detail: detail, Fields: fields,
		})
	}
	sort.Slice(findings, func(i, j int) bool { return less4(findings[i].Target, findings[j].Target) })
	return findings
}

// deviceTypeFromVendor infers a device type / OS hint from the MAC vendor
// name (and hostname) for ARP-discovered devices that have no port data.
func deviceTypeFromVendor(vendor, hostname string) string {
	v := strings.ToLower(vendor + " " + hostname)
	switch {
	case v == "":
		return ""
	case strings.Contains(v, "apple"):
		return "Apple device"
	case strings.Contains(v, "samsung") || strings.Contains(v, "xiaomi") || strings.Contains(v, "huawei") || strings.Contains(v, "oneplus") || strings.Contains(v, "google") && strings.Contains(v, "pixel"):
		return "Mobile device"
	case strings.Contains(v, "raspberry"):
		return "Raspberry Pi (Linux)"
	case containsAny(v, "nintendo", "sony interactive", "playstation", "microsoft") && containsAny(v, "nintendo", "playstation", "xbox"):
		return "Game console"
	case containsAny(v, "lg electronics", "vizio", "tcl", "hisense") || (strings.Contains(v, "samsung") && strings.Contains(v, "tv")) || strings.Contains(v, "chromecast") || strings.Contains(v, "fire tv") || strings.Contains(v, "appletv") || strings.Contains(v, "apple tv"):
		return "Smart TV / streamer"
	case containsAny(v, "hikvision", "dahua", "axis communications", "wyze", "reolink", "amcrest", "ubiquiti") && strings.Contains(v, "cam"):
		return "IP camera"
	case containsAny(v, "hikvision", "dahua", "wyze", "reolink", "amcrest"):
		return "IP camera"
	case strings.Contains(v, "samsung") || strings.Contains(v, "xiaomi") || strings.Contains(v, "huawei") || strings.Contains(v, "oneplus") || strings.Contains(v, "motorola") || strings.Contains(v, "oppo") || strings.Contains(v, "vivo") || strings.Contains(v, "pixel"):
		return "Mobile device"
	case containsAny(v, "intel", "dell", "lenovo", "hon hai", "asus", "msi", "gigabyte", "micro-star", "clevo", "framework"):
		return "PC / laptop"
	case containsAny(v, "hewlett", "hp ", "canon", "epson", "brother", "lexmark", "xerox", "kyocera", "ricoh"):
		return "Printer"
	case containsAny(v, "ecobee", "nest", "ring", "tuya", "espressif", "sonos", "amazon", "roku", "shelly", "sonoff", "lifx", "philips hue", "wemo", "smartthings") || (strings.Contains(v, "tp-link") && strings.Contains(v, "smart")):
		return "IoT / smart device"
	case containsAny(v, "cisco", "ubiquiti", "netgear", "tp-link", "mikrotik", "juniper", "aruba", "arris", "technicolor", "d-link", "zyxel", "fortinet", "ruckus", "meraki"):
		return "Network device"
	case containsAny(v, "vmware", "virtualbox", "qemu", "xensource", "xen", "parallels", "proxmox"):
		return "Virtual machine"
	case containsAny(v, "synology", "qnap", "western digital", "seagate", "netapp"):
		return "NAS / storage"
	}
	return ""
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// parseARP extracts ip->mac pairs from `arp -a` style text. When an IP has
// several entries (for example a physical NIC and a bridge), it prefers a
// universally administered MAC over a locally administered virtual one.
func parseARP(text string) map[string]string {
	out := map[string]string{}
	for _, m := range arpLineRe.FindAllStringSubmatch(text, -1) {
		mac := normalizeMAC(m[2])
		if mac == "" || mac == "ff:ff:ff:ff:ff:ff" || strings.HasPrefix(mac, "01:00:5e") {
			continue
		}
		ip := m[1]
		if cur, ok := out[ip]; ok && !isLocalMAC(cur) && isLocalMAC(mac) {
			continue // keep the real NIC MAC over a virtual one
		}
		out[ip] = mac
	}
	return out
}

// isLocalMAC reports whether a MAC is locally administered (the 0x02 bit of the
// first octet is set), which marks virtual or randomized addresses.
func isLocalMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	var b int
	if _, err := fmt.Sscanf(mac[:2], "%x", &b); err != nil {
		return false
	}
	return b&0x02 != 0
}

func dedupeNets(nets []*net.IPNet) []*net.IPNet {
	seen := map[string]bool{}
	var out []*net.IPNet
	for _, n := range nets {
		if !seen[n.String()] {
			seen[n.String()] = true
			out = append(out, n)
		}
	}
	return out
}

// less4 orders dotted IPv4 strings numerically.
func less4(a, b string) bool {
	ai, bi := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if ai == nil || bi == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if ai[i] != bi[i] {
			return ai[i] < bi[i]
		}
	}
	return false
}

// localNets returns private IPv4 networks on up, non-loopback interfaces.
func localNets() []*net.IPNet {
	var out []*net.IPNet
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.To4() == nil || !n.IP.IsPrivate() {
				continue
			}
			out = append(out, &net.IPNet{IP: n.IP.Mask(n.Mask), Mask: n.Mask})
		}
	}
	return out
}

// LocalNetworks returns the detected local CIDRs as strings, for the UI.
func LocalNetworks() []string {
	var out []string
	for _, n := range localNets() {
		out = append(out, n.String())
	}
	return out
}

func enumerateHosts(ipnet *net.IPNet) []string {
	var hosts []string
	ip := ipnet.IP.Mask(ipnet.Mask).To4()
	if ip == nil {
		return hosts
	}
	for cur := cloneIP(ip); ipnet.Contains(cur); incIP(cur) {
		if cur[3] == 0 || cur[3] == 255 {
			continue // skip network and broadcast
		}
		hosts = append(hosts, cur.String())
		if len(hosts) >= 65534 {
			break
		}
	}
	return hosts
}

func sweepHosts(ctx context.Context, hosts []string) {
	sem := make(chan struct{}, 128)
	var wg sync.WaitGroup
	for _, h := range hosts {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, p := range sweepPorts[:4] {
				d := net.Dialer{Timeout: 350 * time.Millisecond}
				conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, p))
				if err == nil {
					_ = conn.Close()
					return
				}
			}
		}(h)
	}
	wg.Wait()
}

var arpLineRe = regexp.MustCompile(`\(([0-9.]+)\) at ([0-9a-fA-F:]+)`)

// readARPTable parses `arp -a` into an ip->mac map, trying `ip neigh` on Linux.
func readARPTable() map[string]string {
	out := map[string]string{}
	add := func(ip, mac string) {
		mac = normalizeMAC(mac)
		if mac == "" || strings.Count(mac, ":") != 5 {
			return
		}
		if mac == "ff:ff:ff:ff:ff:ff" || strings.HasPrefix(mac, "01:00:5e") {
			return
		}
		out[ip] = mac
	}
	// Resolve arp by absolute path first: a service may run with a PATH that
	// does not include /usr/sbin.
	arpBin := firstExisting("arp", "/usr/sbin/arp", "/sbin/arp", "/usr/bin/arp")
	var text string
	if b, err := exec.Command(arpBin, "-a", "-n").Output(); err == nil && len(b) > 0 { // #nosec G204 -- recon tools run as an argv list (no shell) from a vetted binary path
		text = string(b)
	} else if b, err := exec.Command(arpBin, "-a").Output(); err == nil { // #nosec G204 -- recon tools run as an argv list (no shell) from a vetted binary path
		text = string(b)
	}
	for ip, mac := range parseARP(text) {
		add(ip, mac)
	}
	if len(out) == 0 {
		ipBin := firstExisting("ip", "/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip")
		if b, err := exec.Command(ipBin, "neigh").Output(); err == nil { // #nosec G204 -- recon tools run as an argv list (no shell) from a vetted binary path
			sc := bufio.NewScanner(strings.NewReader(string(b)))
			for sc.Scan() {
				f := strings.Fields(sc.Text())
				if len(f) >= 5 && f[3] == "lladdr" {
					add(f[0], f[4])
				}
			}
		}
	}
	return out
}

// firstExisting returns the first path that exists, falling back to name.
func firstExisting(name string, paths ...string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return name
}

func normalizeMAC(mac string) string {
	parts := strings.Split(strings.ToLower(mac), ":")
	if len(parts) != 6 {
		return ""
	}
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}

var macPrefixesOnce sync.Once
var macPrefixes map[string]string

func loadMACPrefixes() map[string]string {
	macPrefixesOnce.Do(func() {
		macPrefixes = map[string]string{}
		paths := []string{
			"/opt/homebrew/share/nmap/nmap-mac-prefixes",
			"/usr/share/nmap/nmap-mac-prefixes",
			"/usr/local/share/nmap/nmap-mac-prefixes",
		}
		for _, p := range paths {
			f, err := os.Open(p) // #nosec G304 -- path comes from a fixed list or /sys, never from a request
			if err != nil {
				continue
			}
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := sc.Text()
				if line == "" || line[0] == '#' {
					continue
				}
				if i := strings.IndexByte(line, ' '); i == 6 {
					macPrefixes[strings.ToUpper(line[:6])] = strings.TrimSpace(line[i+1:])
				}
			}
			_ = f.Close()
			break
		}
	})
	return macPrefixes
}

func vendorFor(mac string, prefixes map[string]string) string {
	hex := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	if len(hex) < 6 {
		return ""
	}
	return prefixes[hex[:6]]
}

func reverseName(ctx context.Context, ip string) string {
	rctx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(rctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
