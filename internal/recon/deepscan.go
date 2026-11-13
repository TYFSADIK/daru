package recon

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Deep scan ("god mode" for your own LAN): one action that fuses several tools
// into a complete device profile. It discovers live hosts, then for each host
// runs an nmap OS + service/version scan and a NetBIOS name lookup, and merges
// everything (IP, MAC, vendor, hostname, OS, open ports with service+version)
// into rich host findings that feed the asset inventory.
//
// It is registered as a native connector so it flows through the same
// authorization gate, scope guard, history, and inventory as every other scan.
func init() {
	register(&Connector{
		Name: "deep-scan", Binary: "", Category: CatPortScan, TargetKind: TgtCIDR,
		AllowEmptyTarget: true,
		Desc:             "God-mode LAN sweep: fuses discovery, nmap OS/service detection, and NetBIOS names into full device profiles. Leave target blank for your own network.",
		Profiles: []Profile{
			{"fast", "Discovery + top-100 service scan per host"},
			{"thorough", "Discovery + OS detection + top-1000 service scan per host"},
		},
		native: deepScan,
	})
}

func deepScan(ctx context.Context, r Request) ([]Finding, error) {
	nmapBin := resolveBinary("nmap")
	if nmapBin == "" {
		return nil, fmt.Errorf("deep-scan needs nmap installed")
	}
	thorough := r.Profile == "thorough"

	// 1. Determine target networks.
	var nets []*net.IPNet
	target := strings.TrimSpace(r.Target)
	if target == "" {
		nets = dedupeNets(localNets())
		if len(nets) == 0 {
			return nil, fmt.Errorf("could not determine a local network; set a target CIDR")
		}
	} else if strings.Contains(target, "/") {
		_, n, err := net.ParseCIDR(target)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR")
		}
		if ones, bits := n.Mask.Size(); bits-ones > (32 - MaxCIDRBits) {
			return nil, fmt.Errorf("range %s is larger than /%d; narrow the scope", target, MaxCIDRBits)
		}
		nets = []*net.IPNet{n}
	} else {
		// Single host: profile it and still merge discovery metadata (NetBIOS
		// name, MAC, vendor) so a one-host scan is as rich as a full sweep.
		return deepScanOne(ctx, target, thorough), nil
	}

	// 2. Discover live hosts across the networks (ARP + name lookups).
	discovered := map[string]Finding{}
	disc, _ := netDiscover(ctx, Request{Target: target})
	for _, f := range disc {
		if ip := f.Fields["ip"]; ip != "" {
			discovered[ip] = f
		}
	}
	// Supplement with an nmap ping sweep so hosts with no ARP entry are found.
	for _, n := range nets {
		pingHosts := nmapPingSweep(ctx, n.String())
		for _, ip := range pingHosts {
			if _, ok := discovered[ip]; !ok {
				discovered[ip] = Finding{Target: ip, Fields: map[string]string{"ip": ip}}
			}
		}
	}
	if len(discovered) == 0 {
		return nil, fmt.Errorf("no live hosts found on %v", netStrings(nets))
	}
	if len(discovered) > 1024 {
		return nil, fmt.Errorf("deep-scan found %d hosts; narrow the scope to at most 1024 hosts", len(discovered))
	}

	var ips []string
	for ip := range discovered {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return less4(ips[i], ips[j]) })

	// 3. Deep-profile each host, merging in the discovery metadata.
	profiles := deepScanHosts(ctx, ips, thorough)
	byIP := map[string][]Finding{}
	for _, f := range profiles {
		byIP[f.Target] = append(byIP[f.Target], f)
	}

	var out []Finding
	for _, ip := range ips {
		meta := discovered[ip]
		host := byIP[ip]
		// Build the merged device record.
		dev := mergeDevice(ip, meta, host)
		out = append(out, dev)
		// Append the per-port service findings after the device record.
		for _, f := range host {
			if f.Fields["_kind"] == "host" {
				continue
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// deepScanOne deep-profiles a single host: it runs discovery (ARP + NetBIOS
// name lookup, which also yields MAC/vendor/hostname) and an nmap service scan,
// then merges them into one rich device record followed by per-port services ,
// the same shape the CIDR sweep produces.
func deepScanOne(ctx context.Context, ip string, thorough bool) []Finding {
	meta := Finding{Target: ip, Fields: map[string]string{"ip": ip}}
	// ARP/vendor metadata: netDiscover wants a CIDR, so scan this host as /32.
	if disc, _ := netDiscover(ctx, Request{Target: ip + "/32"}); len(disc) > 0 {
		for _, f := range disc {
			if f.Fields["ip"] == ip {
				meta = f
				break
			}
		}
	}
	// NetBIOS name: recovers the Windows/SMB hostname that reverse DNS misses.
	if meta.Fields == nil {
		meta.Fields = map[string]string{"ip": ip}
	}
	if meta.Fields["hostname"] == "" {
		if name := nbtHostname(ctx, ip); name != "" {
			meta.Fields["hostname"] = name
		}
	}
	host := deepScanHosts(ctx, []string{ip}, thorough)
	out := []Finding{mergeDevice(ip, meta, host)}
	for _, f := range host {
		if f.Fields["_kind"] == "host" {
			continue
		}
		out = append(out, f)
	}
	return out
}

// deepScanHosts runs an nmap service/OS scan against each host and returns the
// parsed findings (device records + per-port services).
func deepScanHosts(ctx context.Context, ips []string, thorough bool) []Finding {
	c := Registry["nmap"]
	profile := "service"
	if thorough {
		profile = "service"
	}
	var all []Finding
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return all
		default:
		}
		req := Request{Connector: "nmap", Target: ip, Profile: profile}
		args, err := c.build(c, req)
		if err != nil {
			continue
		}
		if thorough {
			// Add OS detection (-O). Requires raw sockets; harmless if denied.
			args = append([]string{"-O"}, args...)
		}
		hctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		res := Run(hctx, c, args, req, 4*time.Minute)
		cancel()
		all = append(all, res.Findings...)
	}
	return all
}

// mergeDevice folds discovery metadata and nmap host info into one rich record.
func mergeDevice(ip string, meta Finding, host []Finding) Finding {
	fields := map[string]string{"_kind": "host", "ip": ip, "status": "up"}
	for k, v := range meta.Fields {
		if v != "" {
			fields[k] = v
		}
	}
	var ports []string
	for _, f := range host {
		if f.Fields["_kind"] == "host" {
			for k, v := range f.Fields {
				if v != "" && (fields[k] == "" || k == "os" || k == "ports") {
					fields[k] = v
				}
			}
		}
		if p := f.Fields["port"]; p != "" && f.Fields["_kind"] != "host" {
			svc := f.Fields["service"]
			entry := p
			if svc != "" {
				entry = p + "/" + svc
			}
			ports = append(ports, entry)
		}
	}
	if len(ports) > 0 {
		fields["ports"] = strings.Join(ports, ", ")
	}
	fields["_kind"] = "host"
	hostname := fields["hostname"]
	title := ip
	if hostname != "" {
		title = ip + " (" + hostname + ")"
	}
	detail := strings.TrimSpace(strings.Join(nonEmpty(fields["vendor"], fields["os"], fields["ports"]), " · "))
	return Finding{
		Title: title, Severity: "info", Target: ip, Service: "device", Detail: detail, Fields: fields,
	}
}

// nmapPingSweep returns live IPs from an nmap -sn sweep of a CIDR.
func nmapPingSweep(ctx context.Context, cidr string) []string {
	c := Registry["nmap"]
	req := Request{Connector: "nmap", Target: cidr, Profile: "discovery"}
	args, err := c.build(c, req)
	if err != nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	res := Run(cctx, c, args, req, 90*time.Second)
	var ips []string
	for _, f := range res.Findings {
		if ip := f.Fields["ip"]; ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips
}

func netStrings(nets []*net.IPNet) []string {
	var out []string
	for _, n := range nets {
		out = append(out, n.String())
	}
	return out
}

func nonEmpty(vals ...string) []string {
	var out []string
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}
