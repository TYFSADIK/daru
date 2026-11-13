package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Asset is one discovered device or host.
type Asset struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Vendor    string `json:"vendor"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	OpenPorts string `json:"open_ports"`
	Status    string `json:"status"`
	Source    string `json:"source"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// UpsertAssetsFromFindings records host-kind findings as inventory assets,
// preserving first_seen and merging in any newly learned attributes.
func (s *Store) UpsertAssetsFromFindings(ctx context.Context, source string, findings []ScanFinding) error {
	for _, f := range findings {
		if f.Fields == nil || f.Fields["_kind"] != "host" {
			continue
		}
		ip := f.Fields["ip"]
		if ip == "" {
			ip = f.Target
		}
		if ip == "" {
			continue
		}
		a := Asset{
			IP: ip, MAC: f.Fields["mac"], Vendor: f.Fields["vendor"],
			Hostname: f.Fields["hostname"], OS: f.Fields["os"],
			OpenPorts: f.Fields["ports"], Status: "up", Source: source,
		}
		if err := s.upsertAsset(ctx, a); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) upsertAsset(ctx context.Context, a Asset) error {
	// Keep the earliest first_seen and fill blanks from the prior record.
	prev, _ := s.getAsset(ctx, a.IP)
	incomingPorts := a.OpenPorts // the ports this scan actually observed
	firstSeen := "now64(3)"
	if prev != nil {
		firstSeen = quoteTime(prev.FirstSeen)
		a.MAC = firstNonEmpty(a.MAC, prev.MAC)
		a.Vendor = firstNonEmpty(a.Vendor, prev.Vendor)
		a.Hostname = firstNonEmpty(a.Hostname, prev.Hostname)
		a.OS = firstNonEmpty(a.OS, prev.OS)
		// Union prior and newly-seen ports so the record accumulates.
		a.OpenPorts = unionPorts(prev.OpenPorts, incomingPorts)
	}
	sql := fmt.Sprintf(`INSERT INTO assets
		(ip, mac, vendor, hostname, os, open_ports, status, source, first_seen, last_seen, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, now64(3), now64(3))`,
		quote(a.IP), quote(a.MAC), quote(a.Vendor), quote(a.Hostname), quote(a.OS),
		quote(a.OpenPorts), quote(a.Status), quote(a.Source), firstSeen)
	if err := s.exec(ctx, sql); err != nil {
		return err
	}
	// A genuinely new device on the network is a notable security event.
	if prev == nil {
		desc := a.IP
		if a.Hostname != "" {
			desc += " (" + a.Hostname + ")"
		}
		detail := "New device joined the network: " + desc
		if a.Vendor != "" {
			detail += " · vendor " + a.Vendor
		}
		if a.OS != "" {
			detail += " · " + a.OS
		}
		_ = s.InsertNotable(ctx, NotableEvent{
			RuleName: "New device on network", Severity: "low", Entity: a.IP,
			Mitre: "T1200", Detail: detail,
		})
	} else if newly := newPorts(prev.OpenPorts, incomingPorts); len(newly) > 0 {
		// A known device exposing a port it did not have before is a signal.
		who := a.IP
		if a.Hostname != "" {
			who += " (" + a.Hostname + ")"
		}
		_ = s.InsertNotable(ctx, NotableEvent{
			RuleName: "New open port on device", Severity: "medium", Entity: a.IP,
			Mitre: "T1046", Detail: "Device " + who + " exposed new port(s): " + strings.Join(newly, ", "),
		})
	}
	return nil
}

// unionPorts merges two comma-separated port lists, numerically sorted.
func unionPorts(a, b string) string {
	seen := map[string]bool{}
	var all []string
	for _, p := range append(splitPorts(a), splitPorts(b)...) {
		if p != "" && !seen[p] {
			seen[p] = true
			all = append(all, p)
		}
	}
	sort.Slice(all, func(i, j int) bool { return atoiSafe(all[i]) < atoiSafe(all[j]) })
	return strings.Join(all, ",")
}

// newPorts returns ports present in cur but not in prev.
func newPorts(prev, cur string) []string {
	have := map[string]bool{}
	for _, p := range splitPorts(prev) {
		have[p] = true
	}
	var out []string
	for _, p := range splitPorts(cur) {
		if p != "" && !have[p] {
			out = append(out, p)
		}
	}
	return out
}

func splitPorts(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		// Keep just the numeric port (handles "80/tcp" or "80/http" entries).
		parts[i] = strings.TrimSpace(strings.SplitN(parts[i], "/", 2)[0])
	}
	return parts
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// GetAsset returns the inventory record for one IP, or nil if unknown.
func (s *Store) GetAsset(ctx context.Context, ip string) (*Asset, error) {
	return s.getAsset(ctx, ip)
}

func (s *Store) getAsset(ctx context.Context, ip string) (*Asset, error) {
	res, err := s.Query(ctx, fmt.Sprintf(
		"SELECT ip, mac, vendor, hostname, os, open_ports, status, source, toString(first_seen), toString(last_seen) FROM assets FINAL WHERE ip = %s LIMIT 1", quote(ip)))
	if err != nil || len(res.Rows) == 0 {
		return nil, err
	}
	return rowToAsset(res.Rows[0]), nil
}

// ListAssets returns the device inventory, most recently seen first, at
// most 1000 rows.
func (s *Store) ListAssets(ctx context.Context) ([]Asset, error) {
	res, err := s.Query(ctx, `SELECT ip, mac, vendor, hostname, os, open_ports, status, source,
		toString(first_seen), toString(last_seen) FROM assets FINAL ORDER BY last_seen DESC, ip LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	var out []Asset
	for _, r := range res.Rows {
		if a := rowToAsset(r); a != nil {
			out = append(out, *a)
		}
	}
	return out, nil
}

func rowToAsset(r []any) *Asset {
	if len(r) < 10 {
		return nil
	}
	return &Asset{
		IP: asString(r[0]), MAC: asString(r[1]), Vendor: asString(r[2]), Hostname: asString(r[3]),
		OS: asString(r[4]), OpenPorts: asString(r[5]), Status: asString(r[6]), Source: asString(r[7]),
		FirstSeen: asString(r[8]), LastSeen: asString(r[9]),
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
