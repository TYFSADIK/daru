package store

import (
	"context"
	"fmt"
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
	firstSeen := "now64(3)"
	if prev != nil {
		firstSeen = quoteTime(prev.FirstSeen)
		a.MAC = firstNonEmpty(a.MAC, prev.MAC)
		a.Vendor = firstNonEmpty(a.Vendor, prev.Vendor)
		a.Hostname = firstNonEmpty(a.Hostname, prev.Hostname)
		a.OS = firstNonEmpty(a.OS, prev.OS)
		a.OpenPorts = firstNonEmpty(a.OpenPorts, prev.OpenPorts)
	}
	sql := fmt.Sprintf(`INSERT INTO assets
		(ip, mac, vendor, hostname, os, open_ports, status, source, first_seen, last_seen, updated_at)
		VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, now64(3), now64(3))`,
		quote(a.IP), quote(a.MAC), quote(a.Vendor), quote(a.Hostname), quote(a.OS),
		quote(a.OpenPorts), quote(a.Status), quote(a.Source), firstSeen)
	return s.exec(ctx, sql)
}

func (s *Store) getAsset(ctx context.Context, ip string) (*Asset, error) {
	res, err := s.Query(ctx, fmt.Sprintf(
		"SELECT ip, mac, vendor, hostname, os, open_ports, status, source, toString(first_seen), toString(last_seen) FROM assets FINAL WHERE ip = %s LIMIT 1", quote(ip)))
	if err != nil || len(res.Rows) == 0 {
		return nil, err
	}
	return rowToAsset(res.Rows[0]), nil
}

// ListAssets returns the device inventory, most recently seen first.
func (s *Store) ListAssets(ctx context.Context) ([]Asset, error) {
	res, err := s.Query(ctx, `SELECT ip, mac, vendor, hostname, os, open_ports, status, source,
		toString(first_seen), toString(last_seen) FROM assets FINAL ORDER BY last_seen DESC, ip`)
	if err != nil {
		return nil, err
	}
	var out []Asset
	for _, r := range res.Rows {
		out = append(out, *rowToAsset(r))
	}
	return out, nil
}

func rowToAsset(r []any) *Asset {
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
