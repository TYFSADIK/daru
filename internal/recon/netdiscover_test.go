package recon

import (
	"net"
	"testing"
)

// Real `arp -a` output captured on a macOS LAN.
const sampleARP = `? (192.168.2.0) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (192.168.2.1) at a0:39:f9:2c:51:b5 on en0 ifscope [ethernet]
? (192.168.2.1) at ae:c9:6:a2:76:64 on bridge100 ifscope permanent [bridge]
? (192.168.2.12) at 44:61:32:60:65:28 on en0 ifscope [ethernet]
? (192.168.2.34) at 2c:33:7a:9e:13:ef on en0 ifscope [ethernet]
? (192.168.2.75) at 90:de:80:b3:0:81 on en0 ifscope [ethernet]
? (192.168.2.78) at c8:e2:65:53:b4:7a on en0 ifscope [ethernet]
? (192.168.2.82) at 58:96:1d:f0:71:e3 on en0 ifscope [ethernet]
? (192.168.2.125) at 8a:44:c8:27:bc:bf on en0 ifscope permanent [ethernet]
? (192.168.2.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
mdns.mcast.net (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]`

func TestParseARP(t *testing.T) {
	arp := parseARP(sampleARP)
	// Broadcast, network, and multicast entries are dropped.
	if _, ok := arp["192.168.2.0"]; ok {
		t.Error("broadcast MAC should be dropped")
	}
	if _, ok := arp["224.0.0.251"]; ok {
		t.Error("multicast MAC should be dropped")
	}
	if arp["192.168.2.1"] == "" {
		t.Error("gateway not parsed")
	}
	// Single-hex octets are zero-padded: 90:de:80:b3:0:81 -> ...:00:81.
	if arp["192.168.2.75"] != "90:de:80:b3:00:81" {
		t.Errorf("MAC not normalized: %q", arp["192.168.2.75"])
	}
}

// Real arp-scan --quiet output, including its header and footer lines which
// the parser must ignore.
const sampleArpScan = `Interface: en0, type: EN10MB, MAC: aa:bb:cc:dd:ee:ff, IPv4: 192.168.2.100
Starting arp-scan 1.10.0 with 256 hosts
192.168.2.1	a0:39:f9:2c:51:b5	Sagemcom Broadband SAS
192.168.2.12	44:61:32:60:65:28	ecobee inc.
192.168.2.78	c8:e2:65:53:b4:7a	Intel Corporate
192.168.2.90	3c:06:30:1a:2b:3c	(Unknown)

12 packets received by filter, 0 packets dropped
Ending arp-scan: 256 hosts scanned`

func TestParseArpScan(t *testing.T) {
	macs, vendors := parseArpScan(sampleArpScan)
	if len(macs) != 4 {
		t.Fatalf("expected 4 devices, got %d: %v", len(macs), macs)
	}
	if macs["192.168.2.1"] != "a0:39:f9:2c:51:b5" {
		t.Errorf("gateway mac wrong: %q", macs["192.168.2.1"])
	}
	if vendors["192.168.2.12"] != "ecobee inc." {
		t.Errorf("ecobee vendor wrong: %q", vendors["192.168.2.12"])
	}
	// Header MAC line must not be parsed as a device.
	if _, ok := macs["192.168.2.100"]; ok {
		t.Error("interface header line parsed as a device")
	}
	// "(Unknown)" vendor falls back to the prefix lookup in devicesFromScan.
	_, net24, _ := net.ParseCIDR("192.168.2.0/24")
	devices := devicesFromScan(macs, vendors, []*net.IPNet{net24},
		map[string]string{"3C0630": "Apple, Inc."}, nil)
	byIP := map[string]Finding{}
	for _, d := range devices {
		byIP[d.Target] = d
	}
	if byIP["192.168.2.90"].Fields["vendor"] != "Apple, Inc." {
		t.Errorf("unknown vendor should fall back to prefix lookup, got %q", byIP["192.168.2.90"].Fields["vendor"])
	}
	if byIP["192.168.2.1"].Fields["vendor"] != "Sagemcom Broadband SAS" {
		t.Errorf("arp-scan vendor should win, got %q", byIP["192.168.2.1"].Fields["vendor"])
	}
}

func TestBuildDevices(t *testing.T) {
	arp := parseARP(sampleARP)
	_, net24, _ := net.ParseCIDR("192.168.2.0/24")
	vendors := map[string]string{
		"A039F9": "Sagemcom Broadband SAS",
		"446132": "ecobee",
		"2C337A": "Hon Hai Precision Ind.",
		"C8E265": "Intel Corporate",
	}
	devices := buildDevices(arp, []*net.IPNet{net24}, vendors, nil)
	if len(devices) < 6 {
		t.Fatalf("expected the LAN devices, got %d", len(devices))
	}
	// Devices are sorted by IP and carry the right vendor.
	byIP := map[string]Finding{}
	for _, d := range devices {
		byIP[d.Target] = d
		if d.Fields["_kind"] != "host" {
			t.Errorf("device %s not marked as host", d.Target)
		}
	}
	if byIP["192.168.2.1"].Fields["vendor"] != "Sagemcom Broadband SAS" {
		t.Errorf("gateway vendor wrong: %q", byIP["192.168.2.1"].Fields["vendor"])
	}
	if byIP["192.168.2.12"].Fields["vendor"] != "ecobee" {
		t.Errorf("ecobee vendor wrong: %q", byIP["192.168.2.12"].Fields["vendor"])
	}
	if byIP["192.168.2.78"].Fields["vendor"] != "Intel Corporate" {
		t.Errorf("intel vendor wrong: %q", byIP["192.168.2.78"].Fields["vendor"])
	}
	// First device is the lowest IP.
	if devices[0].Target != "192.168.2.1" {
		t.Errorf("devices not sorted by IP: first is %s", devices[0].Target)
	}
}
