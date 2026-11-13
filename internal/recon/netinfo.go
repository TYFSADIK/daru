package recon

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// InterfaceInfo is a live snapshot of one network interface. Byte/packet
// counters are cumulative since boot; the UI polls and diffs them to show
// live throughput. All of this reads from the kernel and needs no privileges.
type InterfaceInfo struct {
	Name         string   `json:"name"`
	MAC          string   `json:"mac"`
	MTU          int      `json:"mtu"`
	Up           bool     `json:"up"`
	Wireless     bool     `json:"wireless"`
	Addrs        []string `json:"addrs"`
	SpeedMbps    int      `json:"speed_mbps"`      // wired link speed, when known
	OperState    string   `json:"oper_state"`      // up, down, dormant...
	SSID         string   `json:"ssid"`            // wifi only
	FreqMHz      float64  `json:"freq_mhz"`        // wifi only
	Band         string   `json:"band"`            // wifi only: "2.4 GHz" / "5 GHz" / "6 GHz"
	SignalDBm    int      `json:"signal_dbm"`      // wifi only
	RxBitrate    string   `json:"rx_bitrate"`      // wifi only, raw: "816.7 MBit/s 80MHz HE-MCS 7..."
	TxBitrate    string   `json:"tx_bitrate"`      // wifi only, raw
	RxMbps       float64  `json:"rx_mbps"`         // wifi only: parsed headline rx speed
	TxMbps       float64  `json:"tx_mbps"`         // wifi only: parsed headline tx speed
	ChannelWidth string   `json:"channel_width"`   // wifi only, e.g. "80MHz"
	WiFiGen      string   `json:"wifi_generation"` // wifi only, e.g. "Wi-Fi 6 (802.11ax)"
	RxBytes      uint64   `json:"rx_bytes"`
	TxBytes      uint64   `json:"tx_bytes"`
	RxPackets    uint64   `json:"rx_packets"`
	TxPackets    uint64   `json:"tx_packets"`
	SampledAt    int64    `json:"sampled_at_ms"` // epoch ms of this snapshot
}

// Interfaces returns a live snapshot of every non-loopback interface.
func Interfaces(ctx context.Context) []InterfaceInfo {
	ifaces, err := netInterfaces()
	if err != nil {
		return nil
	}
	now := time.Now().UnixMilli()
	var out []InterfaceInfo
	for _, name := range ifaces {
		info := InterfaceInfo{Name: name, SampledAt: now}
		base := filepath.Join("/sys/class/net", name)
		info.MAC = strings.TrimSpace(readFile(filepath.Join(base, "address")))
		info.OperState = strings.TrimSpace(readFile(filepath.Join(base, "operstate")))
		info.Up = info.OperState == "up" || info.OperState == "unknown"
		info.MTU = atoi(readFile(filepath.Join(base, "mtu")))
		if s := atoi(readFile(filepath.Join(base, "speed"))); s > 0 {
			info.SpeedMbps = s
		}
		info.RxBytes = atou(readFile(filepath.Join(base, "statistics/rx_bytes")))
		info.TxBytes = atou(readFile(filepath.Join(base, "statistics/tx_bytes")))
		info.RxPackets = atou(readFile(filepath.Join(base, "statistics/rx_packets")))
		info.TxPackets = atou(readFile(filepath.Join(base, "statistics/tx_packets")))
		// Wireless marker: the interface has a wireless/ sysfs dir.
		if _, err := os.Stat(filepath.Join(base, "wireless")); err == nil {
			info.Wireless = true
			enrichWiFi(ctx, &info)
		} else if _, err := os.Stat(filepath.Join(base, "phy80211")); err == nil {
			info.Wireless = true
			enrichWiFi(ctx, &info)
		}
		info.Addrs = interfaceAddrs(name)
		out = append(out, info)
	}
	return out
}

// enrichWiFi fills SSID, frequency, signal, and bitrates from `iw dev <if> link`.
func enrichWiFi(ctx context.Context, info *InterfaceInfo) {
	bin := firstExisting("iw", "/usr/sbin/iw", "/sbin/iw", "/usr/bin/iw")
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, bin, "dev", info.Name, "link").Output() // #nosec G204 -- recon tools run as an argv list (no shell) from a vetted binary path
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "SSID:"):
			info.SSID = strings.TrimSpace(strings.TrimPrefix(t, "SSID:"))
		case strings.HasPrefix(t, "freq:"):
			info.FreqMHz, _ = strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(t, "freq:")), 64)
		case strings.HasPrefix(t, "signal:"):
			if fields := strings.Fields(strings.TrimPrefix(t, "signal:")); len(fields) > 0 {
				info.SignalDBm = atoi(fields[0])
			}
		case strings.HasPrefix(t, "rx bitrate:"):
			info.RxBitrate = strings.TrimSpace(strings.TrimPrefix(t, "rx bitrate:"))
			mbps, width, gen := parseBitrate(info.RxBitrate)
			info.RxMbps = mbps
			if width != "" {
				info.ChannelWidth = width
			}
			if gen != "" {
				info.WiFiGen = gen
			}
		case strings.HasPrefix(t, "tx bitrate:"):
			info.TxBitrate = strings.TrimSpace(strings.TrimPrefix(t, "tx bitrate:"))
			mbps, width, gen := parseBitrate(info.TxBitrate)
			info.TxMbps = mbps
			if info.ChannelWidth == "" {
				info.ChannelWidth = width
			}
			if info.WiFiGen == "" {
				info.WiFiGen = gen
			}
		}
	}
	info.Band = bandForFreq(info.FreqMHz)
}

// parseBitrate pulls the headline Mbps, channel width, and Wi-Fi generation out
// of an `iw` bitrate string like "720.6 MBit/s 80MHz HE-MCS 7 HE-NSS 2".
func parseBitrate(s string) (mbps float64, width, gen string) {
	fields := strings.Fields(s)
	for i, f := range fields {
		switch {
		case f == "MBit/s" && i > 0:
			mbps, _ = strconv.ParseFloat(fields[i-1], 64)
		case strings.HasSuffix(f, "MHz"):
			width = f
		case strings.HasPrefix(f, "EHT"):
			gen = "Wi-Fi 7 (802.11be)"
		case strings.HasPrefix(f, "HE"):
			if gen == "" {
				gen = "Wi-Fi 6 (802.11ax)"
			}
		case strings.HasPrefix(f, "VHT"):
			if gen == "" {
				gen = "Wi-Fi 5 (802.11ac)"
			}
		case strings.HasPrefix(f, "HT") && !strings.HasPrefix(f, "HE"):
			if gen == "" {
				gen = "Wi-Fi 4 (802.11n)"
			}
		}
	}
	return mbps, width, gen
}

// bandForFreq maps a center frequency (MHz) to its Wi-Fi band label.
func bandForFreq(freq float64) string {
	switch {
	case freq >= 2400 && freq < 2500:
		return "2.4 GHz"
	case freq >= 4900 && freq < 5925:
		return "5 GHz"
	case freq >= 5925 && freq <= 7125:
		return "6 GHz"
	}
	return ""
}

func netInterfaces() ([]string, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.Name() == "lo" {
			continue
		}
		names = append(names, e.Name())
	}
	return names, nil
}

func interfaceAddrs(name string) []string {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, _ := ifc.Addrs()
	var out []string
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

func readFile(path string) string {
	b, err := os.ReadFile(path) // #nosec G304 -- path comes from a fixed list or /sys, never from a request
	if err != nil {
		return ""
	}
	return string(b)
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func atou(s string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return n
}
