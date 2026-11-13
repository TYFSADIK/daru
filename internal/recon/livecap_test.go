package recon

import (
	"strings"
	"testing"
)

func TestParseLive(t *testing.T) {
	// Fields in liveFields order: epoch,len,eth.src,eth.dst,ip.src,ip.dst,
	// ipv6.src,ipv6.dst,proto,tcp.sport,tcp.dport,udp.sport,udp.dport,
	// dns.qry,http.host,sni,info
	line := "1700000000.5\t120\taa:bb\tcc:dd\t192.168.1.2\t192.168.1.1\t\t\tTCP\t51000\t443\t\t\t\t\texample.com\tseq ack"
	p, ok := parseLive(line)
	if !ok {
		t.Fatal("expected a packet")
	}
	if p.SrcIP != "192.168.1.2" || p.DstIP != "192.168.1.1" {
		t.Errorf("addresses wrong: %+v", p)
	}
	if p.DstPort != "443" || p.Protocol != "TCP" || p.Length != 120 {
		t.Errorf("fields wrong: %+v", p)
	}
	if p.SNI != "example.com" {
		t.Errorf("SNI not parsed: %+v", p)
	}
	if p.TimeMs != 1700000000500 {
		t.Errorf("time wrong: %d", p.TimeMs)
	}

	// UDP/DNS packet: ports come from the udp.* columns.
	dns := "1700000001.0\t80\t\t\t10.0.0.5\t10.0.0.1\t\t\tDNS\t\t\t5353\t53\tfoo.local\t\t\tstandard query"
	d, _ := parseLive(dns)
	if d.SrcPort != "5353" || d.DstPort != "53" || d.DNSQuery != "foo.local" {
		t.Errorf("udp/dns parse wrong: %+v", d)
	}

	if _, ok := parseLive(""); ok {
		t.Error("empty line should not parse")
	}
}

func TestParseTcpdump(t *testing.T) {
	line := "1794068590.788806 c8:e2:65:53:b4:7a > a0:39:f9:2c:51:b5, ethertype IPv4 (0x0800), length 83: 192.168.2.78.43073 > 198.41.192.37.443: tcp 0"
	p, ok := parseTcpdump(line)
	if !ok {
		t.Fatal("expected a packet")
	}
	if p.SrcIP != "192.168.2.78" || p.SrcPort != "43073" {
		t.Errorf("src wrong: %+v", p)
	}
	if p.DstIP != "198.41.192.37" || p.DstPort != "443" {
		t.Errorf("dst wrong: %+v", p)
	}
	if p.Protocol != "TLS" { // upgraded from tcp via dst port 443
		t.Errorf("protocol should upgrade to TLS: %q", p.Protocol)
	}
	if p.Length != 83 || p.SrcMAC != "c8:e2:65:53:b4:7a" {
		t.Errorf("frame fields wrong: %+v", p)
	}
	// A UDP/DNS line.
	dns := "1700000000.1 aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66, ethertype IPv4 (0x0800), length 90: 10.0.0.2.5353 > 10.0.0.1.53: UDP, length 48"
	d, _ := parseTcpdump(dns)
	if d.DstPort != "53" || d.Protocol != "DNS" {
		t.Errorf("dns parse wrong: %+v", d)
	}
	if _, ok := parseTcpdump("listening on wlo1, link-type EN10MB"); ok {
		t.Error("control line should not parse")
	}
}

func TestValidBPF(t *testing.T) {
	for _, s := range []string{"tcp port 443", "host 192.168.1.1 and udp", "not arp"} {
		if !validBPF(s) {
			t.Errorf("should accept %q", s)
		}
	}
	for _, s := range []string{"tcp; rm -rf", "host `id`", "a|b"} {
		if validBPF(s) {
			t.Errorf("should reject %q", s)
		}
	}
}

func TestParseTsharkRich(t *testing.T) {
	// liveFields order; a TLS packet carrying SNI, and a DNS query packet.
	tls := "1700000000.0\t120\taa\tbb\t10.0.0.2\t1.1.1.1\t\t\tTLSv1.3\t50000\t443\t\t\t\t\tapi.example.com\tClient Hello"
	dns := "1700000001.0\t80\taa\tbb\t10.0.0.2\t1.1.1.1\t\t\tDNS\t\t\t5300\t53\tapi.example.com\t\t\tStandard query"
	fs := parseTsharkRich([]byte(tls+"\n"+dns), Request{Target: "cap.pcap"})
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(fs), fs)
	}
	if fs[0].Fields["sni"] != "api.example.com" || !strings.Contains(fs[0].Detail, "TLS SNI") {
		t.Errorf("SNI not surfaced: %+v", fs[0])
	}
	if fs[1].Fields["dns_query"] != "api.example.com" || !strings.Contains(fs[1].Detail, "DNS:") {
		t.Errorf("DNS query not surfaced: %+v", fs[1])
	}
}

func TestChooseCaptureEngine(t *testing.T) {
	// When tshark+tcpdump exist but dumpcap is not runnable, the hybrid pipe
	// engine must be chosen so live capture still gets rich decode.
	eng, bin := chooseCaptureEngine()
	if bin == "" {
		t.Skip("no capture tools installed")
	}
	if eng != engineTshark && eng != engineTsharkPipe && eng != engineTcpdump {
		t.Errorf("unexpected engine %q", eng)
	}
}
