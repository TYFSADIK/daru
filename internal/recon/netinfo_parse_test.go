package recon

import "testing"

func TestParseBitrate(t *testing.T) {
	cases := []struct {
		in   string
		mbps float64
		w, g string
	}{
		{"720.6 MBit/s 80MHz HE-MCS 7 HE-NSS 2 HE-GI 0", 720.6, "80MHz", "Wi-Fi 6 (802.11ax)"},
		{"866.7 MBit/s VHT-MCS 9 80MHz VHT-NSS 2", 866.7, "80MHz", "Wi-Fi 5 (802.11ac)"},
		{"144.4 MBit/s MCS 15 40MHz short GI", 144.4, "40MHz", ""},
		{"54.0 MBit/s", 54.0, "", ""},
	}
	for _, c := range cases {
		m, w, g := parseBitrate(c.in)
		if m != c.mbps || w != c.w {
			t.Errorf("%q => mbps=%v w=%q (want %v %q)", c.in, m, w, c.mbps, c.w)
		}
		if c.g != "" && g != c.g {
			t.Errorf("%q => gen=%q want %q", c.in, g, c.g)
		}
	}
}
func TestBandForFreq(t *testing.T) {
	if bandForFreq(2412) != "2.4 GHz" || bandForFreq(5180) != "5 GHz" || bandForFreq(5955) != "6 GHz" {
		t.Fatal("band mapping wrong")
	}
}

func TestParseDarwinNetstat(t *testing.T) {
	in := []byte(`Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0        16384 <Link#1>                         46395     0   29370355    46395     0   29370355     0
lo0        16384 127           127.0.0.1          46395     -   29370355    46395     -   29370355     -
en0        1500  <Link#11>     f0:18:98:22:52:a1 9120345     0 8123456789  5012345     0  987654321     0
en0        1500  10.0.0/24     10.0.0.52        9120345     - 8123456789  5012345     -  987654321     -
utun3*     1380  <Link#20>                             0     0          0        0     0          0     0
`)
	got := parseDarwinNetstat(in)
	if got["lo0"] != [2]uint64{29370355, 29370355} {
		t.Errorf("lo0 = %v", got["lo0"])
	}
	if got["en0"] != [2]uint64{8123456789, 987654321} {
		t.Errorf("en0 = %v (a row with a MAC address)", got["en0"])
	}
	if _, ok := got["utun3"]; !ok {
		t.Errorf("utun3* should be parsed as utun3")
	}
}
