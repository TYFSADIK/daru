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
