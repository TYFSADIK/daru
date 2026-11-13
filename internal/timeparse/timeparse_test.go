package timeparse

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	now := time.Date(2026, 11, 7, 15, 30, 45, 0, time.UTC)
	cases := []struct {
		in   string
		want string // RFC3339, or "zero"
	}{
		{"", "zero"},
		{"0", "zero"},
		{"now", "2026-11-07T15:30:45Z"},
		{"-15m", "2026-11-07T15:15:45Z"},
		{"-1h", "2026-11-07T14:30:45Z"},
		{"-1d", "2026-11-06T15:30:45Z"},
		{"-1d@d", "2026-11-06T00:00:00Z"},
		{"@d", "2026-11-07T00:00:00Z"},
		{"-1h@h", "2026-11-07T14:00:00Z"},
		{"2026-01-15", "2026-01-15T00:00:00Z"},
		{"2026-01-15T12:00:00Z", "2026-01-15T12:00:00Z"},
		{"1700000000", "2023-11-14T22:13:20Z"},
	}
	for _, c := range cases {
		got, err := Parse(c.in, now)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.in, err)
			continue
		}
		if c.want == "zero" {
			if !got.IsZero() {
				t.Errorf("Parse(%q) = %v, want zero", c.in, got)
			}
			continue
		}
		if got.Format(time.RFC3339) != c.want {
			t.Errorf("Parse(%q) = %v, want %v", c.in, got.Format(time.RFC3339), c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	now := time.Now()
	for _, in := range []string{"-15x", "garbage", "@z", "-1d@"} {
		if _, err := Parse(in, now); err == nil {
			t.Errorf("Parse(%q) should have failed", in)
		}
	}
}

func TestSpan(t *testing.T) {
	n, unit, _, err := Span("5m")
	if err != nil || n != 5 || unit != "MINUTE" {
		t.Errorf("Span(5m) = %d %s %v", n, unit, err)
	}
	if _, _, _, err := Span("5x"); err == nil {
		t.Error("Span(5x) should fail")
	}
}
