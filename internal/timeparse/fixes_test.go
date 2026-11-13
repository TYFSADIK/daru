package timeparse

import (
	"testing"
	"time"
)

func TestParseRejectsNonsense(t *testing.T) {
	now := time.Date(2026, 11, 7, 15, 30, 45, 0, time.UTC)
	for _, in := range []string{
		"2026",
		"15",
		"-m",
		"-10000000000h",
		"-10000000000000000000h",
		"+123",
	} {
		if _, err := Parse(in, now); err == nil {
			t.Errorf("Parse(%q) should fail", in)
		}
	}
	// A real epoch still works.
	got, err := Parse("1700000000", now)
	if err != nil {
		t.Fatalf("Parse epoch: %v", err)
	}
	if got.Year() != 2023 {
		t.Errorf("epoch parsed to %v, want 2023", got)
	}
}

func TestSpanRejectsOverflow(t *testing.T) {
	if _, _, _, err := Span("99999999999999999999m"); err == nil {
		t.Error("Span with an overflowing number should fail")
	}
	if _, _, _, err := Span("m"); err == nil {
		t.Error("Span with no number should fail")
	}
}
