package ingest

import (
	"strings"
	"testing"
	"time"
)

func TestParseHECTimeMagnitudes(t *testing.T) {
	want := time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)
	cases := map[string]string{
		"1700000000":           "seconds",
		"1700000000000":        "milliseconds",
		"1700000000000000":     "microseconds",
		"1700000000000000000":  "nanoseconds",
		"2023-11-14T22:13:20Z": "rfc3339",
	}
	for in, label := range cases {
		got, err := parseHECTime(in)
		if err != nil {
			t.Errorf("%s %q: %v", label, in, err)
			continue
		}
		if !got.Equal(want) {
			t.Errorf("%s %q = %v, want %v", label, in, got, want)
		}
	}
	if _, err := parseHECTime("999999999999999999999"); err == nil {
		t.Error("out of range HEC time should fail")
	}
	if _, err := parseHECTime("not-a-time"); err == nil {
		t.Error("invalid HEC time should fail")
	}
}

func TestParseHECArray(t *testing.T) {
	body := []byte(`[{"event":"hi","time":1700000000,"host":"h1"},{"event":"bye","host":"h2"}]`)
	events, err := ParseHEC(body, "main", "default")
	if err != nil {
		t.Fatalf("ParseHEC array: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].Raw != "hi" || events[0].Host != "h1" {
		t.Errorf("first array event wrong: %+v", events[0])
	}
	if events[0].Time.Year() != 2023 {
		t.Errorf("array event time wrong: %v", events[0].Time)
	}
}

func TestParseRawStrictCapsAndErrors(t *testing.T) {
	events, err := ParseRawStrict([]byte("a\nb\n"), "main", "h", "s", "st")
	if err != nil || len(events) != 2 {
		t.Fatalf("ParseRawStrict = %d events %v, want 2 nil", len(events), err)
	}
	// A line over the 8 MB scanner limit must be reported, not dropped.
	big := strings.Repeat("x", 9*1024*1024)
	_, err = ParseRawStrict([]byte(big+"\n"), "main", "h", "s", "st")
	if err == nil {
		t.Error("overlong raw line should return an error")
	}
	// Too many events must be reported.
	var sb strings.Builder
	for i := 0; i < 100001; i++ {
		sb.WriteString("line\n")
	}
	_, err = ParseRawStrict([]byte(sb.String()), "main", "h", "s", "st")
	if err == nil {
		t.Error("more than 100000 raw events should return an error")
	}
}

func TestExtractFieldsExplicitFirst(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 200; i++ {
		sb.WriteString("k")
		sb.WriteString(strings.Repeat("x", 3))
		sb.WriteString("=v ")
	}
	// Use distinct keys so trimming actually engages.
	raw := ""
	for i := 0; i < 200; i++ {
		raw += "field" + strings.Repeat("a", i%5) + string(rune('a'+i%26)) + "=v "
	}
	_ = sb
	f := ExtractFields(raw, map[string]string{"keep": "yes"})
	if len(f) > 128 {
		t.Errorf("field map not bounded: %d", len(f))
	}
	if f["keep"] != "yes" {
		t.Errorf("explicit field must survive trimming, got %v", f)
	}
}

func TestFlattenJSONSorted(t *testing.T) {
	out := map[string]string{}
	FlattenJSON("", map[string]any{"z": "1", "a": "2", "m": "3"}, out, 0)
	if out["a"] != "2" || out["m"] != "3" || out["z"] != "1" {
		t.Errorf("flatten wrong: %v", out)
	}
}
