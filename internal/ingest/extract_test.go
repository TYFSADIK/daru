package ingest

import (
	"testing"
)

func TestExtractFields(t *testing.T) {
	raw := `user=alice action="log in" status=200 bytes=1024`
	f := ExtractFields(raw, nil)
	if f["user"] != "alice" || f["status"] != "200" || f["bytes"] != "1024" {
		t.Errorf("kv extraction wrong: %v", f)
	}
	if f["action"] != "log in" {
		t.Errorf("quoted value wrong: %q", f["action"])
	}
}

func TestExtractExplicitWins(t *testing.T) {
	f := ExtractFields("status=200", map[string]string{"status": "override"})
	if f["status"] != "override" {
		t.Errorf("explicit field should win, got %q", f["status"])
	}
}

func TestExtractCommonPatterns(t *testing.T) {
	f := ExtractFields(`192.168.1.5 - - "GET / HTTP/1.1" 404 120`, nil)
	if f["src_ip"] != "192.168.1.5" {
		t.Errorf("ip not extracted: %v", f)
	}
	if f["status"] != "404" {
		t.Errorf("status not extracted: %v", f)
	}
}

func TestExtractBounded(t *testing.T) {
	raw := ""
	for i := 0; i < 300; i++ {
		raw += "k" + string(rune('a'+i%26)) + "x" + string(rune('0'+i%10)) + "=v "
	}
	f := ExtractFields(raw, nil)
	if len(f) > 128 {
		t.Errorf("field map not bounded: %d", len(f))
	}
}

func TestParseHEC(t *testing.T) {
	body := []byte(`{"event":{"user":"bob","code":403},"sourcetype":"app","host":"h1"}
{"event":"plain log line status=500","host":"h2"}`)
	events, err := ParseHEC(body, "main", "default")
	if err != nil {
		t.Fatalf("ParseHEC: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].Fields["user"] != "bob" || events[0].Host != "h1" {
		t.Errorf("object event wrong: %+v", events[0])
	}
	if events[0].Index != "main" {
		t.Errorf("default index not applied: %q", events[0].Index)
	}
	if events[1].Fields["status"] != "500" {
		t.Errorf("string event extraction wrong: %+v", events[1].Fields)
	}
}

func TestParseRaw(t *testing.T) {
	body := []byte("line one status=200\nline two status=500\n\n")
	events := ParseRaw(body, "main", "host", "src", "st")
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (blank line skipped)", len(events))
	}
	if events[1].Fields["status"] != "500" {
		t.Errorf("raw extraction wrong: %v", events[1].Fields)
	}
}

func TestFlattenJSON(t *testing.T) {
	out := map[string]string{}
	FlattenJSON("", map[string]any{
		"a": "x",
		"b": map[string]any{"c": float64(5)},
	}, out, 0)
	if out["a"] != "x" || out["b.c"] != "5" {
		t.Errorf("flatten wrong: %v", out)
	}
}
