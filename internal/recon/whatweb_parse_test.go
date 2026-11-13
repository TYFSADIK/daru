package recon

import (
	"strings"
	"testing"
)

func TestParseWhatwebRich(t *testing.T) {
	out := []byte(`[
{"target":"http://127.0.0.1:8099/","http_status":200,"plugins":{"HTTPServer":{"string":["SimpleHTTP/0.6 Python/3.13.5"]},"MetaGenerator":{"string":["WordPress 6.4"]},"PoweredBy":{"string":["nginx/1"]},"Title":{"string":["Daru Test Server"]},"WordPress":{"version":["6.4"]},"HTML5":{}}}
]`)
	f := parseWhatweb(out, Request{Target: "http://127.0.0.1:8099/"})
	if len(f) != 1 {
		t.Fatalf("want 1 finding, got %d", len(f))
	}
	fields := f[0].Fields
	if fields["server"] != "SimpleHTTP/0.6 Python/3.13.5" {
		t.Errorf("server not extracted: %q", fields["server"])
	}
	if fields["title"] != "Daru Test Server" {
		t.Errorf("title not extracted: %q", fields["title"])
	}
	if !strings.Contains(fields["cms"], "WordPress") {
		t.Errorf("cms not extracted: %q", fields["cms"])
	}
	if fields["powered_by"] != "nginx/1" {
		t.Errorf("powered_by not extracted: %q", fields["powered_by"])
	}
	// Detail must carry plugin values, not just names.
	if !strings.Contains(f[0].Detail, "WordPress 6.4") {
		t.Errorf("detail lost plugin value: %q", f[0].Detail)
	}
}
