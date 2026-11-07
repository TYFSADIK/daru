// Package ingest accepts logs over HTTP (including the Splunk HEC format so
// existing forwarders can point at Basalt unchanged) and raw TCP, extracts
// fields, and writes batches to the store.
package ingest

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	// key=value or key="quoted value" pairs.
	kvRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.]*)=("([^"\\]|\\.)*"|[^\s,;]+)`)
	// Common log tokens worth promoting to fields.
	ipRe     = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	statusRe = regexp.MustCompile(`"\s(\d{3})\s`)
)

// ExtractFields pulls fields out of a raw line using key=value pairs and a few
// common patterns. Explicit fields supplied by the sender win over extracted
// ones.
func ExtractFields(raw string, explicit map[string]string) map[string]string {
	fields := map[string]string{}
	for _, m := range kvRe.FindAllStringSubmatch(raw, 64) {
		key := m[1]
		val := m[2]
		if len(val) >= 2 && val[0] == '"' {
			val = unquote(val)
		}
		if _, ok := fields[key]; !ok {
			fields[key] = val
		}
	}
	if _, ok := fields["src_ip"]; !ok {
		if m := ipRe.FindString(raw); m != "" {
			fields["src_ip"] = m
		}
	}
	if _, ok := fields["status"]; !ok {
		if m := statusRe.FindStringSubmatch(raw); m != nil {
			fields["status"] = m[1]
		}
	}
	for k, v := range explicit {
		fields[k] = v
	}
	// Keep the map bounded so a hostile line cannot explode row width.
	if len(fields) > 128 {
		trimmed := map[string]string{}
		n := 0
		for k, v := range fields {
			if n >= 128 {
				break
			}
			trimmed[k] = v
			n++
		}
		return trimmed
	}
	return fields
}

func unquote(s string) string {
	if u, err := strconv.Unquote(s); err == nil {
		return u
	}
	return strings.Trim(s, `"`)
}

// FlattenJSON turns a decoded JSON object into dotted string fields.
func FlattenJSON(prefix string, v any, out map[string]string, depth int) {
	if depth > 10 || len(out) > 128 {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			FlattenJSON(key, val, out, depth+1)
		}
	case []any:
		for i, val := range t {
			if i > 50 {
				break
			}
			FlattenJSON(prefix+"."+strconv.Itoa(i), val, out, depth+1)
		}
	case string:
		out[prefix] = t
	case float64:
		out[prefix] = strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		out[prefix] = strconv.FormatBool(t)
	case nil:
		// skip
	}
}
