package ingest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/TYFSADIK/daru/internal/store"
)

// Ingester writes parsed events to the store.
type Ingester struct {
	st        *store.Store
	defaultIx string
}

// New creates an Ingester.
func New(st *store.Store) *Ingester {
	return &Ingester{st: st, defaultIx: "main"}
}

// hecEvent is one Splunk HEC record. "event" may be a string or an object.
type hecEvent struct {
	Time       json.Number     `json:"time"`
	Host       string          `json:"host"`
	Source     string          `json:"source"`
	Sourcetype string          `json:"sourcetype"`
	Index      string          `json:"index"`
	Event      json.RawMessage `json:"event"`
	Fields     map[string]any  `json:"fields"`
}

// ParseHEC decodes one or more concatenated HEC JSON objects into events.
// It also accepts a single JSON array of HEC records, which is the form
// the plain JSON ingest endpoint documents. defaultIndex applies when a
// record names none.
func ParseHEC(body []byte, defaultIndex, defaultHost string) ([]store.Event, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var arr []hecEvent
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		if err := dec.Decode(&arr); err != nil {
			return nil, fmt.Errorf("invalid HEC JSON array: %w", err)
		}
		events := make([]store.Event, 0, len(arr))
		for _, h := range arr {
			ev, err := hecToEvent(h, defaultIndex, defaultHost)
			if err != nil {
				return events, err
			}
			events = append(events, ev)
			if len(events) > 100000 {
				return events, fmt.Errorf("too many events in one request")
			}
		}
		return events, nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var events []store.Event
	for {
		var h hecEvent
		err := dec.Decode(&h)
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return events, fmt.Errorf("invalid HEC JSON: %w", err)
		}
		ev, err := hecToEvent(h, defaultIndex, defaultHost)
		if err != nil {
			return events, err
		}
		events = append(events, ev)
		if len(events) > 100000 {
			return events, fmt.Errorf("too many events in one request")
		}
	}
	return events, nil
}

func validIndexName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func hecToEvent(h hecEvent, defaultIndex, defaultHost string) (store.Event, error) {
	ev := store.Event{
		Index:      firstNonEmpty(h.Index, defaultIndex, "main"),
		Host:       firstNonEmpty(h.Host, defaultHost),
		Source:     h.Source,
		Sourcetype: firstNonEmpty(h.Sourcetype, "hec"),
		Fields:     map[string]string{},
	}
	if !validIndexName(ev.Index) {
		return ev, fmt.Errorf("invalid index name %q", ev.Index)
	}
	if h.Time != "" {
		t, err := parseHECTime(h.Time.String())
		if err != nil {
			return ev, err
		}
		ev.Time = t
	}
	explicit := map[string]string{}
	for k, v := range h.Fields {
		explicit[k] = toStr(v)
	}

	// event may be a JSON object or a bare string.
	var asString string
	if len(h.Event) > 0 {
		trimmed := bytes.TrimSpace(h.Event)
		if len(trimmed) > 0 && trimmed[0] == '{' {
			var obj map[string]any
			if err := json.Unmarshal(trimmed, &obj); err == nil {
				FlattenJSON("", obj, explicit, 0)
				ev.Raw = string(trimmed)
			} else {
				asString = string(trimmed)
			}
		} else if err := json.Unmarshal(trimmed, &asString); err != nil {
			asString = string(trimmed)
		}
	}
	if ev.Raw == "" {
		ev.Raw = asString
	}
	ev.Fields = ExtractFields(ev.Raw, explicit)
	return ev, nil
}

// ParseRaw splits a raw text body into one event per line. It keeps the
// old signature for existing callers; new callers should use
// ParseRawStrict, which reports scanner errors instead of dropping lines.
func ParseRaw(body []byte, index, host, source, sourcetype string) []store.Event {
	events, _ := ParseRawStrict(body, index, host, source, sourcetype)
	return events
}

// ParseRawStrict splits a raw text body into one event per line, checks
// the scanner error (a line over the 8 MB limit or any read error used to
// end the loop silently with a 200 response), caps the batch at 100000
// events, and stamps each event with its own time.
func ParseRawStrict(body []byte, index, host, source, sourcetype string) ([]store.Event, error) {
	if index == "" {
		index = "main"
	}
	if !validIndexName(index) {
		return nil, fmt.Errorf("invalid index name %q", index)
	}
	if sourcetype == "" {
		sourcetype = "raw"
	}
	var events []store.Event
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		events = append(events, store.Event{
			Time:       time.Now().UTC(),
			Index:      index,
			Host:       host,
			Source:     source,
			Sourcetype: sourcetype,
			Raw:        line,
			Fields:     ExtractFields(line, nil),
		})
		if len(events) > 100000 {
			return events, fmt.Errorf("too many events in one request")
		}
	}
	if err := sc.Err(); err != nil {
		return events, fmt.Errorf("reading raw body: %w", err)
	}
	return events, nil
}

// Write stores a batch of events.
func (i *Ingester) Write(ctx context.Context, events []store.Event) (int, error) {
	return i.st.InsertEvents(ctx, events)
}

// parseHECTime classifies an epoch timestamp by magnitude: seconds below
// 1e11, milliseconds below 1e14, microseconds below 1e17, nanoseconds
// otherwise. Out of range values are an error, not a far future event.
func parseHECTime(s string) (time.Time, error) {
	if s == "" {
		return time.Now().UTC(), nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid HEC time %q", s)
	}
	if f < 0 || f >= 1e20 {
		return time.Time{}, fmt.Errorf("HEC time %q is out of range", s)
	}
	var divisor float64
	switch {
	case f < 1e11:
		divisor = 1
	case f < 1e14:
		divisor = 1e3
	case f < 1e17:
		divisor = 1e6
	default:
		divisor = 1e9
	}
	sec := int64(f / divisor)
	nsec := int64((f/divisor - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).UTC(), nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}
