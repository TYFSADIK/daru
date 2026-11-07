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
// defaultIndex applies when a record names none.
func ParseHEC(body []byte, defaultIndex, defaultHost string) ([]store.Event, error) {
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

func hecToEvent(h hecEvent, defaultIndex, defaultHost string) (store.Event, error) {
	ev := store.Event{
		Index:      firstNonEmpty(h.Index, defaultIndex, "main"),
		Host:       firstNonEmpty(h.Host, defaultHost),
		Source:     h.Source,
		Sourcetype: firstNonEmpty(h.Sourcetype, "hec"),
		Fields:     map[string]string{},
	}
	if h.Time != "" {
		ev.Time = parseHECTime(h.Time.String())
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

// ParseRaw splits a raw text body into one event per line.
func ParseRaw(body []byte, index, host, source, sourcetype string) []store.Event {
	if index == "" {
		index = "main"
	}
	if sourcetype == "" {
		sourcetype = "raw"
	}
	var events []store.Event
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	now := time.Now().UTC()
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		events = append(events, store.Event{
			Time:       now,
			Index:      index,
			Host:       host,
			Source:     source,
			Sourcetype: sourcetype,
			Raw:        line,
			Fields:     ExtractFields(line, nil),
		})
	}
	return events
}

// Write stores a batch of events.
func (i *Ingester) Write(ctx context.Context, events []store.Event) (int, error) {
	return i.st.InsertEvents(ctx, events)
}

func parseHECTime(s string) time.Time {
	if s == "" {
		return time.Now().UTC()
	}
	// HEC time is epoch seconds, possibly fractional, or milliseconds.
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		if f > 1e12 { // looks like milliseconds
			f /= 1000
		}
		sec := int64(f)
		return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC()
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	return time.Now().UTC()
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
