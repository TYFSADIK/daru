package ingest

import (
	"strconv"
	"strings"
	"time"

	"github.com/TYFSADIK/daru/internal/store"
)

// SyslogMessage is one parsed syslog record.
type SyslogMessage struct {
	Facility int // 0-23, or -1 when the message had no PRI
	Severity int // 0-7, or -1 when the message had no PRI
	Time     time.Time
	Host     string
	App      string
	PID      string
	MsgID    string
	Msg      string
	Format   string // "rfc5424", "rfc3164", or "raw"
}

var syslogFacilities = []string{"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
	"uucp", "cron", "authpriv", "ftp", "ntp", "security", "console", "solaris-cron",
	"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"}

var syslogSeverities = []string{"emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"}

// FacilityName returns the RFC 5424 facility keyword, or "" if unknown.
func FacilityName(f int) string {
	if f < 0 || f >= len(syslogFacilities) {
		return ""
	}
	return syslogFacilities[f]
}

// SeverityName returns the RFC 5424 severity keyword, or "" if unknown.
func SeverityName(s int) string {
	if s < 0 || s >= len(syslogSeverities) {
		return ""
	}
	return syslogSeverities[s]
}

// ParseSyslog parses an RFC 5424 or RFC 3164 (BSD) message. Anything else
// is kept whole as the message. now fills in a missing time, and the year
// RFC 3164 timestamps leave out.
func ParseSyslog(line string, now time.Time) SyslogMessage {
	m := SyslogMessage{Facility: -1, Severity: -1, Time: now, Msg: line, Format: "raw"}
	rest, ok := parsePRI(line, &m)
	if !ok {
		return m
	}
	m.Msg = rest
	if strings.HasPrefix(rest, "1 ") {
		parse5424(rest[2:], &m, now)
		return m
	}
	parse3164(rest, &m, now)
	return m
}

func parsePRI(line string, m *SyslogMessage) (string, bool) {
	if len(line) < 3 || line[0] != '<' {
		return line, false
	}
	end := strings.IndexByte(line[:min(len(line), 5)], '>')
	if end < 2 {
		return line, false
	}
	pri, err := strconv.Atoi(line[1:end])
	if err != nil || pri < 0 || pri > 191 {
		return line, false
	}
	m.Facility, m.Severity = pri/8, pri%8
	return line[end+1:], true
}

// nextField splits off one space-separated header field.
func nextField(s string) (string, string) {
	s = strings.TrimLeft(s, " ")
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

func nilValue(v string) string {
	if v == "-" {
		return ""
	}
	return v
}

func parse5424(s string, m *SyslogMessage, now time.Time) {
	m.Format = "rfc5424"
	ts, s := nextField(s)
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		m.Time = t
	} else {
		m.Time = now
	}
	var host, app, pid, msgid string
	host, s = nextField(s)
	app, s = nextField(s)
	pid, s = nextField(s)
	msgid, s = nextField(s)
	m.Host, m.App, m.PID, m.MsgID = nilValue(host), nilValue(app), nilValue(pid), nilValue(msgid)
	// Structured data: "-" or one or more [id k="v" ...] blocks. It stays
	// in the message, where key=value extraction picks the pairs up.
	s = strings.TrimLeft(s, " ")
	if strings.HasPrefix(s, "- ") || s == "-" {
		s = strings.TrimPrefix(strings.TrimPrefix(s, "-"), " ")
	}
	m.Msg = strings.TrimPrefix(s, "\ufeff") // optional UTF-8 BOM
}

func parse3164(s string, m *SyslogMessage, now time.Time) {
	m.Format = "rfc3164"
	// "Mmm dd hh:mm:ss" (the day is space padded: "Nov  3").
	if len(s) >= 16 && s[3] == ' ' && s[15] == ' ' {
		if t, err := time.ParseInLocation("Jan _2 15:04:05", s[:15], time.Local); err == nil {
			t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.Local)
			// A December message read in January belongs to last year.
			if t.After(now.Add(24 * time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			m.Time = t
			s = s[16:]
		}
	}
	// HOSTNAME, unless the next token is already the tag ("sshd[12]:").
	if first, rest := nextField(s); first != "" && !strings.HasSuffix(first, ":") && !strings.Contains(first, "[") {
		m.Host, s = first, rest
	}
	// TAG[PID]: message
	if tag, rest := nextField(s); strings.HasSuffix(tag, ":") {
		tag = strings.TrimSuffix(tag, ":")
		if i := strings.IndexByte(tag, '['); i > 0 && strings.HasSuffix(tag, "]") {
			m.PID = tag[i+1 : len(tag)-1]
			tag = tag[:i]
		}
		m.App, s = tag, rest
	}
	m.Msg = s
}

// SyslogEvent turns a received syslog line into a Daru event. peer is the
// sender's address, used as the host when the message names none.
func SyslogEvent(line, peer, index string, now time.Time) store.Event {
	m := ParseSyslog(line, now)
	host := m.Host
	if host == "" {
		host = peer
	}
	fields := ExtractFields(m.Msg, nil)
	set := func(k, v string) {
		if v != "" {
			fields[k] = v
		}
	}
	set("facility", FacilityName(m.Facility))
	set("severity", SeverityName(m.Severity))
	set("app", m.App)
	set("pid", m.PID)
	set("msgid", m.MsgID)
	set("syslog_format", m.Format)
	set("peer", peer)
	// A sender whose clock runs ahead would hide its events from searches
	// (which end at "now") until that time arrives. Use the receive time
	// instead and keep the sender's time as a field.
	t := m.Time
	if t.After(now.Add(time.Minute)) {
		fields["syslog_time"] = t.UTC().Format(time.RFC3339)
		t = now
	}
	return store.Event{
		Time:       t.UTC(),
		Index:      index,
		Host:       host,
		Source:     "syslog:" + peer,
		Sourcetype: "syslog",
		Raw:        line,
		Fields:     fields,
	}
}
