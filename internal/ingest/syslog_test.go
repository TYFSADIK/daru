package ingest

import (
	"testing"
	"time"
)

func TestParseSyslog5424(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	m := ParseSyslog(`<165>1 2026-11-13T10:15:30.123Z fw01.example.com firewall 4211 DENY [meta src="10.0.0.5"] action=deny dst_port=3389`, now)
	if m.Format != "rfc5424" || m.Facility != 20 || m.Severity != 5 {
		t.Fatalf("format/pri: %+v", m)
	}
	if m.Host != "fw01.example.com" || m.App != "firewall" || m.PID != "4211" || m.MsgID != "DENY" {
		t.Errorf("header: %+v", m)
	}
	if !m.Time.Equal(time.Date(2026, 11, 13, 10, 15, 30, 123000000, time.UTC)) {
		t.Errorf("time: %v", m.Time)
	}
	if m.Msg != `[meta src="10.0.0.5"] action=deny dst_port=3389` {
		t.Errorf("msg: %q", m.Msg)
	}
	// Nil values and no structured data.
	m = ParseSyslog(`<14>1 - - - - - - plain message`, now)
	if m.Host != "" || m.App != "" || m.Msg != "plain message" || !m.Time.Equal(now) {
		t.Errorf("nil values: %+v", m)
	}
}

func TestParseSyslog3164(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.Local)
	m := ParseSyslog(`<38>Nov  3 09:01:02 bastion01 sshd[1234]: Failed password for root from 203.0.113.45 port 51122 ssh2`, now)
	if m.Format != "rfc3164" || m.Facility != 4 || m.Severity != 6 {
		t.Fatalf("format/pri: %+v", m)
	}
	if m.Host != "bastion01" || m.App != "sshd" || m.PID != "1234" {
		t.Errorf("header: %+v", m)
	}
	if m.Time.Month() != time.November || m.Time.Day() != 3 || m.Time.Year() != 2026 || m.Time.Hour() != 9 {
		t.Errorf("time: %v", m.Time)
	}
	if m.Msg != "Failed password for root from 203.0.113.45 port 51122 ssh2" {
		t.Errorf("msg: %q", m.Msg)
	}
	// A December message received in January is from last year.
	jan := time.Date(2027, 1, 1, 0, 5, 0, 0, time.Local)
	if m := ParseSyslog(`<13>Dec 31 23:59:58 host app: x`, jan); m.Time.Year() != 2026 {
		t.Errorf("year rollover: %v", m.Time)
	}
	// No hostname, tag first (common from local daemons).
	if m := ParseSyslog(`<13>Nov 13 10:00:00 cron[99]: job done`, now); m.Host != "" || m.App != "cron" || m.PID != "99" || m.Msg != "job done" {
		t.Errorf("tag first: %+v", m)
	}
}

func TestParseSyslogRawAndBadPRI(t *testing.T) {
	now := time.Now()
	for _, line := range []string{"no header at all", "<999>1 bad pri", "<abc>x", "<", ""} {
		m := ParseSyslog(line, now)
		if m.Format != "raw" || m.Msg != line || m.Facility != -1 {
			t.Errorf("%q: %+v", line, m)
		}
	}
}

func TestSyslogEvent(t *testing.T) {
	now := time.Now()
	ev := SyslogEvent(`<38>Nov  3 09:01:02 bastion01 sshd[1234]: Failed password for root from 203.0.113.45 user=root`, "10.0.0.9", "syslog", now)
	if ev.Host != "bastion01" || ev.Index != "syslog" || ev.Sourcetype != "syslog" || ev.Source != "syslog:10.0.0.9" {
		t.Errorf("event: %+v", ev)
	}
	for k, want := range map[string]string{"facility": "auth", "severity": "info", "app": "sshd", "pid": "1234", "peer": "10.0.0.9", "user": "root"} {
		if ev.Fields[k] != want {
			t.Errorf("field %s = %q, want %q", k, ev.Fields[k], want)
		}
	}
	// No hostname in the message: the sender's address is the host.
	if ev := SyslogEvent("plain line", "10.0.0.9", "syslog", now); ev.Host != "10.0.0.9" {
		t.Errorf("peer as host: %q", ev.Host)
	}
}

func TestSyslogEventFutureClock(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	ev := SyslogEvent(`<14>1 2026-11-13T12:30:00Z host app - - - clock ahead`, "10.0.0.9", "syslog", now)
	if !ev.Time.Equal(now) || ev.Fields["syslog_time"] != "2026-11-13T12:30:00Z" {
		t.Errorf("future time: got %v, syslog_time=%q", ev.Time, ev.Fields["syslog_time"])
	}
	ev = SyslogEvent(`<14>1 2026-11-13T11:30:00Z host app - - - normal`, "10.0.0.9", "syslog", now)
	if ev.Time.Hour() != 11 || ev.Fields["syslog_time"] != "" {
		t.Errorf("past time kept: got %v", ev.Time)
	}
}
