// Package timeparse reads time modifiers such as -15m, -1d@d, now, epoch
// seconds, and RFC 3339 timestamps.
package timeparse

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Parse resolves a time modifier relative to now. An empty string or "0"
// for earliest means unbounded and returns the zero time.
func Parse(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "0", "all", "alltime":
		return time.Time{}, nil
	case "now", "now()":
		return now, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t, nil
		}
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && !strings.HasPrefix(s, "-") && !strings.HasPrefix(s, "+") {
		// A bare number is epoch seconds, but only when it looks like one:
		// short numbers such as 2026 or 15 are not timestamps.
		intPart := s
		if i := strings.IndexByte(s, '.'); i >= 0 {
			intPart = s[:i]
		}
		if len(intPart) < 9 {
			return time.Time{}, fmt.Errorf("invalid time %q: bare numbers must be epoch seconds (at least 9 digits)", s)
		}
		sec := int64(f)
		return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC(), nil
	}
	return relative(s, now)
}

func relative(s string, now time.Time) (time.Time, error) {
	t := now.UTC()
	rest := s
	snap := ""
	if i := strings.IndexByte(s, '@'); i >= 0 {
		rest, snap = s[:i], s[i+1:]
		if snap == "" {
			return time.Time{}, fmt.Errorf("invalid time %q: @ must be followed by a unit such as @d or @h", s)
		}
	}
	if rest != "" && rest != "now" {
		sign := 1
		switch rest[0] {
		case '-':
			sign = -1
			rest = rest[1:]
		case '+':
			rest = rest[1:]
		default:
			return time.Time{}, fmt.Errorf("invalid time %q: use forms like -15m, -1d@d, now, or 2026-01-31T00:00:00Z", s)
		}
		i := 0
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		if i == 0 {
			return time.Time{}, fmt.Errorf("invalid time %q: a unit needs a number before it, for example -15m", s)
		}
		n, err := strconv.Atoi(rest[:i])
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid time %q: %w", s, err)
		}
		if n < 1 || n > 100000 {
			return time.Time{}, fmt.Errorf("invalid time %q: number out of range 1-100000", s)
		}
		if t, err = shift(t, sign*n, rest[i:]); err != nil {
			return time.Time{}, fmt.Errorf("invalid time %q: %w", s, err)
		}
	}
	if snap != "" {
		var err error
		if t, err = snapTo(t, snap); err != nil {
			return time.Time{}, fmt.Errorf("invalid time %q: %w", s, err)
		}
	}
	return t, nil
}

func unit(u string) (string, error) {
	switch strings.ToLower(u) {
	case "s", "sec", "secs", "second", "seconds":
		return "s", nil
	case "m", "min", "mins", "minute", "minutes":
		return "m", nil
	case "h", "hr", "hrs", "hour", "hours":
		return "h", nil
	case "d", "day", "days":
		return "d", nil
	case "w", "week", "weeks":
		return "w", nil
	case "mon", "month", "months":
		return "mon", nil
	case "q", "qtr", "quarter", "quarters":
		return "q", nil
	case "y", "yr", "year", "years":
		return "y", nil
	}
	return "", fmt.Errorf("unknown unit %q", u)
}

func shift(t time.Time, n int, u string) (time.Time, error) {
	if n < -100000 || n > 100000 {
		return t, fmt.Errorf("shift %d is out of range 1-100000", n)
	}
	u, err := unit(u)
	if err != nil {
		return t, err
	}
	switch u {
	case "s":
		return t.Add(time.Duration(n) * time.Second), nil
	case "m":
		return t.Add(time.Duration(n) * time.Minute), nil
	case "h":
		return t.Add(time.Duration(n) * time.Hour), nil
	case "d":
		return t.AddDate(0, 0, n), nil
	case "w":
		return t.AddDate(0, 0, 7*n), nil
	case "mon":
		return t.AddDate(0, n, 0), nil
	case "q":
		return t.AddDate(0, 3*n, 0), nil
	}
	return t.AddDate(n, 0, 0), nil
}

func snapTo(t time.Time, u string) (time.Time, error) {
	u, err := unit(u)
	if err != nil {
		return t, err
	}
	y, mo, d := t.Date()
	switch u {
	case "s":
		return t.Truncate(time.Second), nil
	case "m":
		return t.Truncate(time.Minute), nil
	case "h":
		return t.Truncate(time.Hour), nil
	case "d":
		return time.Date(y, mo, d, 0, 0, 0, 0, time.UTC), nil
	case "w":
		day := time.Date(y, mo, d, 0, 0, 0, 0, time.UTC)
		return day.AddDate(0, 0, -int(day.Weekday())), nil
	case "mon":
		return time.Date(y, mo, 1, 0, 0, 0, 0, time.UTC), nil
	case "q":
		return time.Date(y, mo-(mo-1)%3, 1, 0, 0, 0, 0, time.UTC), nil
	}
	return time.Date(y, 1, 1, 0, 0, 0, 0, time.UTC), nil
}

// Span parses a bucket span such as 30s, 5m, 1h, 1d, 1w, 1mon.
// It returns the count and a ClickHouse interval unit.
func Span(s string) (int, string, time.Duration, error) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	n := 1
	if i > 0 {
		var err error
		n, err = strconv.Atoi(s[:i])
		if err != nil {
			return 0, "", 0, fmt.Errorf("span %q is out of range", s)
		}
	}
	if i == 0 {
		return 0, "", 0, fmt.Errorf("span %q needs a number, for example 5m", s)
	}
	if n < 1 || n > 100000 {
		return 0, "", 0, fmt.Errorf("span %q is out of range", s)
	}
	u, err := unit(s[i:])
	if err != nil {
		return 0, "", 0, fmt.Errorf("span %q: %w", s, err)
	}
	switch u {
	case "s":
		return n, "SECOND", time.Duration(n) * time.Second, nil
	case "m":
		return n, "MINUTE", time.Duration(n) * time.Minute, nil
	case "h":
		return n, "HOUR", time.Duration(n) * time.Hour, nil
	case "d":
		return n, "DAY", time.Duration(n) * 24 * time.Hour, nil
	case "w":
		return n, "WEEK", time.Duration(n) * 7 * 24 * time.Hour, nil
	case "mon":
		return n, "MONTH", time.Duration(n) * 30 * 24 * time.Hour, nil
	case "q":
		return n, "QUARTER", time.Duration(n) * 91 * 24 * time.Hour, nil
	}
	return n, "YEAR", time.Duration(n) * 365 * 24 * time.Hour, nil
}

// AutoSpan picks a bucket span that gives roughly 100 buckets.
func AutoSpan(earliest, latest time.Time) string {
	d := latest.Sub(earliest)
	for _, c := range []struct {
		span string
		dur  time.Duration
	}{
		{"1s", time.Second}, {"5s", 5 * time.Second}, {"10s", 10 * time.Second},
		{"30s", 30 * time.Second}, {"1m", time.Minute}, {"5m", 5 * time.Minute},
		{"10m", 10 * time.Minute}, {"30m", 30 * time.Minute}, {"1h", time.Hour},
		{"3h", 3 * time.Hour}, {"12h", 12 * time.Hour}, {"1d", 24 * time.Hour},
		{"1w", 7 * 24 * time.Hour},
	} {
		if d/c.dur <= 150 {
			return c.span
		}
	}
	return "1mon"
}
