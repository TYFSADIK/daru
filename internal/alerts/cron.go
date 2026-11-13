// Package alerts runs scheduled searches on a cron schedule and records when
// their condition is met.
package alerts

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule is a parsed 5-field cron expression (minute hour dom month dow).
type Schedule struct {
	minute, hour, dom, month, dow uint64
}

// ParseCron parses "m h dom mon dow" with ranges, lists, steps, and *.
// It also accepts a few macros such as @hourly and @daily.
func ParseCron(expr string) (*Schedule, error) {
	expr = strings.TrimSpace(expr)
	switch expr {
	case "@hourly":
		expr = "0 * * * *"
	case "@daily", "@midnight":
		expr = "0 0 * * *"
	case "@weekly":
		expr = "0 0 * * 0"
	case "@monthly":
		expr = "0 0 1 * *"
	case "@yearly", "@annually":
		expr = "0 0 1 1 *"
	}
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("cron needs 5 fields (minute hour day month weekday), got %d", len(fields))
	}
	s := &Schedule{}
	var err error
	if s.minute, err = parseField(fields[0], 0, 59); err != nil {
		return nil, fmt.Errorf("minute: %w", err)
	}
	if s.hour, err = parseField(fields[1], 0, 23); err != nil {
		return nil, fmt.Errorf("hour: %w", err)
	}
	if s.dom, err = parseField(fields[2], 1, 31); err != nil {
		return nil, fmt.Errorf("day of month: %w", err)
	}
	if s.month, err = parseField(fields[3], 1, 12); err != nil {
		return nil, fmt.Errorf("month: %w", err)
	}
	if s.dow, err = parseField(normalizeDow(fields[4]), 0, 6); err != nil {
		return nil, fmt.Errorf("weekday: %w", err)
	}
	return s, nil
}

// normalizeDow maps weekday 7 (Sunday in standard cron) to 0, including
// inside ranges such as 5-7, which becomes 5-6 plus 0.
func normalizeDow(field string) string {
	var parts []string
	for _, part := range strings.Split(field, ",") {
		step := ""
		rang := part
		if i := strings.IndexByte(part, '/'); i >= 0 {
			step, rang = part[i:], part[:i]
		}
		if i := strings.IndexByte(rang, '-'); i >= 0 {
			lo, hi := rang[:i], rang[i+1:]
			if hi == "7" {
				parts = append(parts, lo+"-6"+step, "0"+step)
				continue
			}
		} else if rang == "7" {
			parts = append(parts, "0"+step)
			continue
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ",")
}

func parseField(field string, min, max int) (uint64, error) {
	var bits uint64
	for _, part := range strings.Split(field, ",") {
		step := 1
		rang := part
		if i := strings.IndexByte(part, '/'); i >= 0 {
			var err error
			if step, err = strconv.Atoi(part[i+1:]); err != nil || step < 1 {
				return 0, fmt.Errorf("bad step %q", part)
			}
			rang = part[:i]
		}
		lo, hi := min, max
		if rang != "*" {
			if i := strings.IndexByte(rang, '-'); i >= 0 {
				var err1, err2 error
				lo, err1 = strconv.Atoi(rang[:i])
				hi, err2 = strconv.Atoi(rang[i+1:])
				if err1 != nil || err2 != nil {
					return 0, fmt.Errorf("bad range %q", rang)
				}
			} else {
				v, err := strconv.Atoi(rang)
				if err != nil {
					return 0, fmt.Errorf("bad value %q", rang)
				}
				lo, hi = v, v
			}
		}
		if lo < min || hi > max || lo > hi {
			return 0, fmt.Errorf("value out of range %d-%d", min, max)
		}
		for v := lo; v <= hi; v += step {
			bits |= 1 << uint(v)
		}
	}
	return bits, nil
}

// Matches reports whether t satisfies the schedule, to the minute.
func (s *Schedule) Matches(t time.Time) bool {
	domMatch := s.dom&(1<<uint(t.Day())) != 0
	dowMatch := s.dow&(1<<uint(int(t.Weekday()))) != 0

	// Standard cron day semantics: if both day-of-month and weekday are
	// restricted, either one matching is enough; if only one is restricted,
	// that one must match; if neither is restricted, any day matches.
	var dayOK bool
	switch {
	case s.domRestricted() && s.dowRestricted():
		dayOK = domMatch || dowMatch
	case s.domRestricted():
		dayOK = domMatch
	case s.dowRestricted():
		dayOK = dowMatch
	default:
		dayOK = true
	}

	return s.minute&(1<<uint(t.Minute())) != 0 &&
		s.hour&(1<<uint(t.Hour())) != 0 &&
		s.month&(1<<uint(int(t.Month()))) != 0 &&
		dayOK
}

func (s *Schedule) domRestricted() bool { return s.dom != fullMask(1, 31) }
func (s *Schedule) dowRestricted() bool { return s.dow != fullMask(0, 6) }

func fullMask(min, max int) uint64 {
	var bits uint64
	for v := min; v <= max; v++ {
		bits |= 1 << uint(v)
	}
	return bits
}
