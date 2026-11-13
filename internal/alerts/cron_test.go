package alerts

import (
	"testing"
	"time"
)

func at(s string) time.Time {
	t, _ := time.Parse("2006-01-02 15:04", s)
	return t
}

func TestCron(t *testing.T) {
	cases := []struct {
		expr  string
		when  string
		match bool
	}{
		{"* * * * *", "2026-11-07 10:30", true},
		{"*/5 * * * *", "2026-11-07 10:30", true},
		{"*/5 * * * *", "2026-11-07 10:32", false},
		{"0 * * * *", "2026-11-07 10:00", true},
		{"0 * * * *", "2026-11-07 10:01", false},
		{"30 9 * * *", "2026-11-07 09:30", true},
		{"0 0 1 * *", "2026-11-01 00:00", true},
		{"0 0 1 * *", "2026-11-02 00:00", false},
		{"0 9 * * 6", "2026-11-07 09:00", true},  // 2026-11-07 is a Saturday
		{"0 9 * * 1", "2026-11-07 09:00", false}, // not Monday
		{"@hourly", "2026-11-07 14:00", true},
		{"@daily", "2026-11-07 00:00", true},
	}
	for _, c := range cases {
		s, err := ParseCron(c.expr)
		if err != nil {
			t.Errorf("ParseCron(%q): %v", c.expr, err)
			continue
		}
		if got := s.Matches(at(c.when)); got != c.match {
			t.Errorf("%q matches %q = %v, want %v", c.expr, c.when, got, c.match)
		}
	}
}

func TestCronErrors(t *testing.T) {
	for _, e := range []string{"* * * *", "60 * * * *", "* 25 * * *", "bad * * * *", "* * * * 9"} {
		if _, err := ParseCron(e); err == nil {
			t.Errorf("ParseCron(%q) should fail", e)
		}
	}
}

func TestCondition(t *testing.T) {
	cases := []struct {
		cond  string
		count int
		want  bool
	}{
		{"", 1, true}, {"", 0, false},
		{"count > 0", 1, true}, {"count > 5", 3, false},
		{"count >= 10", 10, true}, {"> 2", 3, true}, {"count == 0", 0, true},
	}
	for _, c := range cases {
		if got := conditionMet(c.cond, c.count); got != c.want {
			t.Errorf("conditionMet(%q, %d) = %v, want %v", c.cond, c.count, got, c.want)
		}
	}
}
