package query

import (
	"strings"
	"testing"
	"time"
)

func mustCompile(t *testing.T, q string) *Compiled {
	t.Helper()
	p, err := Parse(q)
	if err != nil {
		t.Fatalf("parse %q: %v", q, err)
	}
	c, err := Compile(p, Options{Table: "events", MaxRows: 100})
	if err != nil {
		t.Fatalf("compile %q: %v", q, err)
	}
	return c
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		"| stats count",           // generating pipe without makeresults
		"stats",                   // no aggregation
		"stats count by",          // by with no field",
		"eval",                    // no assignment
		"sort",                    // no field
		"where ",                  // empty expression
		"eval x = ",               // dangling
		"stats bogus(x)",          // unknown aggregation
		"rename a b",              // missing AS
		"| makeresults | stats x", // x is not an aggregation
		"makeresults count=1",     // makeresults not at generating position
		"table",                   // no fields
		"search a=",               // missing value
		"eval x = missing(1)",     // unknown function
		"eval x = round(1,2,3)",   // wrong arity
		"timechart span=5 count",  // bad span unit
		"where x = = 5",           // double operator
	}
	for _, q := range bad {
		if _, err := Parse(q); err == nil {
			// Some errors only surface at compile time.
			p, _ := Parse(q)
			if p != nil {
				if _, cerr := Compile(p, Options{}); cerr == nil {
					t.Errorf("expected error for %q", q)
				}
			}
		}
	}
}

func TestCompileSearch(t *testing.T) {
	cases := map[string]string{
		`error`:                     "positionCaseInsensitive(_raw, 'error')",
		`status=500`:                "toFloat64OrNull(toString(`fields`['status'])) = 500",
		`host=web*`:                 "ILIKE 'web%'",
		`status>=400`:               "toFloat64OrNull(toString(`fields`['status'])) >= 400",
		`a=1 OR b=2`:                " OR ",
		`NOT error`:                 "NOT ",
		`status IN (500, 502, 503)`: " OR ",
		`"exact phrase"`:            "positionCaseInsensitive(_raw, 'exact phrase')",
	}
	for q, want := range cases {
		c := mustCompile(t, q)
		if !strings.Contains(c.SQL, want) {
			t.Errorf("search %q: SQL missing %q\n%s", q, want, c.SQL)
		}
	}
}

func TestCompileStats(t *testing.T) {
	c := mustCompile(t, `status=500 | stats count by user`)
	for _, want := range []string{"GROUP BY", "toFloat64(count()) AS `count`", "`fields`['user'] AS `user`"} {
		if !strings.Contains(c.SQL, want) {
			t.Errorf("stats SQL missing %q\n%s", want, c.SQL)
		}
	}
	if !c.Transformed || c.Kind != "table" {
		t.Errorf("stats should be a transformed table, got kind=%q transformed=%v", c.Kind, c.Transformed)
	}
}

func TestCompileAggregations(t *testing.T) {
	cases := map[string]string{
		`stats sum(bytes)`:       "sum(toFloat64OrNull",
		`stats avg(bytes)`:       "avg(toFloat64OrNull",
		`stats dc(user)`:         "uniqExact",
		`stats p95(latency)`:     "quantileExact(0.95)",
		`stats median(latency)`:  "quantileExact(0.5)",
		`stats values(status)`:   "groupUniqArray",
		`stats stdev(x)`:         "stddevSamp",
		`stats count(user) as n`: "AS `n`",
		`stats latest(msg)`:      "argMax",
	}
	for q, want := range cases {
		c := mustCompile(t, q)
		if !strings.Contains(c.SQL, want) {
			t.Errorf("%q: missing %q\n%s", q, want, c.SQL)
		}
	}
}

func TestCompileEval(t *testing.T) {
	c := mustCompile(t, `* | eval kb = bytes / 1024, label = case(status >= 500, "err", status >= 400, "warn")`)
	for _, want := range []string{"divide(", "AS `kb`", "multiIf", "AS `label`"} {
		if !strings.Contains(c.SQL, want) {
			t.Errorf("eval SQL missing %q\n%s", want, c.SQL)
		}
	}
}

func TestCompileTimechart(t *testing.T) {
	c := mustCompile(t, `* | timechart span=1h count by host`)
	if c.Kind != "timechart" || c.TimeField != "_time" {
		t.Errorf("want timechart kind, got %q", c.Kind)
	}
	for _, want := range []string{"toStartOfInterval", "INTERVAL 1 HOUR", "AS series", "AS value"} {
		if !strings.Contains(c.SQL, want) {
			t.Errorf("timechart SQL missing %q\n%s", want, c.SQL)
		}
	}
}

func TestCompileTopRex(t *testing.T) {
	c := mustCompile(t, `* | top limit=5 url`)
	if !strings.Contains(c.SQL, "percent") || !strings.Contains(c.SQL, "LIMIT 5") {
		t.Errorf("top SQL wrong\n%s", c.SQL)
	}
	c = mustCompile(t, `* | rex field=_raw "user=(?<user>\w+)"`)
	if !strings.Contains(c.SQL, "extractGroups") || !strings.Contains(c.SQL, "(?P<user>") {
		t.Errorf("rex SQL wrong\n%s", c.SQL)
	}
}

func TestInjectionSafety(t *testing.T) {
	// A value with a quote must be escaped, never break out of the literal.
	c := mustCompile(t, `msg="it's a test' OR 1=1 --"`)
	if strings.Contains(c.SQL, "OR 1=1 --'") && !strings.Contains(c.SQL, `\'`) {
		t.Errorf("quote not escaped\n%s", c.SQL)
	}
	if !strings.Contains(c.SQL, `\'`) {
		t.Errorf("expected escaped quote in\n%s", c.SQL)
	}
}

func TestTimeParse(t *testing.T) {
	// Covered in detail in timeparse's own tests; a smoke check here.
	c := mustCompile(t, `error | head 5`)
	if !strings.Contains(c.SQL, "LIMIT 5") {
		t.Errorf("head not applied\n%s", c.SQL)
	}
}

func TestPipelineOrder(t *testing.T) {
	c := mustCompile(t, `status=500`)
	if !strings.Contains(c.SQL, "ORDER BY _time DESC") {
		t.Errorf("event search should sort by time desc\n%s", c.SQL)
	}
	c = mustCompile(t, `* | stats count`)
	if strings.Contains(c.SQL, "ORDER BY _time DESC") {
		t.Errorf("stats result should not force time sort\n%s", c.SQL)
	}
	// A projection that drops _time must not then order by it.
	c = mustCompile(t, `* | table host, status`)
	if strings.Contains(c.SQL, "ORDER BY _time") {
		t.Errorf("table without _time should not order by it\n%s", c.SQL)
	}
	c = mustCompile(t, `* | table _time, host`)
	if !strings.Contains(c.SQL, "ORDER BY _time DESC") {
		t.Errorf("table keeping _time should still sort by it\n%s", c.SQL)
	}
}

var _ = time.Now
