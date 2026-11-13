package query

import (
	"strings"
	"testing"
)

func mustCompileFix(t *testing.T, q string) *Compiled {
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

func TestLowercaseOperators(t *testing.T) {
	c := mustCompileFix(t, `error or warning`)
	if !strings.Contains(c.SQL, " OR ") {
		t.Errorf("lowercase or should compile to OR\n%s", c.SQL)
	}
	if strings.Contains(c.SQL, "positionCaseInsensitive(_raw, 'or')") {
		t.Errorf("lowercase or must not be a literal term\n%s", c.SQL)
	}
	c = mustCompileFix(t, `error and warning`)
	if !strings.Contains(c.SQL, " AND ") {
		t.Errorf("lowercase and should compile to AND\n%s", c.SQL)
	}
	c = mustCompileFix(t, `not error`)
	if !strings.Contains(c.SQL, "NOT ") {
		t.Errorf("lowercase not should compile to NOT\n%s", c.SQL)
	}
	c = mustCompileFix(t, `status in (500, 502)`)
	if !strings.Contains(c.SQL, " OR ") {
		t.Errorf("lowercase in should compile\n%s", c.SQL)
	}
}

func TestChartNeedsOverOrBy(t *testing.T) {
	if _, err := Parse(`* | chart count`); err == nil {
		t.Error("chart with no over or by should fail at parse time")
	}
}

func TestTimechartAndChartLimit(t *testing.T) {
	c := mustCompileFix(t, `* | timechart limit=2 span=1h count by host`)
	if c.SeriesLimit != 2 {
		t.Errorf("SeriesLimit = %d, want 2", c.SeriesLimit)
	}
	if !strings.Contains(c.SQL, "LIMIT 2") {
		t.Errorf("timechart limit should appear in SQL\n%s", c.SQL)
	}
	c = mustCompileFix(t, `* | chart limit=2 count over host`)
	if c.SeriesLimit != 2 {
		t.Errorf("chart SeriesLimit = %d, want 2", c.SeriesLimit)
	}
	if !strings.Contains(c.SQL, "LIMIT 2") {
		t.Errorf("chart limit should appear in SQL\n%s", c.SQL)
	}
}

func TestTailAndHeadUseTimeOrder(t *testing.T) {
	c := mustCompileFix(t, `* | tail 5`)
	if !strings.Contains(c.SQL, "row_number() OVER (ORDER BY _time DESC)") {
		t.Errorf("tail should number newest first\n%s", c.SQL)
	}
	if !strings.Contains(c.SQL, "__rn <= 5") {
		t.Errorf("tail should keep __rn <= 5\n%s", c.SQL)
	}
	c = mustCompileFix(t, `* | head 5`)
	if !strings.Contains(c.SQL, "ORDER BY _time DESC") {
		t.Errorf("head should sort by _time first\n%s", c.SQL)
	}
	if !strings.Contains(c.SQL, "LIMIT 5") {
		t.Errorf("head should limit to 5\n%s", c.SQL)
	}
}

func TestStatsByTimeGroupsByRawTime(t *testing.T) {
	c := mustCompileFix(t, `* | stats count by _time`)
	if !strings.Contains(c.SQL, "GROUP BY `_time`") {
		t.Errorf("stats by _time should group by raw _time\n%s", c.SQL)
	}
	if strings.Contains(c.SQL, "GROUP BY formatDateTime") {
		t.Errorf("stats by _time must not group by formatted string\n%s", c.SQL)
	}
}

func TestBinTimeNumericSpanRejected(t *testing.T) {
	p, err := Parse(`* | bin _time span=100`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := Compile(p, Options{}); err == nil {
		t.Error("bin _time span=100 should fail")
	}
}

func TestRexUnnamedGroups(t *testing.T) {
	c := mustCompileFix(t, `* | rex field=_raw "(\w+) (?<b>\w+)"`)
	if !strings.Contains(c.SQL, "extractGroups") {
		t.Fatalf("rex SQL missing extractGroups\n%s", c.SQL)
	}
	// b is the second group overall, not the first named group.
	if !strings.Contains(c.SQL, "), 2) AS `b`") {
		t.Errorf("named group b should use index 2\n%s", c.SQL)
	}
}

func TestDroppedFieldErrors(t *testing.T) {
	p, err := Parse(`* | table host | where foo=1`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := Compile(p, Options{}); err == nil {
		t.Error("referencing a dropped field should fail instead of returning no rows")
	}
}

func TestNotEqualNullTolerant(t *testing.T) {
	c := mustCompileFix(t, `status!=500`)
	if !strings.Contains(c.SQL, "ifNull") && !strings.Contains(c.SQL, "OR toString") {
		t.Errorf("!= should be null tolerant\n%s", c.SQL)
	}
	if strings.Contains(c.SQL, "(NOT (toString") {
		t.Errorf("!= must not be a plain NOT of the equality\n%s", c.SQL)
	}
}

func TestIsNumericScientific(t *testing.T) {
	c := mustCompileFix(t, `status>1e3`)
	if !strings.Contains(c.SQL, "toFloat64OrNull") || !strings.Contains(c.SQL, "1e3") {
		t.Errorf("1e3 should compare numerically\n%s", c.SQL)
	}
	c = mustCompileFix(t, `status>+5`)
	if !strings.Contains(c.SQL, "toFloat64OrNull") {
		t.Errorf("+5 should compare numerically\n%s", c.SQL)
	}
}

func TestEvalDurationRejected(t *testing.T) {
	if _, err := Parse(`* | eval x = 5m`); err == nil {
		t.Error("eval x = 5m should fail instead of becoming a field lookup")
	}
}

func TestEvalReservedFieldsRejected(t *testing.T) {
	for _, q := range []string{`* | eval _time = 5`, `* | eval _id = "x"`, `* | eval _raw = "x"`} {
		if _, err := Parse(q); err == nil {
			t.Errorf("%q should fail", q)
		}
	}
}

func TestRenameOntoExistingColumn(t *testing.T) {
	c := mustCompileFix(t, `* | rename host AS source`)
	if strings.Count(c.SQL, "AS `source`") != 1 {
		t.Errorf("rename onto source should produce one source column\n%s", c.SQL)
	}
	if !strings.Contains(c.SQL, "EXCEPT") {
		t.Errorf("rename should except the old target\n%s", c.SQL)
	}
}

func TestEventstatsWindowSQL(t *testing.T) {
	cases := map[string][]string{
		`* | eventstats count`:          {"toFloat64(count() OVER ())"},
		`* | eventstats dc(user)`:       {"uniqExact", "OVER ()"},
		`* | eventstats sum(bytes)`:     {"sum(", "OVER ()"},
		`* | eventstats avg(bytes)`:     {"avg(", "OVER ()"},
		`* | eventstats range(bytes)`:   {"max(", "OVER ()", "min(", "OVER ()"},
		`* | eventstats values(status)`: {"groupUniqArray", "OVER ()"},
	}
	for q, wants := range cases {
		c := mustCompileFix(t, q)
		for _, w := range wants {
			if !strings.Contains(c.SQL, w) {
				t.Errorf("%q: SQL missing %q\n%s", q, w, c.SQL)
			}
		}
		if strings.Contains(c.SQL, ") OVER ()") && strings.Contains(c.SQL, "toFloat64(count()) OVER") {
			t.Errorf("%q: scalar wrapper must not carry OVER\n%s", q, c.SQL)
		}
	}
}

func TestStreamstatsWindowSQL(t *testing.T) {
	c := mustCompileFix(t, `* | streamstats count`)
	if !strings.Contains(c.SQL, "count() OVER (ORDER BY") {
		t.Errorf("streamstats count should use count() OVER\n%s", c.SQL)
	}
	c = mustCompileFix(t, `* | streamstats dc(user)`)
	if !strings.Contains(c.SQL, "uniqExact") || !strings.Contains(c.SQL, "OVER (ORDER BY") {
		t.Errorf("streamstats dc should use uniqExact OVER\n%s", c.SQL)
	}
}

func TestChIdentEscapesBacktick(t *testing.T) {
	got := chIdent("a`b")
	if got != "`a\\`b`" {
		t.Errorf("chIdent(a`b) = %q, want %q", got, "`a\\`b`")
	}
}
