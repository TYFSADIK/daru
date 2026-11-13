package query

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/TYFSADIK/daru/internal/timeparse"
)

// Options controls how a pipeline compiles to SQL.
type Options struct {
	Table    string    // ClickHouse table, e.g. "events"
	Indexes  []string  // index names already validated against the caller's ACL
	Earliest time.Time // zero means unbounded
	Latest   time.Time // zero means unbounded
	MaxRows  int       // hard cap on returned rows
	Now      time.Time
	// NoIndexes means the caller asked for indexes and none matched.
	// It must search nothing, never every index.
	NoIndexes bool
}

// Compiled is the result of compiling a pipeline.
type Compiled struct {
	SQL         string
	Columns     []string // known output columns in display order, empty if dynamic
	Transformed bool     // true once a reporting command changed the shape
	Kind        string   // "events", "table", "timechart", or "chart"
	TimeField   string   // the time column name for timechart output
	// SeriesLimit is the user supplied timechart/chart limit, 0 if unset.
	SeriesLimit int
}

type relation struct {
	sql         string
	explicit    map[string]bool
	order       []string
	mapCol      bool
	ordered     bool // already has a meaningful ORDER BY
	transform   bool
	kind        string
	timeField   string
	dropped     map[string]bool // fields explicitly removed by fields -
	resolveErr  error           // first dropped field reference, if any
	seriesLimit int
}

const mapColumn = "fields"

var builtinCols = map[string]bool{
	"_time": true, "_raw": true, "host": true, "source": true,
	"sourcetype": true, "index": true, "_id": true,
}

// Compile turns a pipeline into one ClickHouse query.
func Compile(p *Pipeline, opt Options) (*Compiled, error) {
	if opt.Table == "" {
		opt.Table = "events"
	}
	if opt.Now.IsZero() {
		opt.Now = time.Now().UTC()
	}
	if opt.MaxRows <= 0 {
		opt.MaxRows = 10000
	}

	rel, err := baseRelation(p, opt)
	if err != nil {
		return nil, err
	}
	if rel.resolveErr != nil {
		return nil, rel.resolveErr
	}

	stages := p.Stages
	if p.Generating {
		stages = stages[1:] // the generating command built the base
	} else if len(stages) > 0 {
		if _, ok := stages[0].(*cmdSearch); ok {
			stages = stages[1:] // folded into the base WHERE
		}
	}

	for _, st := range stages {
		rel, err = applyStage(rel, st, opt)
		if err != nil {
			return nil, err
		}
		if rel.resolveErr != nil {
			return nil, rel.resolveErr
		}
	}

	final := fmt.Sprintf("SELECT * FROM (%s)", rel.sql)
	// Sort newest-first for event views, but only when _time survives the
	// pipeline: a projection such as `table foo` can drop it.
	if !rel.ordered && !rel.transform && rel.explicit["_time"] {
		final += " ORDER BY _time DESC"
	}
	final += fmt.Sprintf(" LIMIT %d", opt.MaxRows)

	kind := rel.kind
	if kind == "" {
		kind = "events"
	}
	return &Compiled{
		SQL:         final,
		Columns:     rel.order,
		Transformed: rel.transform,
		Kind:        kind,
		TimeField:   rel.timeField,
		SeriesLimit: rel.seriesLimit,
	}, nil
}

func baseRelation(p *Pipeline, opt Options) (*relation, error) {
	if p.Generating {
		mr, ok := p.Stages[0].(*cmdMakeresults)
		if !ok {
			return nil, fmt.Errorf("a generating query must start with makeresults")
		}
		sql := fmt.Sprintf(
			"SELECT %s AS _time FROM numbers(%d)",
			chTime(opt.Now), mr.Count,
		)
		return &relation{
			sql:      sql,
			explicit: map[string]bool{"_time": true},
			order:    []string{"_time"},
		}, nil
	}

	var where []string
	if opt.NoIndexes {
		where = append(where, "1 = 0")
	}
	if len(opt.Indexes) > 0 {
		var lits []string
		for _, ix := range opt.Indexes {
			lits = append(lits, chStr(ix))
		}
		where = append(where, fmt.Sprintf("index IN (%s)", strings.Join(lits, ",")))
	}
	if !opt.Earliest.IsZero() {
		where = append(where, fmt.Sprintf("_time >= %s", chTime(opt.Earliest)))
	}
	if !opt.Latest.IsZero() {
		where = append(where, fmt.Sprintf("_time < %s", chTime(opt.Latest)))
	}

	rel := &relation{
		explicit: map[string]bool{
			"_time": true, "_raw": true, "host": true, "source": true,
			"sourcetype": true, "index": true, "_id": true,
		},
		order:   []string{"_time", "host", "source", "sourcetype", "_raw"},
		mapCol:  true,
		dropped: map[string]bool{},
	}

	if len(p.Stages) > 0 {
		if s, ok := p.Stages[0].(*cmdSearch); ok && s.Pred != nil {
			pred, err := compileSearch(s.Pred, rel)
			if err != nil {
				return nil, err
			}
			if rel.resolveErr != nil {
				return nil, rel.resolveErr
			}
			where = append(where, pred)
		}
	}

	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	rel.sql = fmt.Sprintf(
		"SELECT _id, _time, _raw, host, source, sourcetype, index, %s FROM %s%s",
		mapColumn, chIdent(opt.Table), clause,
	)
	return rel, nil
}

func applyStage(rel *relation, st interface{}, opt Options) (*relation, error) {
	switch c := st.(type) {
	case *cmdSearch:
		if c.Pred == nil {
			return rel, nil
		}
		pred, err := compileSearch(c.Pred, rel)
		if err != nil {
			return nil, err
		}
		return wrapWhere(rel, pred), nil
	case *cmdWhere:
		pred, err := compileWhereExpr(c.Expr, rel)
		if err != nil {
			return nil, err
		}
		return wrapWhere(rel, pred), nil
	case *cmdEval:
		return compileEval(rel, c)
	case *cmdStats:
		return compileStats(rel, c)
	case *cmdTimechart:
		return compileTimechart(rel, c, opt)
	case *cmdChart:
		return compileChart(rel, c)
	case *cmdTable:
		return compileTable(rel, c.Fields, false)
	case *cmdFields:
		return compileFields(rel, c)
	case *cmdSort:
		return compileSort(rel, c)
	case *cmdHead:
		return compileHead(rel, c.N)
	case *cmdTail:
		return compileTail(rel, c.N)
	case *cmdRename:
		return compileRename(rel, c)
	case *cmdDedup:
		return compileDedup(rel, c)
	case *cmdTop:
		return compileTop(rel, c)
	case *cmdBin:
		return compileBin(rel, c)
	case *cmdFillnull:
		return compileFillnull(rel, c)
	case *cmdRex:
		return compileRex(rel, c)
	case *cmdSpath:
		return compileSpath(rel, c)
	case *cmdMakeresults:
		return nil, fmt.Errorf("makeresults must be the first command")
	}
	return nil, fmt.Errorf("command not supported yet")
}

// --- relation helpers ---

func cloneCols(rel *relation) (map[string]bool, []string) {
	m := make(map[string]bool, len(rel.explicit))
	for k := range rel.explicit {
		m[k] = true
	}
	order := append([]string(nil), rel.order...)
	return m, order
}

func wrapWhere(rel *relation, pred string) *relation {
	nr := *rel
	nr.sql = fmt.Sprintf("SELECT * FROM (%s) WHERE %s", rel.sql, pred)
	return &nr
}

func wrapRaw(rel *relation, sql string, keepOrder bool) *relation {
	nr := *rel
	nr.sql = sql
	if !keepOrder {
		nr.ordered = false
	}
	return &nr
}

// --- search predicate ---

func compileSearch(n sNode, rel *relation) (string, error) {
	switch v := n.(type) {
	case *sAnd:
		l, err := compileSearch(v.L, rel)
		if err != nil {
			return "", err
		}
		r, err := compileSearch(v.R, rel)
		if err != nil {
			return "", err
		}
		return "(" + l + " AND " + r + ")", nil
	case *sOr:
		l, err := compileSearch(v.L, rel)
		if err != nil {
			return "", err
		}
		r, err := compileSearch(v.R, rel)
		if err != nil {
			return "", err
		}
		return "(" + l + " OR " + r + ")", nil
	case *sNot:
		x, err := compileSearch(v.X, rel)
		if err != nil {
			return "", err
		}
		return "(NOT " + x + ")", nil
	case *sTerm:
		return termMatch(v.Text), nil
	case *sCmp:
		return cmpMatch(v, rel)
	case *sIn:
		var parts []string
		for _, val := range v.Values {
			parts = append(parts, fieldEquals(v.Field, val, rel))
		}
		return "(" + strings.Join(parts, " OR ") + ")", nil
	}
	return "", fmt.Errorf("bad search")
}

func termMatch(term string) string {
	if strings.ContainsAny(term, "*?") {
		return fmt.Sprintf("_raw ILIKE %s", chStr(wildcardToLike(term)))
	}
	return fmt.Sprintf("positionCaseInsensitive(_raw, %s) > 0", chStr(term))
}

func cmpMatch(v *sCmp, rel *relation) (string, error) {
	field := resolveStr(v.Field, rel)
	if rel.resolveErr != nil {
		return "", rel.resolveErr
	}
	switch v.Op {
	case "=":
		return fieldEquals(v.Field, v.Value, rel), nil
	case "!=":
		// Null tolerant: a row with no value for the field must match
		// !=, because toFloat64OrNull of a missing value is NULL and
		// NOT NULL is NULL, which the old code dropped silently.
		if isNumeric(v.Value) {
			return fmt.Sprintf("(toString(%s) != %s AND ifNull(toFloat64OrNull(toString(%s)) != %s, true))",
				field, chStr(v.Value), field, v.Value), nil
		}
		if strings.ContainsAny(v.Value, "*?") {
			return fmt.Sprintf("(toString(%s) NOT ILIKE %s OR toString(%s) = '')",
				field, chStr(wildcardToLike(v.Value)), field), nil
		}
		return fmt.Sprintf("(toString(%s) != %s OR toString(%s) = '')",
			field, chStr(v.Value), field), nil
	case "<", "<=", ">", ">=":
		if isNumeric(v.Value) {
			return fmt.Sprintf("toFloat64OrNull(toString(%s)) %s %s", field, v.Op, v.Value), nil
		}
		return fmt.Sprintf("toString(%s) %s %s", field, v.Op, chStr(v.Value)), nil
	}
	return "", fmt.Errorf("bad operator %q", v.Op)
}

func fieldEquals(field, value string, rel *relation) string {
	res := resolveStr(field, rel)
	if strings.ContainsAny(value, "*?") {
		return fmt.Sprintf("toString(%s) ILIKE %s", res, chStr(wildcardToLike(value)))
	}
	if isNumeric(value) {
		return fmt.Sprintf("(toString(%s) = %s OR toFloat64OrNull(toString(%s)) = %s)",
			res, chStr(value), res, value)
	}
	return fmt.Sprintf("toString(%s) = %s", res, chStr(value))
}

// --- field resolution ---

func resolveStr(name string, rel *relation) string {
	if rel.resolveErr == nil {
		if err := checkField(name, rel); err != nil {
			rel.resolveErr = err
			return "''"
		}
	}
	if name == "_time" {
		return "formatDateTime(_time, '%Y-%m-%dT%H:%i:%SZ', 'UTC')"
	}
	if rel.explicit[name] {
		return chIdent(name)
	}
	if rel.mapCol {
		return fmt.Sprintf("%s[%s]", chIdent(mapColumn), chStr(name))
	}
	return "''"
}

// checkField reports an error when name was dropped by a projection such as
// table or fields -, instead of silently resolving to an empty string.
func checkField(name string, rel *relation) error {
	if name == "" {
		return fmt.Errorf("empty field name")
	}
	if rel.dropped != nil && rel.dropped[name] {
		return fmt.Errorf("field %q was removed by an earlier table or fields command", name)
	}
	if name == "_time" {
		if !rel.explicit["_time"] && !rel.mapCol {
			return fmt.Errorf("field %q was removed by an earlier table or fields command", name)
		}
		return nil
	}
	if rel.explicit[name] || rel.mapCol {
		return nil
	}
	return fmt.Errorf("field %q was removed by an earlier table or fields command", name)
}

// resolveRaw returns the column without string formatting, for grouping and
// ordering where the native type matters.
func resolveRaw(name string, rel *relation) string {
	if rel.resolveErr == nil {
		if err := checkField(name, rel); err != nil {
			rel.resolveErr = err
			return "''"
		}
	}
	if rel.explicit[name] {
		return chIdent(name)
	}
	if rel.mapCol {
		return fmt.Sprintf("%s[%s]", chIdent(mapColumn), chStr(name))
	}
	return "''"
}

// --- escaping ---

func chStr(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(s) + "'"
}

func chIdent(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "`", "\\`")
	return "`" + s + "`"
}

func chTime(t time.Time) string {
	return fmt.Sprintf("toDateTime64(%s, 3, 'UTC')", chStr(t.UTC().Format("2006-01-02 15:04:05.000")))
}

func wildcardToLike(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '*':
			b.WriteByte('%')
		case '?':
			b.WriteByte('_')
		case '%', '_', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

var numericRe = regexp.MustCompile(`^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$`)

func isNumeric(s string) bool {
	if !numericRe.MatchString(s) {
		return false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return false
	}
	return !math.IsNaN(f) && !math.IsInf(f, 0)
}

func (c *Compiled) String() string { return c.SQL }

var _ = timeparse.Span
