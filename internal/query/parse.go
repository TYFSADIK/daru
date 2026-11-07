package query

import (
	"fmt"
	"strconv"
	"strings"
)

// Search predicate AST.
type sNode interface{}

type sAnd struct{ L, R sNode }
type sOr struct{ L, R sNode }
type sNot struct{ X sNode }
type sTerm struct {
	Text   string
	Quoted bool
}
type sCmp struct {
	Field, Op, Value string
	Quoted           bool
}
type sIn struct {
	Field  string
	Values []string
}

// Expression AST for eval and where.
type eNode interface{}

type eNum struct{ V float64 }
type eStr struct{ V string }
type eField struct{ Name string }
type eCall struct {
	Name string
	Args []eNode
}
type eBin struct {
	Op   string
	L, R eNode
}
type eUn struct {
	Op string
	X  eNode
}
type eIn struct {
	X    eNode
	List []eNode
	Not  bool
}

// Commands.
type cmdSearch struct{ Pred sNode }
type cmdWhere struct{ Expr eNode }
type assignment struct {
	Name string
	Expr eNode
}
type cmdEval struct{ Assign []assignment }
type agg struct {
	Fn, Arg, As string
	Pct         float64
}
type cmdStats struct {
	Kind   string // stats, eventstats, streamstats
	Aggs   []agg
	By     []string
	Window int
}
type cmdTimechart struct {
	Span  string
	Aggs  []agg
	By    string
	Limit int
}
type cmdChart struct {
	Aggs  []agg
	Over  string
	By    string
	Limit int
}
type cmdTable struct{ Fields []string }
type cmdFields struct {
	Remove bool
	Fields []string
}
type sortKey struct {
	Field string
	Desc  bool
}
type cmdSort struct {
	Limit int
	Keys  []sortKey
}
type cmdHead struct{ N int }
type cmdTail struct{ N int }
type cmdRename struct{ From, To []string }
type cmdDedup struct{ Fields []string }
type cmdTop struct {
	Rare     bool
	Fields   []string
	By       []string
	Limit    int
	ShowPerc bool
}
type cmdRex struct {
	Field, Pattern string
	Names          []string
}
type cmdBin struct {
	Field, Span, As string
}
type cmdFillnull struct {
	Value  string
	Fields []string
}
type cmdSpath struct{ Input, Path, Output string }
type cmdMakeresults struct{ Count int }

// Pipeline is a parsed query.
type Pipeline struct {
	Stages []interface{}
	// Generating is true when the query starts with a leading pipe.
	Generating bool
}

var commandNames = map[string]bool{
	"search": true, "where": true, "eval": true, "stats": true, "eventstats": true,
	"streamstats": true, "timechart": true, "chart": true, "table": true, "fields": true,
	"sort": true, "head": true, "tail": true, "rename": true, "dedup": true, "top": true,
	"rare": true, "rex": true, "bin": true, "bucket": true, "fillnull": true, "spath": true,
	"makeresults": true,
}

// Commands lists the supported command names.
func Commands() []string {
	out := make([]string, 0, len(commandNames))
	for name := range commandNames {
		out = append(out, name)
	}
	return out
}

// Parse parses a BQL query.
func Parse(q string) (*Pipeline, error) {
	parts, err := splitPipes(q)
	if err != nil {
		return nil, err
	}
	p := &Pipeline{}
	if strings.TrimSpace(parts[0]) == "" && len(parts) > 1 {
		p.Generating = true
		parts = parts[1:]
	}
	for idx, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			if idx == 0 && len(parts) == 1 {
				p.Stages = append(p.Stages, &cmdSearch{})
				continue
			}
			return nil, fmt.Errorf("empty command after a pipe")
		}
		name, rest := splitCommand(part)
		if idx == 0 && !p.Generating && !commandNames[strings.ToLower(name)] {
			name, rest = "search", part
		}
		stage, err := parseCommand(strings.ToLower(name), rest)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", strings.ToLower(name), err)
		}
		if idx == 0 && p.Generating {
			if _, ok := stage.(*cmdMakeresults); !ok {
				return nil, fmt.Errorf("a query starting with | must use a generating command such as makeresults")
			}
		} else if _, ok := stage.(*cmdMakeresults); ok {
			return nil, fmt.Errorf("makeresults must be the first command, written as | makeresults")
		}
		p.Stages = append(p.Stages, stage)
	}
	return p, nil
}

func splitCommand(part string) (string, string) {
	i := strings.IndexAny(part, " \t\n\r")
	if i < 0 {
		return part, ""
	}
	return part[:i], strings.TrimSpace(part[i:])
}

func parseCommand(name, rest string) (interface{}, error) {
	switch name {
	case "search":
		return parseSearch(rest)
	case "where":
		s, err := exprStream(rest)
		if err != nil {
			return nil, err
		}
		e, err := parseExpr(s)
		if err != nil {
			return nil, err
		}
		if !s.eof() {
			return nil, fmt.Errorf("unexpected %q", s.peek().text)
		}
		return &cmdWhere{Expr: e}, nil
	case "eval":
		return parseEval(rest)
	case "stats", "eventstats", "streamstats":
		return parseStats(name, rest)
	case "timechart":
		return parseTimechart(rest)
	case "chart":
		return parseChart(rest)
	case "table":
		f, err := fieldList(rest)
		if err != nil {
			return nil, err
		}
		if len(f) == 0 {
			return nil, fmt.Errorf("needs at least one field")
		}
		return &cmdTable{Fields: f}, nil
	case "fields":
		remove := false
		r := strings.TrimSpace(rest)
		if strings.HasPrefix(r, "-") {
			remove, r = true, r[1:]
		} else if strings.HasPrefix(r, "+") {
			r = r[1:]
		}
		f, err := fieldList(r)
		if err != nil {
			return nil, err
		}
		if len(f) == 0 {
			return nil, fmt.Errorf("needs at least one field")
		}
		return &cmdFields{Remove: remove, Fields: f}, nil
	case "sort":
		return parseSort(rest)
	case "head", "tail":
		n, err := countArg(rest, 10)
		if err != nil {
			return nil, err
		}
		if name == "head" {
			return &cmdHead{N: n}, nil
		}
		return &cmdTail{N: n}, nil
	case "rename":
		return parseRename(rest)
	case "dedup":
		f, err := fieldList(rest)
		if err != nil {
			return nil, err
		}
		if len(f) == 0 {
			return nil, fmt.Errorf("needs at least one field")
		}
		return &cmdDedup{Fields: f}, nil
	case "top", "rare":
		return parseTop(name == "rare", rest)
	case "rex":
		return parseRex(rest)
	case "bin", "bucket":
		return parseBin(rest)
	case "fillnull":
		return parseFillnull(rest)
	case "spath":
		return parseSpath(rest)
	case "makeresults":
		opts, rest2, err := options(rest, "count")
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(rest2) != "" {
			return nil, fmt.Errorf("unexpected %q", rest2)
		}
		n := 1
		if v, ok := opts["count"]; ok {
			if n, err = strconv.Atoi(v); err != nil || n < 1 || n > 10000 {
				return nil, fmt.Errorf("count must be between 1 and 10000")
			}
		}
		return &cmdMakeresults{Count: n}, nil
	}
	return nil, fmt.Errorf("unknown command")
}

func exprStream(s string) (*stream, error) {
	toks, err := lexExpr(s)
	if err != nil {
		return nil, err
	}
	return &stream{toks: toks}, nil
}

func searchStream(s string) (*stream, error) {
	toks, err := lexSearch(s)
	if err != nil {
		return nil, err
	}
	return &stream{toks: toks}, nil
}

// options pulls key=value options for the given keys out of the arguments
// and returns them with the remaining text.
func options(rest string, keys ...string) (map[string]string, string, error) {
	s, err := searchStream(rest)
	if err != nil {
		return nil, "", err
	}
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	opts := map[string]string{}
	var kept []string
	for !s.eof() {
		t := s.peek()
		if t.kind == tWord && want[strings.ToLower(t.text)] && s.peekN(1).is(tOp, "=") {
			s.next()
			s.next()
			v := s.next()
			if v.kind != tWord && v.kind != tString {
				return nil, "", fmt.Errorf("missing value for %s", t.text)
			}
			opts[strings.ToLower(t.text)] = v.text
			continue
		}
		s.next()
		kept = append(kept, rest[t.pos:endPos(rest, s, t)])
	}
	return opts, strings.Join(kept, " "), nil
}

func endPos(src string, s *stream, t token) int {
	return s.peek().pos
}

func countArg(rest string, def int) (int, error) {
	opts, r, err := options(rest, "limit")
	if err != nil {
		return 0, err
	}
	r = strings.TrimSpace(r)
	if v, ok := opts["limit"]; ok {
		r = v
	}
	if r == "" {
		return def, nil
	}
	n, err := strconv.Atoi(r)
	if err != nil || n < 1 || n > 1000000 {
		return 0, fmt.Errorf("count must be a positive number")
	}
	return n, nil
}

// fieldList reads field names separated by spaces or commas.
func fieldList(rest string) ([]string, error) {
	s, err := searchStream(rest)
	if err != nil {
		return nil, err
	}
	var out []string
	for !s.eof() {
		t := s.next()
		if t.is(tOp, ",") {
			continue
		}
		if t.kind != tWord && t.kind != tString {
			return nil, fmt.Errorf("unexpected %q", t.text)
		}
		if err := checkName(t.text); err != nil {
			return nil, err
		}
		out = append(out, t.text)
	}
	return out, nil
}

// --- search ---

func parseSearch(rest string) (*cmdSearch, error) {
	s, err := searchStream(rest)
	if err != nil {
		return nil, err
	}
	if s.eof() {
		return &cmdSearch{}, nil
	}
	n, err := parseSOr(s)
	if err != nil {
		return nil, err
	}
	if !s.eof() {
		return nil, fmt.Errorf("unexpected %q", s.peek().text)
	}
	return &cmdSearch{Pred: n}, nil
}

func parseSOr(s *stream) (sNode, error) {
	l, err := parseSAnd(s)
	if err != nil {
		return nil, err
	}
	for s.peek().is(tWord, "OR") {
		s.next()
		r, err := parseSAnd(s)
		if err != nil {
			return nil, err
		}
		l = &sOr{l, r}
	}
	return l, nil
}

func parseSAnd(s *stream) (sNode, error) {
	l, err := parseSNot(s)
	if err != nil {
		return nil, err
	}
	for {
		t := s.peek()
		if t.kind == tEOF || t.is(tOp, ")") || t.is(tWord, "OR") {
			return l, nil
		}
		if t.is(tWord, "AND") {
			s.next()
		}
		r, err := parseSNot(s)
		if err != nil {
			return nil, err
		}
		l = &sAnd{l, r}
	}
}

func parseSNot(s *stream) (sNode, error) {
	if s.peek().is(tWord, "NOT") {
		s.next()
		x, err := parseSNot(s)
		if err != nil {
			return nil, err
		}
		return &sNot{x}, nil
	}
	return parseSPrimary(s)
}

func parseSPrimary(s *stream) (sNode, error) {
	t := s.next()
	switch {
	case t.is(tOp, "("):
		n, err := parseSOr(s)
		if err != nil {
			return nil, err
		}
		if err := s.expect(tOp, ")"); err != nil {
			return nil, err
		}
		return n, nil
	case t.kind == tString:
		return &sTerm{Text: t.text, Quoted: true}, nil
	case t.kind == tWord:
		nt := s.peek()
		if nt.kind == tOp && (nt.text == "=" || nt.text == "!=" || nt.text == "<" || nt.text == "<=" || nt.text == ">" || nt.text == ">=") {
			s.next()
			v := s.next()
			if v.kind != tWord && v.kind != tString {
				return nil, fmt.Errorf("missing value after %s%s", t.text, nt.text)
			}
			if err := checkName(t.text); err != nil {
				return nil, err
			}
			return &sCmp{Field: t.text, Op: nt.text, Value: v.text, Quoted: v.kind == tString}, nil
		}
		if nt.is(tWord, "IN") && s.peekN(1).is(tOp, "(") {
			if err := checkName(t.text); err != nil {
				return nil, err
			}
			s.next()
			s.next()
			var vals []string
			for {
				v := s.next()
				if v.is(tOp, ")") {
					break
				}
				if v.is(tOp, ",") {
					continue
				}
				if v.kind != tWord && v.kind != tString {
					return nil, fmt.Errorf("bad IN list")
				}
				vals = append(vals, v.text)
			}
			if len(vals) == 0 {
				return nil, fmt.Errorf("empty IN list")
			}
			return &sIn{Field: t.text, Values: vals}, nil
		}
		return &sTerm{Text: t.text}, nil
	}
	return nil, fmt.Errorf("unexpected %q", t.text)
}

// --- expressions ---

func parseExpr(s *stream) (eNode, error) { return parseEOr(s) }

func parseEOr(s *stream) (eNode, error) {
	l, err := parseEAnd(s)
	if err != nil {
		return nil, err
	}
	for s.peek().keyword("OR") {
		s.next()
		r, err := parseEAnd(s)
		if err != nil {
			return nil, err
		}
		l = &eBin{"OR", l, r}
	}
	return l, nil
}

func parseEAnd(s *stream) (eNode, error) {
	l, err := parseENot(s)
	if err != nil {
		return nil, err
	}
	for s.peek().keyword("AND") {
		s.next()
		r, err := parseENot(s)
		if err != nil {
			return nil, err
		}
		l = &eBin{"AND", l, r}
	}
	return l, nil
}

func parseENot(s *stream) (eNode, error) {
	if s.peek().keyword("NOT") || s.peek().is(tOp, "!") {
		s.next()
		x, err := parseENot(s)
		if err != nil {
			return nil, err
		}
		return &eUn{"NOT", x}, nil
	}
	return parseECmp(s)
}

func parseECmp(s *stream) (eNode, error) {
	l, err := parseEAdd(s)
	if err != nil {
		return nil, err
	}
	t := s.peek()
	if t.kind == tOp {
		switch t.text {
		case "=", "==", "!=", "<", "<=", ">", ">=":
			s.next()
			r, err := parseEAdd(s)
			if err != nil {
				return nil, err
			}
			op := t.text
			if op == "==" {
				op = "="
			}
			return &eBin{op, l, r}, nil
		}
	}
	not := false
	if t.keyword("NOT") && s.peekN(1).keyword("IN") {
		s.next()
		not = true
		t = s.peek()
	}
	if t.keyword("LIKE") {
		s.next()
		r, err := parseEAdd(s)
		if err != nil {
			return nil, err
		}
		return &eCall{"like", []eNode{l, r}}, nil
	}
	if t.keyword("IN") {
		s.next()
		if err := s.expect(tOp, "("); err != nil {
			return nil, err
		}
		in := &eIn{X: l, Not: not}
		for !s.accept(tOp, ")") {
			if s.eof() {
				return nil, fmt.Errorf("unterminated IN list")
			}
			e, err := parseEAdd(s)
			if err != nil {
				return nil, err
			}
			in.List = append(in.List, e)
			s.accept(tOp, ",")
		}
		return in, nil
	}
	return l, nil
}

func parseEAdd(s *stream) (eNode, error) {
	l, err := parseEMul(s)
	if err != nil {
		return nil, err
	}
	for {
		t := s.peek()
		if t.kind == tOp && (t.text == "+" || t.text == "-" || t.text == ".") {
			s.next()
			r, err := parseEMul(s)
			if err != nil {
				return nil, err
			}
			l = &eBin{t.text, l, r}
			continue
		}
		return l, nil
	}
}

func parseEMul(s *stream) (eNode, error) {
	l, err := parseEUnary(s)
	if err != nil {
		return nil, err
	}
	for {
		t := s.peek()
		if t.kind == tOp && (t.text == "*" || t.text == "/" || t.text == "%") {
			s.next()
			r, err := parseEUnary(s)
			if err != nil {
				return nil, err
			}
			l = &eBin{t.text, l, r}
			continue
		}
		return l, nil
	}
}

func parseEUnary(s *stream) (eNode, error) {
	if s.peek().is(tOp, "-") {
		s.next()
		x, err := parseEUnary(s)
		if err != nil {
			return nil, err
		}
		return &eUn{"-", x}, nil
	}
	return parseEPrimary(s)
}

func parseEPrimary(s *stream) (eNode, error) {
	t := s.next()
	switch {
	case t.kind == tNum:
		v, err := strconv.ParseFloat(t.text, 64)
		if err != nil {
			return nil, fmt.Errorf("bad number %q", t.text)
		}
		return &eNum{v}, nil
	case t.kind == tString:
		return &eStr{t.text}, nil
	case t.is(tOp, "("):
		e, err := parseExpr(s)
		if err != nil {
			return nil, err
		}
		if err := s.expect(tOp, ")"); err != nil {
			return nil, err
		}
		return e, nil
	case t.kind == tWord:
		if !t.quoted && s.peek().is(tOp, "(") {
			s.next()
			call := &eCall{Name: strings.ToLower(t.text)}
			for !s.accept(tOp, ")") {
				if s.eof() {
					return nil, fmt.Errorf("unterminated call to %s", t.text)
				}
				e, err := parseExpr(s)
				if err != nil {
					return nil, err
				}
				call.Args = append(call.Args, e)
				if !s.accept(tOp, ",") && !s.peek().is(tOp, ")") {
					return nil, fmt.Errorf("expected , or ) in call to %s", t.text)
				}
			}
			return call, nil
		}
		if !t.quoted {
			switch strings.ToLower(t.text) {
			case "true":
				return &eCall{Name: "true"}, nil
			case "false":
				return &eCall{Name: "false"}, nil
			case "null":
				return &eCall{Name: "null"}, nil
			}
		}
		if err := checkName(t.text); err != nil {
			return nil, err
		}
		return &eField{t.text}, nil
	}
	if t.kind == tEOF {
		return nil, fmt.Errorf("expression ends too early")
	}
	return nil, fmt.Errorf("unexpected %q", t.text)
}

func parseEval(rest string) (*cmdEval, error) {
	s, err := exprStream(rest)
	if err != nil {
		return nil, err
	}
	ev := &cmdEval{}
	for !s.eof() {
		name := s.next()
		if name.kind != tWord {
			return nil, fmt.Errorf("expected a field name, got %q", name.text)
		}
		if err := checkName(name.text); err != nil {
			return nil, err
		}
		if err := s.expect(tOp, "="); err != nil {
			return nil, err
		}
		e, err := parseExpr(s)
		if err != nil {
			return nil, err
		}
		ev.Assign = append(ev.Assign, assignment{name.text, e})
		if !s.accept(tOp, ",") && !s.eof() {
			return nil, fmt.Errorf("unexpected %q", s.peek().text)
		}
	}
	if len(ev.Assign) == 0 {
		return nil, fmt.Errorf("needs at least one assignment")
	}
	return ev, nil
}

// --- aggregations ---

var aggFuncs = map[string]bool{
	"count": true, "c": true, "dc": true, "distinct_count": true, "estdc": true, "sum": true,
	"avg": true, "mean": true, "min": true, "max": true, "median": true, "mode": true,
	"range": true, "stdev": true, "stdevp": true, "var": true, "varp": true, "values": true,
	"list": true, "earliest": true, "latest": true, "first": true, "last": true, "sumsq": true,
}

func isAggName(name string) bool {
	n := strings.ToLower(name)
	if aggFuncs[n] {
		return true
	}
	_, ok := percentile(n)
	return ok
}

func percentile(n string) (float64, bool) {
	for _, prefix := range []string{"exactperc", "perc", "p"} {
		if strings.HasPrefix(n, prefix) {
			v, err := strconv.ParseFloat(n[len(prefix):], 64)
			if err == nil && v > 0 && v < 100 {
				return v, true
			}
		}
	}
	return 0, false
}

// parseAggs reads aggregations until "by", "over", or the end.
func parseAggs(s *stream) ([]agg, error) {
	var out []agg
	for !s.eof() {
		t := s.peek()
		if t.keyword("by") || t.keyword("over") {
			break
		}
		if t.is(tOp, ",") {
			s.next()
			continue
		}
		if t.kind != tWord || !isAggName(t.text) {
			return nil, fmt.Errorf("unknown aggregation %q", t.text)
		}
		s.next()
		a := agg{Fn: strings.ToLower(t.text)}
		if a.Fn == "c" {
			a.Fn = "count"
		}
		if a.Fn == "distinct_count" {
			a.Fn = "dc"
		}
		if a.Fn == "mean" {
			a.Fn = "avg"
		}
		if s.accept(tOp, "(") {
			f := s.next()
			if f.kind != tWord && f.kind != tString {
				return nil, fmt.Errorf("expected a field in %s()", a.Fn)
			}
			if err := checkName(f.text); err != nil {
				return nil, err
			}
			a.Arg = f.text
			if err := s.expect(tOp, ")"); err != nil {
				return nil, err
			}
		} else if a.Fn != "count" {
			return nil, fmt.Errorf("%s needs a field, like %s(bytes)", a.Fn, a.Fn)
		}
		if p, ok := percentile(a.Fn); ok {
			a.Pct = p
		}
		a.As = a.Fn
		if a.Arg != "" {
			a.As = a.Fn + "(" + a.Arg + ")"
		}
		if s.peek().keyword("as") {
			s.next()
			n := s.next()
			if n.kind != tWord && n.kind != tString {
				return nil, fmt.Errorf("expected a name after as")
			}
			if err := checkName(n.text); err != nil {
				return nil, err
			}
			a.As = n.text
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("needs at least one aggregation, for example count")
	}
	return out, nil
}

func byFields(s *stream) ([]string, error) {
	var out []string
	for !s.eof() {
		t := s.next()
		if t.is(tOp, ",") {
			continue
		}
		if t.kind != tWord && t.kind != tString {
			return nil, fmt.Errorf("unexpected %q", t.text)
		}
		if err := checkName(t.text); err != nil {
			return nil, err
		}
		out = append(out, t.text)
	}
	return out, nil
}

func parseStats(kind, rest string) (*cmdStats, error) {
	opts, rest, err := options(rest, "window")
	if err != nil {
		return nil, err
	}
	s, err := searchStream(rest)
	if err != nil {
		return nil, err
	}
	aggs, err := parseAggs(s)
	if err != nil {
		return nil, err
	}
	st := &cmdStats{Kind: kind, Aggs: aggs}
	if v, ok := opts["window"]; ok {
		if kind != "streamstats" {
			return nil, fmt.Errorf("window only applies to streamstats")
		}
		if st.Window, err = strconv.Atoi(v); err != nil || st.Window < 1 || st.Window > 100000 {
			return nil, fmt.Errorf("window must be a positive number")
		}
	}
	if s.peek().keyword("by") {
		s.next()
		if st.By, err = byFields(s); err != nil {
			return nil, err
		}
		if len(st.By) == 0 {
			return nil, fmt.Errorf("by needs at least one field")
		}
	}
	if !s.eof() {
		return nil, fmt.Errorf("unexpected %q", s.peek().text)
	}
	return st, nil
}

func parseTimechart(rest string) (*cmdTimechart, error) {
	opts, rest, err := options(rest, "span", "limit")
	if err != nil {
		return nil, err
	}
	s, err := searchStream(rest)
	if err != nil {
		return nil, err
	}
	aggs, err := parseAggs(s)
	if err != nil {
		return nil, err
	}
	tc := &cmdTimechart{Span: opts["span"], Aggs: aggs, Limit: 10}
	if v, ok := opts["limit"]; ok {
		if tc.Limit, err = strconv.Atoi(v); err != nil || tc.Limit < 0 {
			return nil, fmt.Errorf("limit must be zero or more")
		}
	}
	if s.peek().keyword("by") {
		s.next()
		by, err := byFields(s)
		if err != nil {
			return nil, err
		}
		if len(by) != 1 {
			return nil, fmt.Errorf("timechart splits by exactly one field")
		}
		if len(aggs) != 1 {
			return nil, fmt.Errorf("timechart with by takes one aggregation")
		}
		tc.By = by[0]
	}
	if !s.eof() {
		return nil, fmt.Errorf("unexpected %q", s.peek().text)
	}
	return tc, nil
}

func parseChart(rest string) (*cmdChart, error) {
	opts, rest, err := options(rest, "limit")
	if err != nil {
		return nil, err
	}
	s, err := searchStream(rest)
	if err != nil {
		return nil, err
	}
	aggs, err := parseAggs(s)
	if err != nil {
		return nil, err
	}
	ch := &cmdChart{Aggs: aggs, Limit: 10}
	if v, ok := opts["limit"]; ok {
		if ch.Limit, err = strconv.Atoi(v); err != nil || ch.Limit < 0 {
			return nil, fmt.Errorf("limit must be zero or more")
		}
	}
	if s.peek().keyword("over") {
		s.next()
		t := s.next()
		if t.kind != tWord {
			return nil, fmt.Errorf("over needs a field")
		}
		ch.Over = t.text
		if s.peek().keyword("by") {
			s.next()
			b := s.next()
			if b.kind != tWord {
				return nil, fmt.Errorf("by needs a field")
			}
			ch.By = b.text
		}
	} else if s.peek().keyword("by") {
		s.next()
		by, err := byFields(s)
		if err != nil {
			return nil, err
		}
		if len(by) < 1 || len(by) > 2 {
			return nil, fmt.Errorf("chart takes one or two by fields")
		}
		ch.Over = by[0]
		if len(by) == 2 {
			ch.By = by[1]
		}
	}
	if !s.eof() {
		return nil, fmt.Errorf("unexpected %q", s.peek().text)
	}
	for _, n := range []string{ch.Over, ch.By} {
		if n != "" {
			if err := checkName(n); err != nil {
				return nil, err
			}
		}
	}
	if ch.By != "" && len(aggs) != 1 {
		return nil, fmt.Errorf("chart with two split fields takes one aggregation")
	}
	return ch, nil
}

func parseSort(rest string) (*cmdSort, error) {
	s, err := searchStream(rest)
	if err != nil {
		return nil, err
	}
	so := &cmdSort{}
	if t := s.peek(); t.kind == tWord {
		if n, err := strconv.Atoi(t.text); err == nil {
			if n < 1 {
				return nil, fmt.Errorf("sort limit must be positive")
			}
			so.Limit = n
			s.next()
		}
	}
	pendingDesc := false
	for !s.eof() {
		t := s.next()
		if t.is(tOp, ",") {
			continue
		}
		if t.kind != tWord && t.kind != tString {
			return nil, fmt.Errorf("unexpected %q", t.text)
		}
		name := t.text
		desc := pendingDesc
		pendingDesc = false
		if t.kind == tWord && (name == "-" || name == "+") {
			pendingDesc = name == "-"
			continue
		}
		if t.kind == tWord && strings.HasPrefix(name, "-") {
			desc, name = true, name[1:]
		} else if t.kind == tWord && strings.HasPrefix(name, "+") {
			name = name[1:]
		}
		if err := checkName(name); err != nil {
			return nil, err
		}
		so.Keys = append(so.Keys, sortKey{name, desc})
	}
	if len(so.Keys) == 0 {
		return nil, fmt.Errorf("needs at least one field")
	}
	return so, nil
}

func parseRename(rest string) (*cmdRename, error) {
	s, err := searchStream(rest)
	if err != nil {
		return nil, err
	}
	r := &cmdRename{}
	for !s.eof() {
		if s.accept(tOp, ",") {
			continue
		}
		from := s.next()
		as := s.next()
		to := s.next()
		if (from.kind != tWord && from.kind != tString) || !as.keyword("as") || (to.kind != tWord && to.kind != tString) {
			return nil, fmt.Errorf("use the form: rename old AS new")
		}
		for _, n := range []string{from.text, to.text} {
			if err := checkName(n); err != nil {
				return nil, err
			}
		}
		r.From = append(r.From, from.text)
		r.To = append(r.To, to.text)
	}
	if len(r.From) == 0 {
		return nil, fmt.Errorf("needs at least one field")
	}
	return r, nil
}

func parseTop(rare bool, rest string) (*cmdTop, error) {
	opts, rest, err := options(rest, "limit", "showperc")
	if err != nil {
		return nil, err
	}
	s, err := searchStream(rest)
	if err != nil {
		return nil, err
	}
	t := &cmdTop{Rare: rare, Limit: 10, ShowPerc: true}
	if v, ok := opts["limit"]; ok {
		if t.Limit, err = strconv.Atoi(v); err != nil || t.Limit < 1 {
			return nil, fmt.Errorf("limit must be positive")
		}
	}
	if v, ok := opts["showperc"]; ok {
		t.ShowPerc = v != "false" && v != "f" && v != "0"
	}
	for !s.eof() && !s.peek().keyword("by") {
		tk := s.next()
		if tk.is(tOp, ",") {
			continue
		}
		if tk.kind != tWord && tk.kind != tString {
			return nil, fmt.Errorf("unexpected %q", tk.text)
		}
		if err := checkName(tk.text); err != nil {
			return nil, err
		}
		t.Fields = append(t.Fields, tk.text)
	}
	if len(t.Fields) == 0 {
		return nil, fmt.Errorf("needs at least one field")
	}
	if s.peek().keyword("by") {
		s.next()
		if t.By, err = byFields(s); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func parseRex(rest string) (*cmdRex, error) {
	opts, rest, err := options(rest, "field")
	if err != nil {
		return nil, err
	}
	s, err := searchStream(rest)
	if err != nil {
		return nil, err
	}
	pat := s.next()
	if pat.kind != tString || !s.eof() {
		return nil, fmt.Errorf(`use the form: rex field=_raw "(?<name>pattern)"`)
	}
	r := &cmdRex{Field: "_raw", Pattern: pat.text}
	if v, ok := opts["field"]; ok {
		if err := checkName(v); err != nil {
			return nil, err
		}
		r.Field = v
	}
	return r, nil
}

func parseBin(rest string) (*cmdBin, error) {
	opts, rest, err := options(rest, "span")
	if err != nil {
		return nil, err
	}
	s, err := searchStream(rest)
	if err != nil {
		return nil, err
	}
	f := s.next()
	if f.kind != tWord {
		return nil, fmt.Errorf("needs a field, for example bin _time span=1h")
	}
	if err := checkName(f.text); err != nil {
		return nil, err
	}
	b := &cmdBin{Field: f.text, Span: opts["span"], As: f.text}
	if s.peek().keyword("as") {
		s.next()
		n := s.next()
		if n.kind != tWord {
			return nil, fmt.Errorf("expected a name after as")
		}
		if err := checkName(n.text); err != nil {
			return nil, err
		}
		b.As = n.text
	}
	if !s.eof() {
		return nil, fmt.Errorf("unexpected %q", s.peek().text)
	}
	if b.Span == "" {
		return nil, fmt.Errorf("needs span=, for example span=1h or span=100")
	}
	return b, nil
}

func parseFillnull(rest string) (*cmdFillnull, error) {
	opts, rest, err := options(rest, "value")
	if err != nil {
		return nil, err
	}
	fields, err := fieldList(rest)
	if err != nil {
		return nil, err
	}
	v, ok := opts["value"]
	if !ok {
		v = "0"
	}
	return &cmdFillnull{Value: v, Fields: fields}, nil
}

func parseSpath(rest string) (*cmdSpath, error) {
	opts, rest, err := options(rest, "input", "path", "output")
	if err != nil {
		return nil, err
	}
	sp := &cmdSpath{Input: "_raw", Path: opts["path"], Output: opts["output"]}
	if r := strings.TrimSpace(rest); r != "" {
		if sp.Path != "" {
			return nil, fmt.Errorf("unexpected %q", r)
		}
		sp.Path = r
	}
	if v, ok := opts["input"]; ok {
		sp.Input = v
	}
	if sp.Path == "" {
		return nil, fmt.Errorf("needs a path, for example spath path=user.name")
	}
	if sp.Output == "" {
		sp.Output = sp.Path
	}
	for _, n := range []string{sp.Input, sp.Output} {
		if err := checkName(n); err != nil {
			return nil, err
		}
	}
	return sp, nil
}

// checkName rejects field names that could escape an identifier quote.
func checkName(n string) error {
	if n == "" || len(n) > 128 {
		return fmt.Errorf("field names must be 1 to 128 characters")
	}
	for _, r := range n {
		if r == '`' || r == '\\' || r < 0x20 || r == 0x7f {
			return fmt.Errorf("field name %q contains a character that is not allowed", n)
		}
	}
	return nil
}
