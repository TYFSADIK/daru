package query

import (
	"fmt"
	"strings"

	"github.com/TYFSADIK/daru/internal/timeparse"
)

func compileEval(rel *relation, c *cmdEval) (*relation, error) {
	cur := rel
	for _, a := range c.Assign {
		e, err := compileExpr(a.Expr, cur)
		if err != nil {
			return nil, err
		}
		explicit, order := cloneCols(cur)
		except := ""
		if explicit[a.Name] {
			except = fmt.Sprintf(" EXCEPT (%s)", chIdent(a.Name))
		} else {
			order = append(order, a.Name)
		}
		explicit[a.Name] = true
		nr := *cur
		nr.sql = fmt.Sprintf("SELECT *%s, %s AS %s FROM (%s)", except, e.sql, chIdent(a.Name), cur.sql)
		nr.explicit = explicit
		nr.order = order
		cur = &nr
	}
	return cur, nil
}

// aggExpr builds the ClickHouse aggregate for one agg spec.
func aggExpr(a agg, rel *relation) (string, error) {
	raw := func() string { return resolveStr(a.Arg, rel) }
	num := func() string { return "toFloat64OrNull(toString(" + resolveStr(a.Arg, rel) + "))" }
	tm := resolveRaw("_time", rel)

	switch a.Fn {
	case "count":
		if a.Arg == "" {
			return "toFloat64(count())", nil
		}
		return fmt.Sprintf("toFloat64(countIf(toString(%s) != ''))", raw()), nil
	case "dc", "estdc":
		return fmt.Sprintf("toFloat64(uniqExact(toString(%s)))", raw()), nil
	case "sum":
		return fmt.Sprintf("sum(%s)", num()), nil
	case "sumsq":
		return fmt.Sprintf("sum(pow(%s, 2))", num()), nil
	case "avg":
		return fmt.Sprintf("avg(%s)", num()), nil
	case "min":
		return fmt.Sprintf("min(%s)", num()), nil
	case "max":
		return fmt.Sprintf("max(%s)", num()), nil
	case "range":
		return fmt.Sprintf("(max(%s) - min(%s))", num(), num()), nil
	case "median":
		return fmt.Sprintf("quantileExact(0.5)(%s)", num()), nil
	case "stdev":
		return fmt.Sprintf("stddevSamp(%s)", num()), nil
	case "stdevp":
		return fmt.Sprintf("stddevPop(%s)", num()), nil
	case "var":
		return fmt.Sprintf("varSamp(%s)", num()), nil
	case "varp":
		return fmt.Sprintf("varPop(%s)", num()), nil
	case "mode":
		return fmt.Sprintf("arrayElement(topK(1)(toString(%s)), 1)", raw()), nil
	case "values":
		return fmt.Sprintf("arrayStringConcat(arraySort(groupUniqArray(toString(%s))), '\\n')", raw()), nil
	case "list":
		return fmt.Sprintf("arrayStringConcat(groupArray(toString(%s)), '\\n')", raw()), nil
	case "earliest":
		return fmt.Sprintf("argMin(toString(%s), %s)", raw(), tm), nil
	case "latest", "last":
		return fmt.Sprintf("argMax(toString(%s), %s)", raw(), tm), nil
	case "first":
		return fmt.Sprintf("any(toString(%s))", raw()), nil
	}
	if a.Pct > 0 {
		return fmt.Sprintf("quantileExact(%g)(%s)", a.Pct/100, num()), nil
	}
	return "", fmt.Errorf("unknown aggregation %q", a.Fn)
}

// stringAgg reports whether an aggregation produces a string rather than a number.
func stringAgg(a agg) bool {
	switch a.Fn {
	case "values", "list", "mode", "earliest", "latest", "last", "first":
		return true
	}
	return false
}

func compileStats(rel *relation, c *cmdStats) (*relation, error) {
	if c.Kind == "streamstats" {
		return compileStreamstats(rel, c)
	}
	var sel, order []string
	explicit := map[string]bool{}
	for _, by := range c.By {
		sel = append(sel, fmt.Sprintf("%s AS %s", resolveStr(by, rel), chIdent(by)))
		order = append(order, by)
		explicit[by] = true
	}
	for _, a := range c.Aggs {
		expr, err := aggExpr(a, rel)
		if err != nil {
			return nil, err
		}
		sel = append(sel, fmt.Sprintf("%s AS %s", expr, chIdent(a.As)))
		order = append(order, a.As)
		explicit[a.As] = true
	}

	if c.Kind == "eventstats" {
		// eventstats keeps every row and adds aggregate columns via windows.
		var win []string
		part := ""
		if len(c.By) > 0 {
			var p []string
			for _, by := range c.By {
				p = append(p, resolveStr(by, rel))
			}
			part = "PARTITION BY " + strings.Join(p, ", ")
		}
		for _, a := range c.Aggs {
			expr, err := aggExpr(a, rel)
			if err != nil {
				return nil, err
			}
			win = append(win, fmt.Sprintf("%s OVER (%s) AS %s", expr, part, chIdent(a.As)))
		}
		keep, korder := cloneCols(rel)
		for _, a := range c.Aggs {
			if keep[a.As] {
				continue
			}
			keep[a.As] = true
			korder = append(korder, a.As)
		}
		nr := *rel
		nr.sql = fmt.Sprintf("SELECT *, %s FROM (%s)", strings.Join(win, ", "), rel.sql)
		nr.explicit = keep
		nr.order = korder
		return &nr, nil
	}

	groupBy := ""
	if len(c.By) > 0 {
		var g []string
		for _, by := range c.By {
			g = append(g, resolveStr(by, rel))
		}
		groupBy = " GROUP BY " + strings.Join(g, ", ")
	}
	sql := fmt.Sprintf("SELECT %s FROM (%s)%s", strings.Join(sel, ", "), rel.sql, groupBy)
	if len(c.By) > 0 {
		sql += " ORDER BY " + strings.Join(byOrder(c.By), ", ")
	}
	return &relation{
		sql: sql, explicit: explicit, order: order,
		transform: true, ordered: true, kind: "table",
	}, nil
}

func byOrder(by []string) []string {
	var out []string
	for _, b := range by {
		out = append(out, chIdent(b)+" ASC")
	}
	return out
}

func compileStreamstats(rel *relation, c *cmdStats) (*relation, error) {
	part := ""
	if len(c.By) > 0 {
		var p []string
		for _, by := range c.By {
			p = append(p, resolveStr(by, rel))
		}
		part = "PARTITION BY " + strings.Join(p, ", ") + " "
	}
	frame := "ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW"
	if c.Window > 0 {
		frame = fmt.Sprintf("ROWS BETWEEN %d PRECEDING AND CURRENT ROW", c.Window-1)
	}
	var win []string
	keep, korder := cloneCols(rel)
	for _, a := range c.Aggs {
		expr, err := aggExpr(a, rel)
		if err != nil {
			return nil, err
		}
		win = append(win, fmt.Sprintf("%s OVER (%sORDER BY %s %s) AS %s",
			expr, part, resolveRaw("_time", rel), frame, chIdent(a.As)))
		if !keep[a.As] {
			keep[a.As] = true
			korder = append(korder, a.As)
		}
	}
	nr := *rel
	nr.sql = fmt.Sprintf("SELECT *, %s FROM (%s)", strings.Join(win, ", "), rel.sql)
	nr.explicit = keep
	nr.order = korder
	return &nr, nil
}

func compileTimechart(rel *relation, c *cmdTimechart, opt Options) (*relation, error) {
	span := c.Span
	if span == "" {
		span = timeparse.AutoSpan(opt.Earliest, opt.Latest)
		if opt.Earliest.IsZero() || opt.Latest.IsZero() {
			span = "1h"
		}
	}
	n, unit, _, err := timeparse.Span(span)
	if err != nil {
		return nil, err
	}
	bucket := fmt.Sprintf("toStartOfInterval(%s, INTERVAL %d %s, 'UTC')", resolveRaw("_time", rel), n, unit)
	a := c.Aggs[0]
	expr, err := aggExpr(a, rel)
	if err != nil {
		return nil, err
	}

	if c.By == "" {
		var sel = []string{fmt.Sprintf("%s AS _time", bucket)}
		var order = []string{"_time"}
		explicit := map[string]bool{"_time": true}
		for _, ag := range c.Aggs {
			ex, err := aggExpr(ag, rel)
			if err != nil {
				return nil, err
			}
			sel = append(sel, fmt.Sprintf("%s AS %s", ex, chIdent(ag.As)))
			order = append(order, ag.As)
			explicit[ag.As] = true
		}
		sql := fmt.Sprintf("SELECT %s FROM (%s) GROUP BY _time ORDER BY _time ASC",
			strings.Join(sel, ", "), rel.sql)
		return &relation{
			sql: sql, explicit: explicit, order: order,
			transform: true, ordered: true, kind: "timechart", timeField: "_time",
		}, nil
	}

	// Split by a series field: emit long format (_time, series, value); the
	// API pivots into columns and limits to the top series.
	series := resolveStr(c.By, rel)
	sql := fmt.Sprintf(
		"SELECT %s AS _time, toString(%s) AS series, %s AS value FROM (%s) GROUP BY _time, series ORDER BY _time ASC",
		bucket, series, expr, rel.sql,
	)
	return &relation{
		sql:       sql,
		explicit:  map[string]bool{"_time": true, "series": true, "value": true},
		order:     []string{"_time", "series", "value"},
		transform: true, ordered: true, kind: "timechart", timeField: "_time",
	}, nil
}

func compileChart(rel *relation, c *cmdChart) (*relation, error) {
	a := c.Aggs[0]
	expr, err := aggExpr(a, rel)
	if err != nil {
		return nil, err
	}
	if c.By == "" {
		var sel = []string{fmt.Sprintf("toString(%s) AS %s", resolveStr(c.Over, rel), chIdent(c.Over))}
		order := []string{c.Over}
		explicit := map[string]bool{c.Over: true}
		for _, ag := range c.Aggs {
			ex, err := aggExpr(ag, rel)
			if err != nil {
				return nil, err
			}
			sel = append(sel, fmt.Sprintf("%s AS %s", ex, chIdent(ag.As)))
			order = append(order, ag.As)
			explicit[ag.As] = true
		}
		sql := fmt.Sprintf("SELECT %s FROM (%s) GROUP BY %s ORDER BY %s ASC",
			strings.Join(sel, ", "), rel.sql, chIdent(c.Over), chIdent(c.Over))
		return &relation{sql: sql, explicit: explicit, order: order, transform: true, ordered: true, kind: "chart"}, nil
	}
	sql := fmt.Sprintf(
		"SELECT toString(%s) AS %s, toString(%s) AS series, %s AS value FROM (%s) GROUP BY %s, series ORDER BY %s ASC",
		resolveStr(c.Over, rel), chIdent(c.Over), resolveStr(c.By, rel), expr, rel.sql,
		chIdent(c.Over), chIdent(c.Over),
	)
	return &relation{
		sql:       sql,
		explicit:  map[string]bool{c.Over: true, "series": true, "value": true},
		order:     []string{c.Over, "series", "value"},
		transform: true, ordered: true, kind: "chart",
	}, nil
}

func compileTable(rel *relation, fields []string, _ bool) (*relation, error) {
	var sel, order []string
	explicit := map[string]bool{}
	for _, f := range fields {
		sel = append(sel, fmt.Sprintf("%s AS %s", resolveStr(f, rel), chIdent(f)))
		order = append(order, f)
		explicit[f] = true
	}
	nr := *rel
	nr.sql = fmt.Sprintf("SELECT %s FROM (%s)", strings.Join(sel, ", "), rel.sql)
	nr.explicit = explicit
	nr.order = order
	nr.mapCol = false
	return &nr, nil
}

func compileFields(rel *relation, c *cmdFields) (*relation, error) {
	if !c.Remove {
		return compileTable(rel, c.Fields, true)
	}
	explicit, order := cloneCols(rel)
	var keptOrder []string
	remove := map[string]bool{}
	for _, f := range c.Fields {
		remove[f] = true
		delete(explicit, f)
	}
	var excepts []string
	for _, f := range c.Fields {
		if rel.explicit[f] {
			excepts = append(excepts, chIdent(f))
		}
	}
	for _, f := range order {
		if !remove[f] {
			keptOrder = append(keptOrder, f)
		}
	}
	except := ""
	if len(excepts) > 0 {
		except = fmt.Sprintf(" EXCEPT (%s)", strings.Join(excepts, ", "))
	}
	mapExpr := ""
	if rel.mapCol {
		var keys []string
		for _, f := range c.Fields {
			keys = append(keys, chStr(f))
		}
		mapExpr = fmt.Sprintf(", mapFilter((k, v) -> k NOT IN (%s), %s) AS %s",
			strings.Join(keys, ", "), chIdent(mapColumn), chIdent(mapColumn))
		except += fmt.Sprintf(" EXCEPT (%s)", chIdent(mapColumn))
	}
	nr := *rel
	nr.sql = fmt.Sprintf("SELECT *%s%s FROM (%s)", except, mapExpr, rel.sql)
	nr.explicit = explicit
	nr.order = keptOrder
	return &nr, nil
}

func compileSort(rel *relation, c *cmdSort) (*relation, error) {
	var keys []string
	for _, k := range c.Keys {
		dir := "ASC"
		if k.Desc {
			dir = "DESC"
		}
		res := resolveStr(k.Field, rel)
		keys = append(keys,
			fmt.Sprintf("isNull(toFloat64OrNull(toString(%s))) %s", res, dir),
			fmt.Sprintf("toFloat64OrNull(toString(%s)) %s", res, dir),
			fmt.Sprintf("toString(%s) %s", res, dir),
		)
	}
	sql := fmt.Sprintf("SELECT * FROM (%s) ORDER BY %s", rel.sql, strings.Join(keys, ", "))
	if c.Limit > 0 {
		sql += fmt.Sprintf(" LIMIT %d", c.Limit)
	}
	nr := *rel
	nr.sql = sql
	nr.ordered = true
	return &nr, nil
}

func compileTail(rel *relation, n int) (*relation, error) {
	sql := fmt.Sprintf(
		"SELECT * EXCEPT (__rn, __cnt) FROM (SELECT *, row_number() OVER () AS __rn, count() OVER () AS __cnt FROM (%s)) WHERE __rn > __cnt - %d",
		rel.sql, n,
	)
	nr := *rel
	nr.sql = sql
	return &nr, nil
}

func compileRename(rel *relation, c *cmdRename) (*relation, error) {
	explicit, order := cloneCols(rel)
	var adds, excepts []string
	for i, from := range c.From {
		to := c.To[i]
		adds = append(adds, fmt.Sprintf("%s AS %s", resolveStr(from, rel), chIdent(to)))
		if rel.explicit[from] {
			excepts = append(excepts, chIdent(from))
			delete(explicit, from)
			for j, o := range order {
				if o == from {
					order[j] = to
				}
			}
		} else {
			order = append(order, to)
		}
		explicit[to] = true
	}
	except := ""
	if len(excepts) > 0 {
		except = fmt.Sprintf(" EXCEPT (%s)", strings.Join(excepts, ", "))
	}
	nr := *rel
	nr.sql = fmt.Sprintf("SELECT *%s, %s FROM (%s)", except, strings.Join(adds, ", "), rel.sql)
	nr.explicit = explicit
	nr.order = order
	return &nr, nil
}

func compileDedup(rel *relation, c *cmdDedup) (*relation, error) {
	var part []string
	for _, f := range c.Fields {
		part = append(part, resolveStr(f, rel))
	}
	sql := fmt.Sprintf(
		"SELECT * EXCEPT (__rn) FROM (SELECT *, row_number() OVER (PARTITION BY %s ORDER BY %s DESC) AS __rn FROM (%s)) WHERE __rn = 1",
		strings.Join(part, ", "), resolveRaw("_time", rel), rel.sql,
	)
	nr := *rel
	nr.sql = sql
	return &nr, nil
}

func compileTop(rel *relation, c *cmdTop) (*relation, error) {
	group := append([]string(nil), c.By...)
	group = append(group, c.Fields...)
	var sel, groupBy, order []string
	explicit := map[string]bool{}
	for _, f := range group {
		sel = append(sel, fmt.Sprintf("toString(%s) AS %s", resolveStr(f, rel), chIdent(f)))
		groupBy = append(groupBy, chIdent(f))
		order = append(order, f)
		explicit[f] = true
	}
	sel = append(sel, "toFloat64(count()) AS count")
	explicit["count"] = true
	order = append(order, "count")
	if c.ShowPerc {
		sel = append(sel, "round(100.0 * count() / sum(count()) OVER (), 4) AS percent")
		explicit["percent"] = true
		order = append(order, "percent")
	}
	dir := "DESC"
	if c.Rare {
		dir = "ASC"
	}
	sql := fmt.Sprintf("SELECT %s FROM (%s) GROUP BY %s ORDER BY count %s LIMIT %d",
		strings.Join(sel, ", "), rel.sql, strings.Join(groupBy, ", "), dir, c.Limit)
	return &relation{sql: sql, explicit: explicit, order: order, transform: true, ordered: true, kind: "table"}, nil
}

func compileBin(rel *relation, c *cmdBin) (*relation, error) {
	explicit, order := cloneCols(rel)
	var expr string
	if n, unit, _, err := timeparse.Span(c.Span); err == nil && c.Field == "_time" {
		expr = fmt.Sprintf("toStartOfInterval(%s, INTERVAL %d %s, 'UTC')", resolveRaw(c.Field, rel), n, unit)
	} else if isNumeric(c.Span) {
		expr = fmt.Sprintf("floor(toFloat64OrNull(toString(%s)) / %s) * %s", resolveStr(c.Field, rel), c.Span, c.Span)
	} else {
		return nil, fmt.Errorf("span %q must be a time span like 1h or a number", c.Span)
	}
	except := ""
	if rel.explicit[c.As] {
		except = fmt.Sprintf(" EXCEPT (%s)", chIdent(c.As))
	} else {
		order = append(order, c.As)
	}
	explicit[c.As] = true
	nr := *rel
	nr.sql = fmt.Sprintf("SELECT *%s, %s AS %s FROM (%s)", except, expr, chIdent(c.As), rel.sql)
	nr.explicit = explicit
	nr.order = order
	return &nr, nil
}

func compileFillnull(rel *relation, c *cmdFillnull) (*relation, error) {
	if len(c.Fields) == 0 {
		return rel, nil // filling the dynamic map is a no-op for display
	}
	explicit, order := cloneCols(rel)
	var adds, excepts []string
	for _, f := range c.Fields {
		filled := fmt.Sprintf("if(toString(%s) = '', %s, toString(%s)) AS %s",
			resolveStr(f, rel), chStr(c.Value), resolveStr(f, rel), chIdent(f))
		adds = append(adds, filled)
		if rel.explicit[f] {
			excepts = append(excepts, chIdent(f))
		} else {
			order = append(order, f)
		}
		explicit[f] = true
	}
	except := ""
	if len(excepts) > 0 {
		except = fmt.Sprintf(" EXCEPT (%s)", strings.Join(excepts, ", "))
	}
	nr := *rel
	nr.sql = fmt.Sprintf("SELECT *%s, %s FROM (%s)", except, strings.Join(adds, ", "), rel.sql)
	nr.explicit = explicit
	nr.order = order
	return &nr, nil
}

func compileRex(rel *relation, c *cmdRex) (*relation, error) {
	names := namedGroups(c.Pattern)
	if len(names) == 0 {
		return nil, fmt.Errorf("rex pattern needs at least one named group, e.g. (?<status>[0-9]+)")
	}
	explicit, order := cloneCols(rel)
	var adds []string
	src := resolveStr(c.Field, rel)
	for i, name := range names {
		adds = append(adds, fmt.Sprintf(
			"arrayElement(extractGroups(toString(%s), %s), %d) AS %s",
			src, chStr(goToRE2(c.Pattern)), i+1, chIdent(name)))
		if !explicit[name] {
			order = append(order, name)
		}
		explicit[name] = true
	}
	nr := *rel
	nr.sql = fmt.Sprintf("SELECT *, %s FROM (%s)", strings.Join(adds, ", "), rel.sql)
	nr.explicit = explicit
	nr.order = order
	return &nr, nil
}

func compileSpath(rel *relation, c *cmdSpath) (*relation, error) {
	explicit, order := cloneCols(rel)
	path := strings.Split(c.Path, ".")
	var access strings.Builder
	access.WriteString(fmt.Sprintf("toString(%s)", resolveStr(c.Input, rel)))
	expr := access.String()
	for _, p := range path {
		expr = fmt.Sprintf("JSONExtractString(%s, %s)", expr, chStr(p))
	}
	except := ""
	if rel.explicit[c.Output] {
		except = fmt.Sprintf(" EXCEPT (%s)", chIdent(c.Output))
	} else {
		order = append(order, c.Output)
	}
	explicit[c.Output] = true
	nr := *rel
	nr.sql = fmt.Sprintf("SELECT *%s, %s AS %s FROM (%s)", except, expr, chIdent(c.Output), rel.sql)
	nr.explicit = explicit
	nr.order = order
	return &nr, nil
}

// namedGroups extracts (?<name>...) group names in order.
func namedGroups(pattern string) []string {
	var names []string
	for i := 0; i < len(pattern)-3; i++ {
		if pattern[i] == '(' && pattern[i+1] == '?' {
			j := i + 2
			open := byte(0)
			if pattern[j] == '<' {
				open = '>'
			} else if pattern[j] == 'P' && j+1 < len(pattern) && pattern[j+1] == '<' {
				j++
				open = '>'
			} else if pattern[j] == '\'' {
				open = '\''
			}
			if open != 0 {
				j++
				start := j
				for j < len(pattern) && pattern[j] != open {
					j++
				}
				if j < len(pattern) {
					names = append(names, pattern[start:j])
				}
			}
		}
	}
	return names
}

// goToRE2 rewrites (?<name>...) to RE2's (?P<name>...) that ClickHouse accepts.
func goToRE2(pattern string) string {
	return strings.ReplaceAll(pattern, "(?<", "(?P<")
}
