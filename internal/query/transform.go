package query

import (
	"fmt"
	"strings"

	"github.com/TYFSADIK/daru/internal/timeparse"
)

func compileEval(rel *relation, c *cmdEval) (*relation, error) {
	cur := rel
	for _, a := range c.Assign {
		if a.Name == "_time" || a.Name == "_id" || a.Name == "_raw" {
			return nil, fmt.Errorf("eval cannot assign to reserved field %q", a.Name)
		}
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

// windowAggExpr builds a windowed aggregate for eventstats and
// streamstats. ClickHouse requires OVER on a bare aggregate, with any
// scalar wrapper applied outside, so count becomes
// toFloat64(count() OVER (...)) and range becomes
// (max() OVER (...) - min() OVER (...)), never toFloat64(count()) OVER ().
func windowAggExpr(a agg, rel *relation, over string) (string, error) {
	raw := func() string { return resolveStr(a.Arg, rel) }
	num := func() string { return "toFloat64OrNull(toString(" + resolveStr(a.Arg, rel) + "))" }
	tm := resolveRaw("_time", rel)
	w := func(bare string) string { return bare + " OVER " + over }
	switch a.Fn {
	case "count":
		if a.Arg == "" {
			return "toFloat64(" + w("count()") + ")", nil
		}
		return "toFloat64(" + w(fmt.Sprintf("countIf(toString(%s) != '')", raw())) + ")", nil
	case "dc", "estdc":
		return "toFloat64(" + w(fmt.Sprintf("uniqExact(toString(%s))", raw())) + ")", nil
	case "sum":
		return w(fmt.Sprintf("sum(%s)", num())), nil
	case "sumsq":
		return w(fmt.Sprintf("sum(pow(%s, 2))", num())), nil
	case "avg":
		return w(fmt.Sprintf("avg(%s)", num())), nil
	case "min":
		return w(fmt.Sprintf("min(%s)", num())), nil
	case "max":
		return w(fmt.Sprintf("max(%s)", num())), nil
	case "range":
		return fmt.Sprintf("(%s - %s)", w(fmt.Sprintf("max(%s)", num())), w(fmt.Sprintf("min(%s)", num()))), nil
	case "median":
		return w(fmt.Sprintf("quantileExact(0.5)(%s)", num())), nil
	case "stdev":
		return w(fmt.Sprintf("stddevSamp(%s)", num())), nil
	case "stdevp":
		return w(fmt.Sprintf("stddevPop(%s)", num())), nil
	case "var":
		return w(fmt.Sprintf("varSamp(%s)", num())), nil
	case "varp":
		return w(fmt.Sprintf("varPop(%s)", num())), nil
	case "mode":
		return fmt.Sprintf("arrayElement(%s, 1)", w(fmt.Sprintf("topK(1)(toString(%s))", raw()))), nil
	case "values":
		return fmt.Sprintf("arrayStringConcat(arraySort(%s), '\n')", w(fmt.Sprintf("groupUniqArray(toString(%s))", raw()))), nil
	case "list":
		return fmt.Sprintf("arrayStringConcat(%s, '\n')", w(fmt.Sprintf("groupArray(toString(%s))", raw()))), nil
	case "earliest":
		return w(fmt.Sprintf("argMin(toString(%s), %s)", raw(), tm)), nil
	case "latest", "last":
		return w(fmt.Sprintf("argMax(toString(%s), %s)", raw(), tm)), nil
	case "first":
		return w(fmt.Sprintf("any(toString(%s))", raw())), nil
	}
	if a.Pct > 0 {
		return w(fmt.Sprintf("quantileExact(%g)(%s)", a.Pct/100, num())), nil
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
		// Group by the raw value, not the display string: grouping by the
		// formatted _time string collapses events in the same second and
		// loses millisecond precision.
		sel = append(sel, fmt.Sprintf("%s AS %s", resolveRaw(by, rel), chIdent(by)))
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
				p = append(p, resolveRaw(by, rel))
			}
			part = "PARTITION BY " + strings.Join(p, ", ")
		}
		for _, a := range c.Aggs {
			expr, err := windowAggExpr(a, rel, "("+part+")")
			if err != nil {
				return nil, err
			}
			win = append(win, fmt.Sprintf("%s AS %s", expr, chIdent(a.As)))
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
			g = append(g, resolveRaw(by, rel))
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
			p = append(p, resolveRaw(by, rel))
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
		over := fmt.Sprintf("(%sORDER BY %s %s)", part, resolveRaw("_time", rel), frame)
		expr, err := windowAggExpr(a, rel, over)
		if err != nil {
			return nil, err
		}
		win = append(win, fmt.Sprintf("%s AS %s", expr, chIdent(a.As)))
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
		if c.Limit > 0 {
			sql += fmt.Sprintf(" LIMIT %d", c.Limit)
		}
		return &relation{
			sql: sql, explicit: explicit, order: order,
			transform: true, ordered: true, kind: "timechart", timeField: "_time",
			seriesLimit: c.Limit,
		}, nil
	}

	// Split by a series field: emit long format (_time, series, value); the
	// API pivots into columns and limits to the top series.
	series := resolveStr(c.By, rel)
	sql := fmt.Sprintf(
		"SELECT %s AS _time, toString(%s) AS series, %s AS value FROM (%s) GROUP BY _time, series ORDER BY _time ASC",
		bucket, series, expr, rel.sql,
	)
	if c.Limit > 0 {
		sql = topSeriesSQL(sql, c.Limit)
	}
	return &relation{
		sql:       sql,
		explicit:  map[string]bool{"_time": true, "series": true, "value": true},
		order:     []string{"_time", "series", "value"},
		transform: true, ordered: true, kind: "timechart", timeField: "_time",
		seriesLimit: c.Limit,
	}, nil
}

// topSeriesSQL keeps only the top N series by total value from a long
// format (_time, series, value) query.
func topSeriesSQL(inner string, limit int) string {
	return fmt.Sprintf("SELECT * FROM (%s) WHERE series IN (SELECT series FROM (%s) GROUP BY series ORDER BY sum(value) DESC LIMIT %d)",
		inner, inner, limit)
}

func compileChart(rel *relation, c *cmdChart) (*relation, error) {
	if c.Over == "" {
		return nil, fmt.Errorf("chart needs an over or by field")
	}
	a := c.Aggs[0]
	expr, err := aggExpr(a, rel)
	if err != nil {
		return nil, err
	}
	if c.By == "" {
		var sel = []string{fmt.Sprintf("toString(%s) AS %s", resolveRaw(c.Over, rel), chIdent(c.Over))}
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
		orderBy := chIdent(c.Over) + " ASC"
		if c.Limit > 0 {
			orderBy = chIdent(a.As) + " DESC"
		}
		sql := fmt.Sprintf("SELECT %s FROM (%s) GROUP BY %s ORDER BY %s",
			strings.Join(sel, ", "), rel.sql, chIdent(c.Over), orderBy)
		if c.Limit > 0 {
			sql += fmt.Sprintf(" LIMIT %d", c.Limit)
		}
		return &relation{sql: sql, explicit: explicit, order: order, transform: true, ordered: true, kind: "chart", seriesLimit: c.Limit}, nil
	}
	sql := fmt.Sprintf(
		"SELECT toString(%s) AS %s, toString(%s) AS series, %s AS value FROM (%s) GROUP BY %s, series ORDER BY %s ASC",
		resolveRaw(c.Over, rel), chIdent(c.Over), resolveRaw(c.By, rel), expr, rel.sql,
		chIdent(c.Over), chIdent(c.Over),
	)
	if c.Limit > 0 {
		sql = topSeriesSQL(sql, c.Limit)
	}
	return &relation{
		sql:       sql,
		explicit:  map[string]bool{c.Over: true, "series": true, "value": true},
		order:     []string{c.Over, "series", "value"},
		transform: true, ordered: true, kind: "chart",
		seriesLimit: c.Limit,
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
	dropped := map[string]bool{}
	for k, v := range rel.dropped {
		dropped[k] = v
	}
	for _, f := range c.Fields {
		dropped[f] = true
	}
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
	nr.dropped = dropped
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
	// The last N rows in time order: number newest first, keep the first
	// N, and let the outer query sort newest first as usual.
	orderBy := ""
	if rel.explicit["_time"] {
		orderBy = "ORDER BY _time DESC"
	}
	sql := fmt.Sprintf(
		"SELECT * EXCEPT (__rn) FROM (SELECT *, row_number() OVER (%s) AS __rn FROM (%s)) WHERE __rn <= %d",
		orderBy, rel.sql, n,
	)
	nr := *rel
	nr.sql = sql
	nr.ordered = false
	return &nr, nil
}

// compileHead returns the first N rows in newest first order, so head
// picks the newest events instead of arbitrary rows from the scan.
func compileHead(rel *relation, n int) (*relation, error) {
	inner := rel.sql
	if rel.explicit["_time"] && !rel.ordered {
		inner = rel.sql + " ORDER BY _time DESC"
	}
	sql := fmt.Sprintf("SELECT * FROM (%s LIMIT %d)", inner, n)
	nr := *rel
	nr.sql = sql
	nr.ordered = true
	return &nr, nil
}

func compileRename(rel *relation, c *cmdRename) (*relation, error) {
	explicit, order := cloneCols(rel)
	var adds, excepts []string
	exceptSeen := map[string]bool{}
	addExcept := func(name string) {
		if name != "" && !exceptSeen[name] {
			exceptSeen[name] = true
			excepts = append(excepts, chIdent(name))
		}
	}
	for i, from := range c.From {
		to := c.To[i]
		adds = append(adds, fmt.Sprintf("%s AS %s", resolveStr(from, rel), chIdent(to)))
		if rel.explicit[from] {
			addExcept(from)
			delete(explicit, from)
			for j, o := range order {
				if o == from {
					order[j] = to
				}
			}
		} else {
			order = append(order, to)
		}
		// Renaming onto a column that already exists must drop the old
		// target first, or SELECT * keeps both and the result is a
		// duplicate column.
		if to != from && rel.explicit[to] {
			addExcept(to)
		}
		explicit[to] = true
	}
	// Deduplicate the display order, keeping the first occurrence.
	seen := map[string]bool{}
	uniq := order[:0]
	for _, o := range order {
		if !seen[o] {
			seen[o] = true
			uniq = append(uniq, o)
		}
	}
	order = uniq
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
		part = append(part, resolveRaw(f, rel))
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
		sel = append(sel, fmt.Sprintf("toString(%s) AS %s", resolveRaw(f, rel), chIdent(f)))
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
		if c.Field == "_time" {
			return nil, fmt.Errorf("bin _time needs a time span like 1h, not a number")
		}
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
	groups, err := groupIndices(c.Pattern)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("rex pattern needs at least one named group, e.g. (?<status>[0-9]+)")
	}
	explicit, order := cloneCols(rel)
	var adds []string
	src := resolveStr(c.Field, rel)
	for _, g := range groups {
		if err := checkName(g.Name); err != nil {
			return nil, err
		}
		adds = append(adds, fmt.Sprintf(
			"arrayElement(extractGroups(toString(%s), %s), %d) AS %s",
			src, chStr(goToRE2(c.Pattern)), g.Index, chIdent(g.Name)))
		if !explicit[g.Name] {
			order = append(order, g.Name)
		}
		explicit[g.Name] = true
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

// namedGroup is one named capture group with its true 1 based index
// among all groups in the pattern, named or not. ClickHouse
// extractGroups returns every group in order, so a named group after an
// unnamed one must use its true index, not its position among named groups.
type namedGroup struct {
	Name  string
	Index int
}

// namedGroups extracts (?<name>...) group names in order.
func namedGroups(pattern string) []string {
	groups, err := groupIndices(pattern)
	if err != nil {
		return nil
	}
	var names []string
	for _, g := range groups {
		names = append(names, g.Name)
	}
	return names
}

// groupIndices returns every named group with its true index, counting
// unnamed groups, non capturing groups, and lookarounds, while skipping
// escaped parentheses and parentheses inside character classes.
func groupIndices(pattern string) ([]namedGroup, error) {
	var out []namedGroup
	count := 0
	inClass := false
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c == '\\' {
			i++
			continue
		}
		if inClass {
			if c == ']' {
				inClass = false
			}
			continue
		}
		if c == '[' {
			inClass = true
			continue
		}
		if c != '(' {
			continue
		}
		count++
		idx := count
		if i+1 < len(pattern) && pattern[i+1] == '?' {
			j := i + 2
			if j < len(pattern) && pattern[j] == '<' {
				j++
				start := j
				for j < len(pattern) && pattern[j] != '>' {
					j++
				}
				if j >= len(pattern) {
					return nil, fmt.Errorf("rex pattern has an unterminated named group")
				}
				out = append(out, namedGroup{Name: pattern[start:j], Index: idx})
				i = j
				continue
			}
			if j+1 < len(pattern) && pattern[j] == 'P' && pattern[j+1] == '<' {
				j += 2
				start := j
				for j < len(pattern) && pattern[j] != '>' {
					j++
				}
				if j >= len(pattern) {
					return nil, fmt.Errorf("rex pattern has an unterminated named group")
				}
				out = append(out, namedGroup{Name: pattern[start:j], Index: idx})
				i = j
				continue
			}
			if j < len(pattern) && pattern[j] == '\'' {
				j++
				start := j
				for j < len(pattern) && pattern[j] != '\'' {
					j++
				}
				if j >= len(pattern) {
					return nil, fmt.Errorf("rex pattern has an unterminated named group")
				}
				out = append(out, namedGroup{Name: pattern[start:j], Index: idx})
				i = j
				continue
			}
		}
	}
	return out, nil
}

// goToRE2 rewrites (?<name>...) to RE2's (?P<name>...) that ClickHouse accepts.
func goToRE2(pattern string) string {
	return strings.ReplaceAll(pattern, "(?<", "(?P<")
}
