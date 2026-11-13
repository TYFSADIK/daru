// Package search ties the query compiler to the store and shapes results for
// the API: it runs a pipeline, pivots timechart output, and summarizes the
// fields that appear, the way a log search UI expects.
package search

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TYFSADIK/daru/internal/query"
	"github.com/TYFSADIK/daru/internal/store"
	"github.com/TYFSADIK/daru/internal/timeparse"
)

// Service runs searches against the store.
type Service struct {
	st      *store.Store
	MaxRows int
}

// New creates a search Service.
func New(st *store.Store) *Service {
	return &Service{st: st, MaxRows: 10000}
}

// Request is a search request.
type Request struct {
	Query    string
	Earliest string
	Latest   string
	Indexes  []string // indexes the caller may read
	MaxRows  int
	Now      time.Time
	// IndexesSpecified means the caller asked for indexes and Indexes is
	// the filtered result. When it is true and Indexes is empty, the
	// request asked only for unknown indexes and must return no rows,
	// never every index. Handlers must set this when the client supplied
	// an index list.
	IndexesSpecified bool
}

// FieldSummary counts how often a field appears, for the UI sidebar.
// The counts are from the returned rows only, so they are a sample, not
// totals over the whole index.
type FieldSummary struct {
	Name     string `json:"name"`
	Count    int    `json:"count"`
	Distinct int    `json:"distinct"`
	Sampled  bool   `json:"sampled"`
}

// Response is a shaped search result.
type Response struct {
	Kind        string           `json:"kind"`
	Columns     []string         `json:"columns"`
	Rows        []map[string]any `json:"rows"`
	Count       int              `json:"count"`
	Fields      []FieldSummary   `json:"fields"`
	TimeField   string           `json:"time_field,omitempty"`
	Series      []string         `json:"series,omitempty"`
	Elapsed     float64          `json:"elapsed"`
	ScannedRows int64            `json:"scanned_rows"`
	SQL         string           `json:"sql,omitempty"`
	// Sampled is true when Fields and, for timecharts, Count are derived
	// from the returned rows only rather than from a full aggregate.
	Sampled bool `json:"sampled,omitempty"`
}

// Run executes a search request.
func (s *Service) Run(ctx context.Context, req Request) (*Response, error) {
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	// No explicit earliest means the last 24 hours, not the whole
	// retention period. An explicit "all" or "0" still means unbounded.
	earliestStr := req.Earliest
	if earliestStr == "" {
		earliestStr = "-24h"
	}
	earliest, err := timeparse.Parse(earliestStr, now)
	if err != nil {
		return nil, fmt.Errorf("earliest time: %w", err)
	}
	latest, err := timeparse.Parse(req.Latest, now)
	if err != nil {
		return nil, fmt.Errorf("latest time: %w", err)
	}
	if latest.IsZero() {
		latest = now
	}

	p, err := query.Parse(req.Query)
	if err != nil {
		return nil, err
	}
	maxRows := req.MaxRows
	if maxRows <= 0 || maxRows > s.MaxRows {
		maxRows = s.MaxRows
	}
	compiled, err := query.Compile(p, query.Options{
		Indexes:   req.Indexes,
		Earliest:  earliest,
		Latest:    latest,
		MaxRows:   maxRows,
		Now:       now,
		NoIndexes: req.IndexesSpecified && len(req.Indexes) == 0,
	})
	if err != nil {
		return nil, err
	}
	// The caller asked only for unknown indexes: return an empty result
	// without touching ClickHouse.
	if req.IndexesSpecified && len(req.Indexes) == 0 {
		return &Response{
			Kind:    compiled.Kind,
			Columns: compiled.Columns,
			Rows:    []map[string]any{},
			Count:   0,
		}, nil
	}
	res, err := s.st.QueryReadOnly(ctx, compiled.SQL)
	if err != nil {
		return nil, err
	}

	resp := &Response{
		Kind:        compiled.Kind,
		TimeField:   compiled.TimeField,
		Elapsed:     res.Stats.Elapsed,
		ScannedRows: res.Stats.RowsRead,
	}

	rows := rowsToMaps(res)
	if compiled.Kind == "timechart" && hasColumn(res.Columns, "series") {
		resp.Sampled = true
		return pivotTimechart(resp, rows, maxRows, compiled.SeriesLimit), nil
	}

	resp.Rows = rows
	resp.Count = len(rows)
	if compiled.Transformed {
		resp.Columns = res.Columns
	} else {
		resp.Columns = eventColumns(rows)
		resp.Fields = summarizeFields(rows)
		resp.Sampled = true
	}
	return resp, nil
}

// Count returns the number of events matching a request without fetching
// rows. It compiles the same pipeline, strips the row limit, and wraps it
// in a count query, so alert conditions are judged on the true total, not
// on len(rows) capped at MaxRows. For transformed (reporting) queries it
// returns the number of output rows, which callers must not use as an
// event count; use AggregatedValue for those instead.
func (s *Service) Count(ctx context.Context, req Request) (int, error) {
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	earliestStr := req.Earliest
	if earliestStr == "" {
		earliestStr = "-24h"
	}
	earliest, err := timeparse.Parse(earliestStr, now)
	if err != nil {
		return 0, fmt.Errorf("earliest time: %w", err)
	}
	latest, err := timeparse.Parse(req.Latest, now)
	if err != nil {
		return 0, fmt.Errorf("latest time: %w", err)
	}
	if latest.IsZero() {
		latest = now
	}
	p, err := query.Parse(req.Query)
	if err != nil {
		return 0, err
	}
	compiled, err := query.Compile(p, query.Options{
		Indexes:   req.Indexes,
		Earliest:  earliest,
		Latest:    latest,
		MaxRows:   1,
		Now:       now,
		NoIndexes: req.IndexesSpecified && len(req.Indexes) == 0,
	})
	if err != nil {
		return 0, err
	}
	if req.IndexesSpecified && len(req.Indexes) == 0 {
		return 0, nil
	}
	if compiled.Transformed {
		return 0, fmt.Errorf("count query is not supported for reporting queries; use the aggregated value")
	}
	sql := stripLimitOrder(compiled.SQL)
	res, err := s.st.QueryReadOnly(ctx, "SELECT count() FROM ("+sql+")")
	if err != nil {
		return 0, err
	}
	if len(res.Rows) == 0 || len(res.Rows[0]) == 0 {
		return 0, nil
	}
	return int(toInt(res.Rows[0][0])), nil
}

// AggregatedValue extracts the first numeric value from a single row
// reporting result, for alert conditions over stats and timechart output.
// Columns are tried in sorted name order so the result is deterministic;
// use AggregatedTotal when the column order is known.
func AggregatedValue(rows []map[string]any) (float64, bool) {
	if len(rows) != 1 {
		return 0, false
	}
	keys := make([]string, 0, len(rows[0]))
	for k := range rows[0] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return AggregatedTotal(rows, keys, "")
}

// AggregatedTotal sums a reporting result into one number for alert
// conditions. It picks the measure column as a column named "count" when
// there is one, otherwise the first column, in result order, that is
// numeric in every row. Group-by columns (host, user, and so on) are
// strings, so they are never chosen. For a timechart (timeField set) every
// numeric series column is summed, since each one is a per-series count.
// It returns false when no numeric measure exists.
func AggregatedTotal(rows []map[string]any, columns []string, timeField string) (float64, bool) {
	if len(rows) == 0 {
		return 0, true
	}
	if len(columns) == 0 {
		return 0, false
	}
	numericEverywhere := func(col string) bool {
		for _, r := range rows {
			v, present := r[col]
			if !present || v == nil {
				continue // a missing cell in a sparse timechart is zero
			}
			if _, ok := strictFloat(v); !ok {
				return false
			}
		}
		// At least one row must actually carry a number.
		for _, r := range rows {
			if _, ok := strictFloat(r[col]); ok {
				return true
			}
		}
		return false
	}
	sumCol := func(col string) float64 {
		var total float64
		for _, r := range rows {
			if f, ok := strictFloat(r[col]); ok {
				total += f
			}
		}
		return total
	}
	if timeField != "" {
		var total float64
		found := false
		for _, c := range columns {
			if c == timeField || c == "_time" || c == "_span" {
				continue
			}
			if numericEverywhere(c) {
				total += sumCol(c)
				found = true
			}
		}
		return total, found
	}
	for _, c := range columns {
		if c == "count" && numericEverywhere(c) {
			return sumCol(c), true
		}
	}
	for _, c := range columns {
		if c == "_time" {
			continue
		}
		if numericEverywhere(c) {
			return sumCol(c), true
		}
	}
	return 0, false
}

func toInt(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i
		}
	case string:
		var i int64
		fmt.Sscan(n, &i)
		return i
	}
	return 0
}

// stripLimitOrder removes a trailing ORDER BY and LIMIT from compiled SQL
// so it can be wrapped in a count query.
func stripLimitOrder(sql string) string {
	sql = strings.TrimSpace(sql)
	if i := strings.LastIndex(sql, " LIMIT "); i >= 0 {
		sql = strings.TrimSpace(sql[:i])
	}
	if i := strings.LastIndex(sql, " ORDER BY "); i >= 0 {
		sql = strings.TrimSpace(sql[:i])
	}
	return sql
}

// rowsToMaps turns columnar rows into maps, merging the dynamic fields map.
func rowsToMaps(res *store.Result) []map[string]any {
	out := make([]map[string]any, 0, len(res.Rows))
	fieldsIdx := -1
	for i, c := range res.Columns {
		if c == "fields" {
			fieldsIdx = i
		}
	}
	for _, row := range res.Rows {
		m := map[string]any{}
		for i, col := range res.Columns {
			if i == fieldsIdx {
				continue
			}
			m[col] = row[i]
		}
		if fieldsIdx >= 0 {
			if fm, ok := row[fieldsIdx].(map[string]any); ok {
				for k, v := range fm {
					if _, exists := m[k]; !exists {
						m[k] = v
					}
				}
			}
		}
		out = append(out, m)
	}
	return out
}

func eventColumns(rows []map[string]any) []string {
	if len(rows) == 0 {
		return []string{"_time", "_raw"}
	}
	seen := map[string]bool{}
	for _, r := range rows {
		for k := range r {
			seen[k] = true
		}
	}
	var cols []string
	for _, first := range []string{"_time", "host", "source", "sourcetype"} {
		if seen[first] {
			cols = append(cols, first)
			delete(seen, first)
		}
	}
	var rest []string
	for k := range seen {
		if k != "_raw" {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	cols = append(cols, rest...)
	if seen["_raw"] {
		cols = append(cols, "_raw")
	}
	return cols
}

func summarizeFields(rows []map[string]any) []FieldSummary {
	counts := map[string]int{}
	distinct := map[string]map[string]struct{}{}
	skip := map[string]bool{"_raw": true, "_id": true, "_time": true}
	for _, r := range rows {
		for k, v := range r {
			if skip[k] {
				continue
			}
			counts[k]++
			if distinct[k] == nil {
				distinct[k] = map[string]struct{}{}
			}
			if len(distinct[k]) < 1000 {
				distinct[k][fmt.Sprintf("%v", v)] = struct{}{}
			}
		}
	}
	var out []FieldSummary
	for k, c := range counts {
		out = append(out, FieldSummary{Name: k, Count: c, Distinct: len(distinct[k]), Sampled: true})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

// pivotTimechart turns long (_time, series, value) rows into wide rows with one
// column per series, keeping the busiest series up to a sane limit.
func pivotTimechart(resp *Response, rows []map[string]any, maxRows int, seriesLimit int) *Response {
	seriesTotals := map[string]float64{}
	for _, r := range rows {
		s := fmt.Sprintf("%v", r["series"])
		seriesTotals[s] += toFloat(r["value"])
	}
	series := make([]string, 0, len(seriesTotals))
	for s := range seriesTotals {
		series = append(series, s)
	}
	sort.Slice(series, func(i, j int) bool {
		if seriesTotals[series[i]] != seriesTotals[series[j]] {
			return seriesTotals[series[i]] > seriesTotals[series[j]]
		}
		return series[i] < series[j]
	})
	maxSeries := 12
	if seriesLimit > 0 {
		maxSeries = seriesLimit
	}
	if len(series) > maxSeries {
		series = series[:maxSeries]
	}
	keep := map[string]bool{}
	for _, s := range series {
		keep[s] = true
	}

	byTime := map[string]map[string]any{}
	var order []string
	for _, r := range rows {
		t := fmt.Sprintf("%v", r["_time"])
		s := fmt.Sprintf("%v", r["series"])
		if !keep[s] {
			continue
		}
		bucket, ok := byTime[t]
		if !ok {
			bucket = map[string]any{"_time": r["_time"]}
			byTime[t] = bucket
			order = append(order, t)
		}
		bucket[s] = r["value"]
	}
	sort.Strings(order)
	out := make([]map[string]any, 0, len(order))
	for _, t := range order {
		b := byTime[t]
		for _, s := range series {
			if _, ok := b[s]; !ok {
				b[s] = float64(0)
			}
		}
		out = append(out, b)
	}
	resp.Columns = append([]string{"_time"}, series...)
	resp.Series = series
	resp.Rows = out
	// Count here is the number of time buckets, a sampled view of the
	// underlying events, not a total event count.
	resp.Count = len(out)
	resp.Sampled = true
	return resp
}

func hasColumn(cols []string, name string) bool {
	for _, c := range cols {
		if c == name {
			return true
		}
	}
	return false
}

func toFloat(v any) float64 {
	f, _ := toFloatOK(v)
	return f
}

// strictFloat converts a cell to a number only when the whole value is
// numeric. ClickHouse quotes 64 bit integers as JSON strings, so "42" is a
// number, but "10.0.0.1" or "42 apples" is not, unlike fmt.Sscan, which
// accepts a numeric prefix.
func strictFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		return f, err == nil && strings.TrimSpace(n) != ""
	}
	return 0, false
}

func toFloatOK(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case json.Number:
		if f, err := n.Float64(); err == nil {
			return f, true
		}
	case string:
		var f float64
		if _, err := fmt.Sscan(n, &f); err == nil {
			return f, true
		}
	}
	return 0, false
}
