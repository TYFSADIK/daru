// Package search ties the query compiler to the store and shapes results for
// the API: it runs a pipeline, pivots timechart output, and summarizes the
// fields that appear, the way a log search UI expects.
package search

import (
	"context"
	"fmt"
	"sort"
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
}

// FieldSummary counts how often a field appears, for the UI sidebar.
type FieldSummary struct {
	Name     string `json:"name"`
	Count    int    `json:"count"`
	Distinct int    `json:"distinct"`
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
}

// Run executes a search request.
func (s *Service) Run(ctx context.Context, req Request) (*Response, error) {
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	earliest, err := timeparse.Parse(req.Earliest, now)
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
		Indexes:  req.Indexes,
		Earliest: earliest,
		Latest:   latest,
		MaxRows:  maxRows,
		Now:      now,
	})
	if err != nil {
		return nil, err
	}
	res, err := s.st.Query(ctx, compiled.SQL)
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
		return pivotTimechart(resp, rows, maxRows), nil
	}

	resp.Rows = rows
	resp.Count = len(rows)
	if compiled.Transformed {
		resp.Columns = res.Columns
	} else {
		resp.Columns = eventColumns(rows)
		resp.Fields = summarizeFields(rows)
	}
	return resp, nil
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
	cols := []string{"_time", "_raw"}
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
		out = append(out, FieldSummary{Name: k, Count: c, Distinct: len(distinct[k])})
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
func pivotTimechart(resp *Response, rows []map[string]any, maxRows int) *Response {
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
	const maxSeries = 12
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
	resp.Count = len(out)
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
	switch n := v.(type) {
	case float64:
		return n
	case string:
		var f float64
		fmt.Sscan(n, &f)
		return f
	}
	return 0
}
