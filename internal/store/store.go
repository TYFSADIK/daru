// Package store talks to ClickHouse over its HTTP interface, so Basalt needs
// no database driver and one binary is enough to run the whole product.
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Store is a ClickHouse client over HTTP.
type Store struct {
	base     string
	db       string
	user     string
	password string
	client   *http.Client
}

// Config configures a Store.
type Config struct {
	URL      string // e.g. http://localhost:8123
	Database string
	User     string
	Password string
	Timeout  time.Duration
}

// New creates a Store.
func New(cfg Config) *Store {
	if cfg.Database == "" {
		cfg.Database = "basalt"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	return &Store{
		base:     strings.TrimRight(cfg.URL, "/"),
		db:       cfg.Database,
		user:     cfg.User,
		password: cfg.Password,
		client:   &http.Client{Timeout: cfg.Timeout},
	}
}

// exec runs a statement that returns no rows.
func (s *Store) exec(ctx context.Context, sql string) error {
	_, err := s.do(ctx, sql, s.db)
	return err
}

// Exec runs a statement that returns no rows.
func (s *Store) Exec(ctx context.Context, sql string) error {
	return s.exec(ctx, sql)
}

func (s *Store) do(ctx context.Context, sql, database string) ([]byte, error) {
	q := url.Values{}
	if database != "" {
		q.Set("database", database)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/?"+q.Encode(), strings.NewReader(sql))
	if err != nil {
		return nil, err
	}
	if s.user != "" {
		req.Header.Set("X-ClickHouse-User", s.user)
		req.Header.Set("X-ClickHouse-Key", s.password)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clickhouse request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, &QueryError{Status: resp.StatusCode, Message: strings.TrimSpace(string(body))}
	}
	return body, nil
}

// QueryError is a ClickHouse error response.
type QueryError struct {
	Status  int
	Message string
}

func (e *QueryError) Error() string {
	msg := e.Message
	// Surface the human part of ClickHouse's error, not the stack.
	if i := strings.Index(msg, "(version"); i > 0 {
		msg = strings.TrimSpace(msg[:i])
	}
	if len(msg) > 400 {
		msg = msg[:400]
	}
	return msg
}

// Result holds query output.
type Result struct {
	Columns []string
	Types   []string
	Rows    [][]any
	Stats   QueryStats
}

// QueryStats summarizes execution.
type QueryStats struct {
	RowsRead  int64   `json:"rows_read"`
	BytesRead int64   `json:"bytes_read"`
	Elapsed   float64 `json:"elapsed"`
}

// chResponse is ClickHouse's JSONCompact envelope.
type chResponse struct {
	Meta []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"meta"`
	Data       [][]json.RawMessage `json:"data"`
	Rows       int64               `json:"rows"`
	Statistics struct {
		Elapsed   float64 `json:"elapsed"`
		RowsRead  int64   `json:"rows_read"`
		BytesRead int64   `json:"bytes_read"`
	} `json:"statistics"`
}

// Query runs a read query and decodes the JSONCompact response.
func (s *Store) Query(ctx context.Context, sql string) (*Result, error) {
	wrapped := sql + "\nFORMAT JSONCompact"
	body, err := s.do(ctx, wrapped, s.db)
	if err != nil {
		return nil, err
	}
	var raw chResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode clickhouse response: %w", err)
	}
	res := &Result{
		Stats: QueryStats{
			RowsRead:  raw.Statistics.RowsRead,
			BytesRead: raw.Statistics.BytesRead,
			Elapsed:   raw.Statistics.Elapsed,
		},
	}
	for _, m := range raw.Meta {
		res.Columns = append(res.Columns, m.Name)
		res.Types = append(res.Types, m.Type)
	}
	for _, row := range raw.Data {
		out := make([]any, len(row))
		for i, cell := range row {
			out[i] = decodeCell(cell)
		}
		res.Rows = append(res.Rows, out)
	}
	return res, nil
}

// decodeCell converts a JSON cell into a Go value, keeping numbers as float64
// and leaving everything else as its JSON-native type.
func decodeCell(raw json.RawMessage) any {
	s := strings.TrimSpace(string(raw))
	if s == "null" {
		return nil
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return string(raw)
	}
	if n, ok := v.(json.Number); ok {
		if f, err := n.Float64(); err == nil {
			return f
		}
		return n.String()
	}
	return v
}

// Ping checks connectivity.
func (s *Store) Ping(ctx context.Context) error {
	_, err := s.do(ctx, "SELECT 1", "")
	return err
}
