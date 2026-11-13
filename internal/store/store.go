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
//
// It holds two credential sets. The app user (User/Password) runs every
// read and write the product makes at runtime and needs only SELECT,
// INSERT, ALTER DELETE, and ALTER UPDATE (row level; lightweight DELETE
// needs both) on the Daru database. The admin user
// (AdminUser/AdminPassword) runs schema changes: CREATE DATABASE, CREATE
// TABLE, ALTER ADD COLUMN, and ALTER DROP PARTITION for retention. When no
// admin user is configured the app user does both, which is the old single
// user behaviour. User written searches additionally run with readonly=2,
// so the query language can never write or change schema even if a
// compiler bug let SQL through.
type Store struct {
	base          string
	db            string
	user          string
	password      string
	adminUser     string
	adminPassword string
	client        *http.Client
}

// Config configures a Store.
type Config struct {
	URL      string // e.g. http://localhost:8123
	Database string
	User     string // least privilege app user
	Password string
	// AdminUser runs DDL (migrations, partition drops). Empty means User.
	AdminUser     string
	AdminPassword string
	Timeout       time.Duration
}

// credential selects which ClickHouse user a statement runs as.
type credential int

const (
	credApp      credential = iota // runtime reads and writes
	credAdmin                      // schema changes and partition drops
	credReadOnly                   // user written searches: app user, readonly=2
)

// New creates a Store.
func New(cfg Config) *Store {
	if cfg.Database == "" {
		cfg.Database = "daru"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.AdminUser == "" {
		cfg.AdminUser = cfg.User
		cfg.AdminPassword = cfg.Password
	}
	return &Store{
		base:          strings.TrimRight(cfg.URL, "/"),
		db:            cfg.Database,
		user:          cfg.User,
		password:      cfg.Password,
		adminUser:     cfg.AdminUser,
		adminPassword: cfg.AdminPassword,
		client:        &http.Client{Timeout: cfg.Timeout},
	}
}

// SplitPrivileges reports whether DDL runs as a separate admin user.
func (s *Store) SplitPrivileges() bool { return s.adminUser != s.user }

// ddl runs a schema statement as the admin user.
func (s *Store) ddl(ctx context.Context, sql, database string) error {
	_, err := s.doAs(ctx, sql, database, credAdmin)
	return err
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
	return s.doAs(ctx, sql, database, credApp)
}

func (s *Store) doAs(ctx context.Context, sql, database string, cred credential) ([]byte, error) {
	q := url.Values{}
	if database != "" {
		q.Set("database", database)
	}
	if cred == credReadOnly {
		// readonly=2: reads only, but per query limits below may still be
		// set. A query cannot lower this, since readonly itself is locked.
		q.Set("readonly", "2")
	}
	// Bound every query so a bad search cannot scan forever or read an
	// unbounded number of rows.
	q.Set("max_execution_time", "30")
	q.Set("max_rows_to_read", "10000000")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/?"+q.Encode(), strings.NewReader(sql))
	if err != nil {
		return nil, err
	}
	user, password := s.user, s.password
	if cred == credAdmin {
		user, password = s.adminUser, s.adminPassword
	}
	if user != "" {
		req.Header.Set("X-ClickHouse-User", user)
		req.Header.Set("X-ClickHouse-Key", password)
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
	return s.query(ctx, sql, credApp)
}

// QueryReadOnly runs a query compiled from user input with readonly=2, so
// ClickHouse itself refuses any write, DDL, or settings escalation.
func (s *Store) QueryReadOnly(ctx context.Context, sql string) (*Result, error) {
	return s.query(ctx, sql, credReadOnly)
}

func (s *Store) query(ctx context.Context, sql string, cred credential) (*Result, error) {
	wrapped := sql + "\nFORMAT JSONCompact"
	body, err := s.doAs(ctx, wrapped, s.db, cred)
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

// decodeCell converts a JSON cell into a Go value. Integers stay as
// json.Number so values above 2^53 do not lose precision; only
// non-integer numbers become float64.
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
		if strings.ContainsAny(n.String(), ".eE") {
			if f, err := n.Float64(); err == nil {
				return f
			}
			return n.String()
		}
		return n
	}
	return v
}

// Ping checks connectivity.
func (s *Store) Ping(ctx context.Context) error {
	_, err := s.do(ctx, "SELECT 1", "")
	return err
}
