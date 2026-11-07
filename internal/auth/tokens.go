package auth

import (
	"context"
	"fmt"
	"time"
)

// IngestToken authenticates a log forwarder or HEC sender.
type IngestToken struct {
	Name         string    `json:"name"`
	DefaultIndex string    `json:"default_index"`
	Disabled     bool      `json:"disabled"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
}

// CreateIngestToken returns a new token string (shown once) and stores its hash.
func (m *Manager) CreateIngestToken(ctx context.Context, name, defaultIndex, createdBy string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("token name is required")
	}
	if defaultIndex == "" {
		defaultIndex = "main"
	}
	token, hash := NewToken("daru_hec")
	sql := fmt.Sprintf(
		"INSERT INTO ingest_tokens (token_hash, name, default_index, created_by, updated_at) VALUES (%s, %s, %s, %s, now64(3))",
		q(hash), q(name), q(defaultIndex), q(createdBy))
	if err := m.st.Exec(ctx, sql); err != nil {
		return "", err
	}
	return token, nil
}

// ValidateIngestToken resolves a token to its default index.
func (m *Manager) ValidateIngestToken(ctx context.Context, token string) (*IngestToken, error) {
	res, err := m.st.Query(ctx, fmt.Sprintf(
		"SELECT name, default_index, disabled, created_by FROM ingest_tokens FINAL WHERE token_hash = %s LIMIT 1",
		q(hashToken(token))))
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, fmt.Errorf("invalid ingest token")
	}
	row := res.Rows[0]
	if toInt(row[2]) != 0 {
		return nil, fmt.Errorf("ingest token disabled")
	}
	return &IngestToken{
		Name:         str(row[0]),
		DefaultIndex: str(row[1]),
		CreatedBy:    str(row[3]),
	}, nil
}

// ListIngestTokens returns tokens without their secret values.
func (m *Manager) ListIngestTokens(ctx context.Context) ([]IngestToken, error) {
	res, err := m.st.Query(ctx,
		"SELECT name, default_index, disabled, created_by, toString(created_at) FROM ingest_tokens FINAL ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	var out []IngestToken
	for _, row := range res.Rows {
		out = append(out, IngestToken{
			Name:         str(row[0]),
			DefaultIndex: str(row[1]),
			Disabled:     toInt(row[2]) != 0,
			CreatedBy:    str(row[3]),
		})
	}
	return out, nil
}

// DisableIngestToken turns a token off by name.
func (m *Manager) DisableIngestToken(ctx context.Context, name string) error {
	res, err := m.st.Query(ctx, fmt.Sprintf(
		"SELECT token_hash, default_index, created_by FROM ingest_tokens FINAL WHERE name = %s", q(name)))
	if err != nil {
		return err
	}
	for _, row := range res.Rows {
		if err := m.st.Exec(ctx, fmt.Sprintf(
			"INSERT INTO ingest_tokens (token_hash, name, default_index, disabled, created_by, updated_at) VALUES (%s, %s, %s, 1, %s, now64(3))",
			q(str(row[0])), q(name), q(str(row[1])), q(str(row[2])))); err != nil {
			return err
		}
	}
	return nil
}
