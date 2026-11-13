package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// State that must be shared by every Daru server behind one load balancer
// lives here, in ClickHouse, which they all use already: SSO sign in state
// (the callback may reach a different server than the one that started the
// sign in), SAML assertion IDs already accepted (replay protection), and the
// scan counts behind per user quotas.
//
// ClickHouse has no transactions, so "take" and "consume" are a read
// followed by a write. Two servers racing on the very same state within
// milliseconds could both succeed; each state is also bound to one
// browser by an HttpOnly cookie, and each server keeps its own in-memory
// check in front, so this window is not reachable by a replayed request
// on a single server.

// SSOState is a pending OIDC or SAML sign in.
type SSOState struct {
	State     string
	Kind      string // "oidc" or "saml"
	Nonce     string // OIDC
	Verifier  string // OIDC PKCE code verifier
	RequestID string // SAML AuthnRequest ID
	ExpiresAt time.Time
}

// ErrNotFound is returned when a shared record does not exist or expired.
var ErrNotFound = errors.New("not found")

// ErrReplayed is returned when an ID was already consumed.
var ErrReplayed = errors.New("already used")

func chTime(t time.Time) string {
	return fmt.Sprintf("toDateTime64('%s', 3, 'UTC')", t.UTC().Format("2006-01-02 15:04:05.000"))
}

// PutSSOState stores a pending sign in.
func (s *Store) PutSSOState(ctx context.Context, st SSOState) error {
	return s.exec(ctx, fmt.Sprintf(
		"INSERT INTO sso_states (state, kind, nonce, verifier, request_id, expires_at) VALUES (%s, %s, %s, %s, %s, %s)",
		quote(st.State), quote(st.Kind), quote(st.Nonce), quote(st.Verifier), quote(st.RequestID), chTime(st.ExpiresAt)))
}

// TakeSSOState returns a pending sign in of the given kind and deletes it,
// so it is single use across every server.
func (s *Store) TakeSSOState(ctx context.Context, state, kind string) (*SSOState, error) {
	res, err := s.Query(ctx, fmt.Sprintf(
		"SELECT nonce, verifier, request_id, toString(expires_at) FROM sso_states WHERE state = %s AND kind = %s AND expires_at > now64(3) LIMIT 1",
		quote(state), quote(kind)))
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 || len(res.Rows[0]) < 4 {
		return nil, ErrNotFound
	}
	if err := s.exec(ctx, "DELETE FROM sso_states WHERE state = "+quote(state)); err != nil {
		return nil, err
	}
	r := res.Rows[0]
	exp, _ := time.Parse("2006-01-02 15:04:05.000", rowString(r, 3))
	return &SSOState{State: state, Kind: kind, Nonce: rowString(r, 0), Verifier: rowString(r, 1),
		RequestID: rowString(r, 2), ExpiresAt: exp}, nil
}

// ConsumeOnce records id as used until expiresAt and returns ErrReplayed
// when any server already recorded it.
func (s *Store) ConsumeOnce(ctx context.Context, id string, expiresAt time.Time) error {
	res, err := s.Query(ctx, "SELECT count() FROM used_ids WHERE id = "+quote(id))
	if err != nil {
		return err
	}
	if len(res.Rows) > 0 && rowInt(res.Rows[0], 0) > 0 {
		return ErrReplayed
	}
	return s.exec(ctx, fmt.Sprintf("INSERT INTO used_ids (id, expires_at) VALUES (%s, %s)", quote(id), chTime(expiresAt)))
}

// ScanUsage reports, for a user, scans still running (started in the last
// 30 minutes, so a crashed server cannot pin a slot forever) and scans
// started in the last hour, counting scheduled scans charged to them.
func (s *Store) ScanUsage(ctx context.Context, user string) (running, lastHour int, err error) {
	res, err := s.Query(ctx, fmt.Sprintf(`SELECT
		countIf(status = 'running' AND started_at > now64(3) - INTERVAL 30 MINUTE),
		countIf(started_at > now64(3) - INTERVAL 1 HOUR)
		FROM scans FINAL WHERE created_by IN (%s, %s) AND started_at > now64(3) - INTERVAL 1 HOUR`,
		quote(user), quote("scheduler:"+user)))
	if err != nil {
		return 0, 0, err
	}
	if len(res.Rows) == 0 || len(res.Rows[0]) < 2 {
		return 0, 0, nil
	}
	return int(rowInt(res.Rows[0], 0)), int(rowInt(res.Rows[0], 1)), nil
}
