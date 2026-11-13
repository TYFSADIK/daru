package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TYFSADIK/daru/internal/store"
)

// Real ClickHouse sends UInt8 flags (disabled, revoked, totp_enabled) and,
// on 25.x, UInt64 counts as bare JSON numbers. The store keeps integers as
// json.Number. Every flag check must read them, or a revoked session, a
// disabled account, or TOTP would be silently ignored.
func TestToIntHandlesStoreNumbers(t *testing.T) {
	for _, c := range []struct {
		in   any
		want int64
	}{
		{json.Number("1"), 1}, {json.Number("42"), 42}, {"7", 7}, {float64(3), 3},
		{int64(5), 5}, {int(6), 6}, {json.Number("0"), 0}, {nil, 0},
	} {
		if got := toInt(c.in); got != c.want {
			t.Errorf("toInt(%#v) = %d, want %d", c.in, got, c.want)
		}
	}
}

// unquotedCH answers like ClickHouse 25.8: flags and counts as bare numbers.
func unquotedCH(t *testing.T, answer func(sql string) string) *Manager {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprint(w, answer(string(b)))
	}))
	t.Cleanup(srv.Close)
	return New(store.New(store.Config{URL: srv.URL, Database: "daru"}))
}

func compactRows(cols int, rows string) string {
	meta := strings.TrimSuffix(strings.Repeat(`{"name":"c","type":"String"},`, cols), ",")
	return `{"meta":[` + meta + `],"data":` + rows + `,"rows":1,"statistics":{"elapsed":0,"rows_read":0,"bytes_read":0}}`
}

func TestRevokedSessionAndDisabledUserWithBareNumbers(t *testing.T) {
	exp := time.Now().UTC().Add(time.Hour).Format("2006-01-02 15:04:05.000")
	revoked, disabled := 1, 0
	m := unquotedCH(t, func(sql string) string {
		switch {
		case strings.Contains(sql, "FROM sessions"):
			return compactRows(4, fmt.Sprintf(`[["alice","user","%s",%d]]`, exp, revoked))
		case strings.Contains(sql, "FROM users"):
			return compactRows(7, fmt.Sprintf(`[["id","alice","user","",%d,"*","local"]]`, disabled))
		}
		return compactRows(1, `[]`)
	})
	ctx := context.Background()
	if _, err := m.Validate(ctx, "tok"); err == nil {
		t.Error("a revoked session (revoked = bare 1) was accepted")
	}
	revoked, disabled = 0, 1
	if _, err := m.Validate(ctx, "tok"); err == nil {
		t.Error("a session of a disabled account (disabled = bare 1) was accepted")
	}
	revoked, disabled = 0, 0
	if _, err := m.Validate(ctx, "tok"); err != nil {
		t.Errorf("a valid session was refused: %v", err)
	}
}

func TestCountUsersAndTOTPWithBareNumbers(t *testing.T) {
	m := unquotedCH(t, func(sql string) string {
		switch {
		case strings.Contains(sql, "SELECT count()"):
			return compactRows(1, `[[1]]`)
		case strings.Contains(sql, "password_hash"):
			return compactRows(10, `[["id","alice","user","",0,"hash","SECRET",1,"*","local"]]`)
		}
		return compactRows(1, `[]`)
	})
	ctx := context.Background()
	if n, err := m.CountUsers(ctx); err != nil || n != 1 {
		t.Errorf("CountUsers = %d %v, want 1 (a bare count must not read as 0)", n, err)
	}
	if on, _, err := m.TOTPStatus(ctx, "alice"); err != nil || !on {
		t.Errorf("TOTPStatus = %v %v, want enabled (totp_enabled = bare 1)", on, err)
	}
}
