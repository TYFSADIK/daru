package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TYFSADIK/daru/internal/auth"
	"github.com/TYFSADIK/daru/internal/ingest"
	"github.com/TYFSADIK/daru/internal/search"
	"github.com/TYFSADIK/daru/internal/store"
)

// fakeCH is a minimal ClickHouse HTTP endpoint for API tests. It knows a
// few users (by bearer token), a few indexes, and records every other
// statement so tests can inspect the SQL a search compiled to.
type fakeCH struct {
	mu      sync.Mutex
	users   map[string]fakeUser // username -> user
	tokens  map[string]string   // sha256(token) -> username
	indexes []string
	down    bool
	queries []string
	inserts int
	// Shared state tables, as ClickHouse would hold them for every server.
	sso       map[string][]string // state -> kind, nonce, verifier, request_id
	used      map[string]bool
	scanUsage [2]int // running, last hour
}

var quotedVals = regexp.MustCompile(`'((?:[^'\\]|\\.)*)'`)

func allQuoted(sql string) []string {
	var out []string
	for _, m := range quotedVals.FindAllStringSubmatch(sql, -1) {
		out = append(out, m[1])
	}
	return out
}

type fakeUser struct {
	role, access, source string
}

func newFakeCH() *fakeCH {
	return &fakeCH{users: map[string]fakeUser{}, tokens: map[string]string{}, indexes: []string{"main", "web", "secret"},
		sso: map[string][]string{}, used: map[string]bool{}}
}

func (f *fakeCH) addUser(name, role, access, token string) {
	f.addUserSource(name, role, access, token, "local")
}

func (f *fakeCH) addUserSource(name, role, access, token, source string) {
	sum := sha256.Sum256([]byte(token))
	f.users[name] = fakeUser{role: role, access: access, source: source}
	f.tokens[hex.EncodeToString(sum[:])] = name
}

func compact(cols []string, rows [][]any) string {
	meta := make([]map[string]string, len(cols))
	for i, c := range cols {
		meta[i] = map[string]string{"name": c, "type": "String"}
	}
	if rows == nil {
		rows = [][]any{}
	}
	b, _ := json.Marshal(map[string]any{"meta": meta, "data": rows, "rows": len(rows),
		"statistics": map[string]any{"elapsed": 0, "rows_read": 0, "bytes_read": 0}})
	return string(b)
}

func quotedArg(sql, after string) string {
	i := strings.Index(sql, after)
	if i < 0 {
		return ""
	}
	rest := sql[i+len(after):]
	rest = strings.TrimPrefix(strings.TrimSpace(rest), "'")
	if j := strings.Index(rest, "'"); j >= 0 {
		return rest[:j]
	}
	return ""
}

func (f *fakeCH) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	sql := string(b)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		http.Error(w, "Code: 210. connection refused", http.StatusServiceUnavailable)
		return
	}
	switch {
	case strings.HasPrefix(sql, "INSERT INTO sso_states"):
		v := allQuoted(sql) // state, kind, nonce, verifier, request_id, time
		f.sso[v[0]] = v[1:5]
	case strings.HasPrefix(sql, "DELETE FROM sso_states"):
		delete(f.sso, allQuoted(sql)[0])
	case strings.Contains(sql, "FROM sso_states"):
		v := allQuoted(sql) // state, kind
		row, ok := f.sso[v[0]]
		if !ok || row[0] != v[1] {
			fmt.Fprint(w, compact([]string{"nonce"}, nil))
			return
		}
		fmt.Fprint(w, compact([]string{"nonce", "verifier", "request_id", "expires"},
			[][]any{{row[1], row[2], row[3], "2099-01-01 00:00:00.000"}}))
	case strings.Contains(sql, "FROM used_ids"):
		n := "0"
		if f.used[allQuoted(sql)[0]] {
			n = "1"
		}
		fmt.Fprint(w, compact([]string{"count()"}, [][]any{{n}}))
	case strings.HasPrefix(sql, "INSERT INTO used_ids"):
		f.used[allQuoted(sql)[0]] = true
	case strings.Contains(sql, "countIf(status = 'running'"):
		fmt.Fprint(w, compact([]string{"running", "hour"}, [][]any{{fmt.Sprint(f.scanUsage[0]), fmt.Sprint(f.scanUsage[1])}}))
	case strings.Contains(sql, "FROM sessions"):
		name, ok := f.tokens[quotedArg(sql, "token_hash =")]
		if !ok {
			fmt.Fprint(w, compact([]string{"username", "role", "expires", "revoked"}, nil))
			return
		}
		exp := time.Now().UTC().Add(time.Hour).Format("2006-01-02 15:04:05.000")
		fmt.Fprint(w, compact([]string{"username", "role", "expires", "revoked"},
			[][]any{{name, f.users[name].role, exp, "0"}}))
	case strings.Contains(sql, "FROM users"):
		name := quotedArg(sql, "username =")
		u, ok := f.users[name]
		if !ok {
			fmt.Fprint(w, compact([]string{"id"}, nil))
			return
		}
		if strings.Contains(sql, "password_hash") { // getFull
			fmt.Fprint(w, compact([]string{"id", "username", "role", "email", "disabled", "password_hash", "totp_secret", "totp_enabled", "index_access", "auth_source"},
				[][]any{{"00000000-0000-0000-0000-000000000001", name, u.role, "", "0", "x", "", "0", u.access, u.source}}))
			return
		}
		fmt.Fprint(w, compact([]string{"id", "username", "role", "email", "disabled", "index_access", "auth_source"},
			[][]any{{"00000000-0000-0000-0000-000000000001", name, u.role, "", "0", u.access, u.source}}))
	case strings.Contains(sql, "FROM (SELECT DISTINCT name"):
		var rows [][]any
		for _, ix := range f.indexes {
			rows = append(rows, []any{ix, "90", "0", "0", "", ""})
		}
		fmt.Fprint(w, compact([]string{"name", "retention_days", "events", "bytes", "oldest", "newest"}, rows))
	case strings.HasPrefix(strings.TrimSpace(sql), "INSERT INTO events"):
		f.inserts++
		fmt.Fprint(w, "")
	default:
		f.queries = append(f.queries, sql+" ?"+r.URL.RawQuery)
		fmt.Fprint(w, compact([]string{"_time", "_raw"}, nil))
	}
}

func newTestServer(t *testing.T, f *fakeCH, tweak func(*Server)) http.Handler {
	t.Helper()
	ch := httptest.NewServer(f)
	t.Cleanup(ch.Close)
	st := store.New(store.Config{URL: ch.URL, Database: "daru"})
	s := &Server{
		Store:  st,
		Auth:   auth.New(st),
		Ingest: ingest.New(st),
		Search: search.New(st),
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if tweak != nil {
		tweak(s)
	}
	return s.Handler()
}

func doJSON(h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.RemoteAddr = "127.0.0.1:5555"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func (f *fakeCH) lastSearch(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.queries) - 1; i >= 0; i-- {
		if strings.Contains(f.queries[i], "FROM `events`") {
			return f.queries[i]
		}
	}
	t.Fatal("no search reached ClickHouse")
	return ""
}

func TestSearchEnforcesIndexACL(t *testing.T) {
	f := newFakeCH()
	f.addUser("alice", auth.RoleUser, "main", "tok-alice")
	f.addUser("bob", auth.RoleUser, "", "tok-bob")
	f.addUser("root", auth.RoleAdmin, "", "tok-root")
	h := newTestServer(t, f, nil)

	// Alice may read only main, with or without an explicit index list.
	rec := doJSON(h, "POST", "/api/search", "tok-alice", map[string]any{"query": "error"})
	if rec.Code != 200 {
		t.Fatalf("alice search: %d %s", rec.Code, rec.Body)
	}
	sql := f.lastSearch(t)
	if !strings.Contains(sql, "index IN ('main')") || strings.Contains(sql, "'secret'") {
		t.Errorf("alice search not restricted to main: %s", sql)
	}
	if !strings.Contains(sql, "readonly=2") {
		t.Errorf("search should run with readonly=2: %s", sql)
	}
	// Asking for secret explicitly yields nothing and never queries it.
	before := len(f.queries)
	rec = doJSON(h, "POST", "/api/search", "tok-alice", map[string]any{"query": "error", "indexes": []string{"secret"}})
	if rec.Code != 200 {
		t.Fatalf("alice secret search: %d %s", rec.Code, rec.Body)
	}
	if len(f.queries) != before {
		t.Errorf("a search for a forbidden index reached ClickHouse: %v", f.queries[before:])
	}
	// Bob has no index at all: empty result, never an unfiltered query.
	before = len(f.queries)
	rec = doJSON(h, "POST", "/api/search", "tok-bob", map[string]any{"query": "*"})
	if rec.Code != 200 {
		t.Fatalf("bob search: %d %s", rec.Code, rec.Body)
	}
	if len(f.queries) != before {
		t.Errorf("a user with no index access reached ClickHouse: %v", f.queries[before:])
	}
	// Admin reads everything regardless of the stored value.
	doJSON(h, "POST", "/api/search", "tok-root", map[string]any{"query": "*"})
	sql = f.lastSearch(t)
	for _, ix := range []string{"'main'", "'web'", "'secret'"} {
		if !strings.Contains(sql, ix) {
			t.Errorf("admin search missing %s: %s", ix, sql)
		}
	}

	// The index list is filtered the same way.
	rec = doJSON(h, "GET", "/api/indexes", "tok-alice", nil)
	var got struct {
		Indexes []struct{ Name string } `json:"indexes"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if len(got.Indexes) != 1 || got.Indexes[0].Name != "main" {
		t.Errorf("alice index list = %+v, want only main", got.Indexes)
	}
}

func TestSetIndexAccessValidates(t *testing.T) {
	f := newFakeCH()
	f.addUser("root", auth.RoleAdmin, "*", "tok-root")
	f.addUser("alice", auth.RoleUser, "*", "tok-alice")
	h := newTestServer(t, f, nil)
	rec := doJSON(h, "POST", "/api/admin/users/alice/indexes", "tok-root", map[string]any{"indexes": []string{"nope"}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown index should be rejected, got %d %s", rec.Code, rec.Body)
	}
	rec = doJSON(h, "POST", "/api/admin/users/alice/indexes", "tok-root", map[string]any{"indexes": []string{"main", "web", "main"}})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"main,web"`) {
		t.Errorf("set index access = %d %s, want main,web", rec.Code, rec.Body)
	}
	// Non-admins cannot change ACLs.
	rec = doJSON(h, "POST", "/api/admin/users/alice/indexes", "tok-alice", map[string]any{"all": true})
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin ACL change = %d, want 403", rec.Code)
	}
}

func TestIndexAccessParsing(t *testing.T) {
	if all, _ := auth.ParseIndexAccess(auth.RoleAdmin, ""); !all {
		t.Error("admin should read every index")
	}
	if all, set := auth.ParseIndexAccess(auth.RoleUser, ""); all || len(set) != 0 {
		t.Error("empty access should mean no index")
	}
	if all, _ := auth.ParseIndexAccess(auth.RolePower, "*"); !all {
		t.Error("* should mean every index")
	}
	if _, err := auth.FormatIndexAccess(false, []string{"bad name"}); err == nil {
		t.Error("invalid index name should be rejected")
	}
}

func TestReadyAndMetrics(t *testing.T) {
	f := newFakeCH()
	h := newTestServer(t, f, func(s *Server) {})
	if rec := doJSON(h, "GET", "/ready", "", nil); rec.Code != 200 {
		t.Errorf("/ready with ClickHouse up = %d", rec.Code)
	}
	rec := doJSON(h, "GET", "/metrics", "", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "daru_ready 1") ||
		!strings.Contains(rec.Body.String(), `daru_http_requests_total{route="probe",code="2xx"}`) {
		t.Errorf("/metrics from loopback = %d\n%s", rec.Code, rec.Body)
	}
	// Non-loopback without a token is refused.
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.RemoteAddr = "192.0.2.10:4000"
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	if out.Code != http.StatusForbidden {
		t.Errorf("/metrics from the network without a token = %d, want 403", out.Code)
	}
	f.mu.Lock()
	f.down = true
	f.mu.Unlock()
	if rec := doJSON(h, "GET", "/ready", "", nil); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/ready with ClickHouse down = %d, want 503", rec.Code)
	}
	// /api/health stays a pure liveness probe.
	if rec := doJSON(h, "GET", "/api/health", "", nil); rec.Code != 200 {
		t.Errorf("/api/health with ClickHouse down = %d, want 200", rec.Code)
	}
}

func TestMetricsToken(t *testing.T) {
	f := newFakeCH()
	h := newTestServer(t, f, func(s *Server) { s.MetricsToken = "0123456789abcdef-metrics" })
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.RemoteAddr = "192.0.2.10:4000"
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	if out.Code != http.StatusUnauthorized {
		t.Errorf("/metrics without token = %d, want 401", out.Code)
	}
	req.Header.Set("Authorization", "Bearer 0123456789abcdef-metrics")
	out = httptest.NewRecorder()
	h.ServeHTTP(out, req)
	if out.Code != 200 {
		t.Errorf("/metrics with token = %d, want 200", out.Code)
	}
}

func TestIngestLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newIngestLimiter(1000) // capacity max(2000, 100000) = 100000
	l.now = func() time.Time { return now }
	l.last = now
	l.tokens = 2000
	if ok, _ := l.take(1500); !ok {
		t.Fatal("first batch should pass")
	}
	ok, wait := l.take(1000)
	if ok || wait <= 0 {
		t.Fatalf("second batch should be limited, ok=%v wait=%v", ok, wait)
	}
	now = now.Add(time.Second) // refills 1000
	if ok, _ := l.take(1000); !ok {
		t.Error("batch should pass after refill")
	}
	if newIngestLimiter(-1) != nil || newIngestLimiter(0) != nil {
		t.Error("non-positive rate should disable the limiter")
	}
	var nilL *ingestLimiter
	if ok, _ := nilL.take(1 << 30); !ok {
		t.Error("nil limiter should admit everything")
	}
}

func TestAdmitIngestRefusesWhenDrained(t *testing.T) {
	s := &Server{IngestMaxEPS: 1}
	s.initLimits()
	s.ingestLimit.tokens = 0
	rec := httptest.NewRecorder()
	if s.admitIngest(rec, 10, true) {
		t.Fatal("ingest should be refused with an empty bucket")
	}
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" ||
		!strings.Contains(rec.Body.String(), `"code":9`) {
		t.Errorf("rate limited HEC response = %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
}

func TestUserQuotas(t *testing.T) {
	now := time.Unix(5000, 0)
	q := newUserQuotas(2, 3, 1)
	q.now = func() time.Time { return now }
	r1, err := q.acquireScan("alice")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := q.acquireScan("scheduler:alice") // charged to alice
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.acquireScan("alice"); err == nil {
		t.Error("third concurrent scan should hit the concurrency quota")
	}
	if _, err := q.acquireScan("bob"); err != nil {
		t.Errorf("bob has his own quota: %v", err)
	}
	r1()
	r1() // double release is harmless
	r3, err := q.acquireScan("alice")
	if err != nil {
		t.Fatalf("slot should free after release: %v", err)
	}
	r2()
	r3()
	if _, err := q.acquireScan("alice"); err == nil {
		t.Error("fourth scan in an hour should hit the hourly quota")
	}
	now = now.Add(61 * time.Minute)
	if _, err := q.acquireScan("alice"); err != nil {
		t.Errorf("hourly quota should reset: %v", err)
	}
	if err := q.checkSchedules("alice", 0); err != nil {
		t.Error(err)
	}
	if err := q.checkSchedules("alice", 1); err == nil {
		t.Error("second schedule should hit the schedule quota")
	}
	var nilQ *userQuotas
	if rel, err := nilQ.acquireScan("x"); err != nil || rel == nil {
		t.Error("nil quotas should admit everything")
	}
}

func TestLimitOr(t *testing.T) {
	if limitOr(0, 7) != 7 || limitOr(-1, 7) != 0 || limitOr(3, 7) != 3 {
		t.Error("limitOr wrong")
	}
}

// A password change re-writes the whole user row. It must carry the index
// ACL, or a restricted user would silently widen to every index.
func TestPasswordChangeKeepsIndexAccess(t *testing.T) {
	f := newFakeCH()
	f.addUser("alice", auth.RoleUser, "main", "tok-alice")
	ch := httptest.NewServer(f)
	defer ch.Close()
	am := auth.New(store.New(store.Config{URL: ch.URL, Database: "daru"}))
	if err := am.SetPassword(context.Background(), "alice", "a-new-long-password-123"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	found := false
	for _, q := range f.queries {
		if strings.HasPrefix(q, "INSERT INTO users") {
			found = true
			if !strings.Contains(q, "index_access") || !strings.Contains(q, "'main', 'local', now64(3)") {
				t.Errorf("user row rewrite dropped index_access: %s", q)
			}
		}
	}
	if !found {
		t.Fatal("SetPassword did not write the user row")
	}
}

// Two Daru servers sharing one ClickHouse: a sign in started on one
// finishes on the other, and is still single use.
func TestSSOStateSharedAcrossServers(t *testing.T) {
	f := newFakeCH()
	ch := httptest.NewServer(f)
	defer ch.Close()
	a := store.New(store.Config{URL: ch.URL, Database: "daru"})
	b := store.New(store.Config{URL: ch.URL, Database: "daru"})
	ctx := context.Background()
	if err := a.PutSSOState(ctx, store.SSOState{State: "st1", Kind: "oidc", Nonce: "n1", Verifier: "v1",
		ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	got, err := b.TakeSSOState(ctx, "st1", "oidc")
	if err != nil || got.Nonce != "n1" || got.Verifier != "v1" {
		t.Fatalf("server b could not take server a's state: %+v %v", got, err)
	}
	if _, err := a.TakeSSOState(ctx, "st1", "oidc"); err == nil {
		t.Error("state was usable twice")
	}
	if err := a.PutSSOState(ctx, store.SSOState{State: "st2", Kind: "saml", RequestID: "id-1",
		ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.TakeSSOState(ctx, "st2", "oidc"); err == nil {
		t.Error("a saml state was accepted as oidc")
	}
	// Replay records are shared too.
	if err := a.ConsumeOnce(ctx, "saml:abc", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := b.ConsumeOnce(ctx, "saml:abc", time.Now().Add(time.Hour)); err != store.ErrReplayed {
		t.Errorf("server b accepted an assertion server a already used: %v", err)
	}
}

// Scan quotas count scans every server recorded.
func TestSharedScanQuota(t *testing.T) {
	f := newFakeCH()
	ch := httptest.NewServer(f)
	defer ch.Close()
	s := &Server{Store: store.New(store.Config{URL: ch.URL, Database: "daru"}),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), ScanConcurrentPerUser: 2, ScanPerHourPerUser: 5}
	s.initLimits()
	f.scanUsage = [2]int{1, 1}
	if err := s.sharedScanQuota("alice"); err != nil {
		t.Errorf("under quota refused: %v", err)
	}
	f.scanUsage = [2]int{2, 2} // two running on other servers
	if err := s.sharedScanQuota("scheduler:alice"); err == nil {
		t.Error("running scans on other servers were not counted")
	}
	f.scanUsage = [2]int{0, 5}
	if err := s.sharedScanQuota("alice"); err == nil {
		t.Error("hourly scans on other servers were not counted")
	}
	f.down = true
	if err := s.sharedScanQuota("alice"); err == nil {
		t.Error("quota must fail closed when usage cannot be read")
	}
}

func TestReplicasSplitIngestLimit(t *testing.T) {
	s := &Server{IngestMaxEPS: 30000, Replicas: 3}
	s.initLimits()
	if s.ingestLimit.rate != 10000 {
		t.Errorf("per server rate = %v, want 10000", s.ingestLimit.rate)
	}
}
