package api

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TYFSADIK/daru/internal/auth"
)

// miniIdP issues RS256 ID tokens; the nonce it signs is whatever the last
// authorization request carried, as a real provider would.
type miniIdP struct {
	srv   *httptest.Server
	key   *rsa.PrivateKey
	nonce string
	email string
}

func newMiniIdP(t *testing.T) *miniIdP {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &miniIdP{key: k, email: "alice@example.com"}
	mux := http.NewServeMux()
	enc := base64.RawURLEncoding.EncodeToString
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": m.srv.URL, "authorization_endpoint": m.srv.URL + "/authorize",
			"token_endpoint": m.srv.URL + "/token", "jwks_uri": m.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "RSA", "kid": "k1", "n": enc(k.N.Bytes()), "e": enc(big.NewInt(int64(k.E)).Bytes())}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().Unix()
		h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1"})
		c, _ := json.Marshal(map[string]any{"iss": m.srv.URL, "aud": "daru", "sub": "s1", "email": m.email,
			"email_verified": true, "iat": now, "exp": now + 300, "nonce": m.nonce})
		signing := enc(h) + "." + enc(c)
		d := sha256.Sum256([]byte(signing))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
		json.NewEncoder(w).Encode(map[string]string{"id_token": signing + "." + enc(sig)})
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func oidcServer(t *testing.T, f *fakeCH, idp *miniIdP, autoCreate bool) http.Handler {
	t.Helper()
	p, err := auth.DiscoverOIDC(context.Background(), auth.OIDCConfig{Issuer: idp.srv.URL, ClientID: "daru",
		ClientSecret: "s3cret", RedirectURL: "http://127.0.0.1:8088/api/oidc/callback"})
	if err != nil {
		t.Fatal(err)
	}
	return newTestServer(t, f, func(s *Server) {
		s.OIDC = OIDCSettings{Provider: p, AutoCreate: autoCreate}
	})
}

// startLogin runs GET /api/oidc/login and returns the state cookie and the
// state from the redirect, recording the nonce at the IdP.
func startLogin(t *testing.T, h http.Handler, idp *miniIdP) (*http.Cookie, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/oidc/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login start = %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if !strings.HasPrefix(loc.String(), idp.srv.URL+"/authorize") {
		t.Fatalf("login redirect went to %s", loc)
	}
	idp.nonce = loc.Query().Get("nonce")
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == oidcStateCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly {
		t.Fatal("state cookie missing or not HttpOnly")
	}
	return cookie, loc.Query().Get("state")
}

func callback(h http.Handler, state string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/api/oidc/callback?code=c1&state="+url.QueryEscape(state), nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func sessionSet(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return true
		}
	}
	return false
}

func TestOIDCLoginExistingUser(t *testing.T) {
	f := newFakeCH()
	f.addUserSource("alice@example.com", auth.RoleUser, "main", "unused", auth.SourceOIDC)
	idp := newMiniIdP(t)
	h := oidcServer(t, f, idp, false)

	rec := doJSON(h, "GET", "/api/oidc/config", "", nil)
	if !strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Errorf("config = %s", rec.Body)
	}
	cookie, state := startLogin(t, h, idp)
	rec = callback(h, state, cookie)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/#/search" || !sessionSet(rec) {
		t.Fatalf("callback = %d %s session=%v", rec.Code, rec.Header().Get("Location"), sessionSet(rec))
	}
	// The state is single use.
	rec = callback(h, state, cookie)
	if rec.Header().Get("Location") != "/?sso=failed" || sessionSet(rec) {
		t.Error("replayed state was accepted")
	}
}

func TestOIDCLoginRefusals(t *testing.T) {
	f := newFakeCH()
	idp := newMiniIdP(t)
	h := oidcServer(t, f, idp, false)

	// Unknown user with auto create off.
	cookie, state := startLogin(t, h, idp)
	if rec := callback(h, state, cookie); rec.Header().Get("Location") != "/?sso=failed" || sessionSet(rec) {
		t.Error("unknown user signed in with auto create off")
	}
	// An IdP identity must not take over a local account of the same name,
	// even with auto create on.
	f.addUser("alice@example.com", auth.RoleAdmin, "*", "unused")
	hAuto := oidcServer(t, f, idp, true)
	cookie, state = startLogin(t, hAuto, idp)
	if rec := callback(hAuto, state, cookie); rec.Header().Get("Location") != "/?sso=failed" || sessionSet(rec) {
		t.Error("OIDC identity signed in to a local admin account")
	}
	// Callback in a browser without the state cookie (login CSRF).
	f.addUserSource("alice@example.com", auth.RoleUser, "*", "unused", auth.SourceOIDC)
	_, state = startLogin(t, h, idp)
	if rec := callback(h, state, nil); rec.Header().Get("Location") != "/?sso=failed" || sessionSet(rec) {
		t.Error("callback without the state cookie was accepted")
	}
	// Provider error.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/oidc/callback?error=access_denied", nil))
	if rec.Header().Get("Location") != "/?sso=failed" {
		t.Error("provider error not handled")
	}
}

func TestOIDCAutoCreateLeastPrivilege(t *testing.T) {
	f := newFakeCH()
	idp := newMiniIdP(t)
	idp.email = "newbie@example.com"
	h := oidcServer(t, f, idp, true)
	cookie, state := startLogin(t, h, idp)
	// The fake store does not persist inserts, so the post-create lookup
	// is not exercised; check the created row instead.
	callback(h, state, cookie)
	f.mu.Lock()
	defer f.mu.Unlock()
	var created string
	for _, q := range f.queries {
		if strings.HasPrefix(q, "INSERT INTO users") {
			created = q
		}
	}
	if !strings.Contains(created, "'newbie@example.com'") || !strings.Contains(created, "'user'") ||
		!strings.Contains(created, "'', 'oidc', now64(3)") {
		t.Errorf("auto created account should be role user with no index access: %s", created)
	}
}

func TestOIDCDisabledByDefault(t *testing.T) {
	h := newTestServer(t, newFakeCH(), nil)
	if rec := doJSON(h, "GET", "/api/oidc/config", "", nil); !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Errorf("config = %s", rec.Body)
	}
	if rec := doJSON(h, "GET", "/api/oidc/login", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("login with SSO off = %d", rec.Code)
	}
}
