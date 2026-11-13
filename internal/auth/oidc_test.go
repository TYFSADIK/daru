package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
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
)

// FakeIdP is a minimal OIDC provider for tests: discovery, JWKS, and a
// token endpoint that returns whatever ID token the test queues.
type fakeIdP struct {
	srv     *httptest.Server
	rsaKey  *rsa.PrivateKey
	ecKey   *ecdsa.PrivateKey
	nextTok string
	gotForm url.Values
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{rsaKey: rk, ecKey: ek}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		b64 := base64.RawURLEncoding.EncodeToString
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "RSA", "kid": "r1", "use": "sig", "n": b64(rk.N.Bytes()), "e": b64(big.NewInt(int64(rk.E)).Bytes())},
			{"kty": "EC", "kid": "e1", "crv": "P-256", "x": b64(pad32(ek.X.Bytes())), "y": b64(pad32(ek.Y.Bytes()))},
		}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.gotForm = r.PostForm
		id, secret, ok := r.BasicAuth()
		if !ok || id != "daru" || secret != "s3cret" {
			http.Error(w, "bad client", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": f.nextTok, "token_type": "Bearer"})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// sign builds a compact JWT. alg "none" and "HS256" produce tokens the
// verifier must refuse.
func (f *fakeIdP) sign(t *testing.T, alg, kid string, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	c, _ := json.Marshal(claims)
	signing := enc(h) + "." + enc(c)
	digest := sha256.Sum256([]byte(signing))
	var sig []byte
	switch alg {
	case "RS256":
		sig, _ = rsa.SignPKCS1v15(rand.Reader, f.rsaKey, crypto.SHA256, digest[:])
	case "ES256":
		r, s, _ := ecdsa.Sign(rand.Reader, f.ecKey, digest[:])
		sig = append(pad32(r.Bytes()), pad32(s.Bytes())...)
	case "HS256":
		m := hmac.New(sha256.New, []byte("guess"))
		m.Write([]byte(signing))
		sig = m.Sum(nil)
	}
	return signing + "." + enc(sig)
}

func (f *fakeIdP) claims(nonce string) map[string]any {
	now := time.Now().Unix()
	return map[string]any{"iss": f.srv.URL, "aud": "daru", "sub": "u-123", "email": "Alice@Example.com",
		"email_verified": true, "preferred_username": "alice", "iat": now, "exp": now + 300, "nonce": nonce}
}

func provider(t *testing.T, f *fakeIdP, cfg OIDCConfig) *OIDCProvider {
	t.Helper()
	cfg.Issuer, cfg.ClientID, cfg.ClientSecret = f.srv.URL, "daru", "s3cret"
	if cfg.RedirectURL == "" {
		cfg.RedirectURL = "https://daru.example.com/api/oidc/callback"
	}
	p, err := DiscoverOIDC(context.Background(), cfg)
	if err != nil {
		t.Fatalf("DiscoverOIDC: %v", err)
	}
	return p
}

func TestOIDCVerifyValidTokens(t *testing.T) {
	f := newFakeIdP(t)
	p := provider(t, f, OIDCConfig{})
	ctx := context.Background()
	for _, alg := range []struct{ alg, kid string }{{"RS256", "r1"}, {"ES256", "e1"}} {
		tok := f.sign(t, alg.alg, alg.kid, f.claims("n-1"))
		c, err := p.VerifyIDToken(ctx, tok, "n-1")
		if err != nil {
			t.Fatalf("%s token rejected: %v", alg.alg, err)
		}
		if c.Subject != "u-123" {
			t.Errorf("%s claims wrong: %+v", alg.alg, c)
		}
	}
}

func TestOIDCRejectsBadTokens(t *testing.T) {
	f := newFakeIdP(t)
	p := provider(t, f, OIDCConfig{})
	ctx := context.Background()
	mod := func(k string, v any) map[string]any {
		c := f.claims("n-1")
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		return c
	}
	now := time.Now().Unix()
	cases := map[string]string{
		"alg none":         f.sign(t, "none", "r1", f.claims("n-1")),
		"HS256":            f.sign(t, "HS256", "r1", f.claims("n-1")),
		"wrong issuer":     f.sign(t, "RS256", "r1", mod("iss", "https://evil.example")),
		"wrong audience":   f.sign(t, "RS256", "r1", mod("aud", "someone-else")),
		"multi aud no azp": f.sign(t, "RS256", "r1", mod("aud", []string{"daru", "other"})),
		"expired":          f.sign(t, "RS256", "r1", mod("exp", now-3600)),
		"future iat":       f.sign(t, "RS256", "r1", mod("iat", now+3600)),
		"no exp":           f.sign(t, "RS256", "r1", mod("exp", nil)),
		"wrong nonce":      f.sign(t, "RS256", "r1", mod("nonce", "other")),
		"no subject":       f.sign(t, "RS256", "r1", mod("sub", "")),
		"unknown kid":      f.sign(t, "RS256", "zz", f.claims("n-1")),
		"key confusion":    f.sign(t, "ES256", "r1", f.claims("n-1")),
	}
	// A valid signature over different claims.
	good := f.sign(t, "RS256", "r1", f.claims("n-1"))
	parts := strings.Split(good, ".")
	evil, _ := json.Marshal(mod("sub", "admin"))
	cases["tampered payload"] = parts[0] + "." + base64.RawURLEncoding.EncodeToString(evil) + "." + parts[2]
	cases["garbage"] = "not.a.jwt"
	for name, tok := range cases {
		if _, err := p.VerifyIDToken(ctx, tok, "n-1"); err == nil {
			t.Errorf("%s: token accepted, want rejection", name)
		}
	}
	// An empty expected nonce never matches, even an empty claim.
	if _, err := p.VerifyIDToken(ctx, f.sign(t, "RS256", "r1", mod("nonce", "")), ""); err == nil {
		t.Error("empty nonce accepted")
	}
}

func TestOIDCExchangeUsesPKCEAndClientAuth(t *testing.T) {
	f := newFakeIdP(t)
	p := provider(t, f, OIDCConfig{})
	f.nextTok = f.sign(t, "RS256", "r1", f.claims("n-9"))
	auth := p.AuthCodeURL("st", "n-9", "verifier-abc")
	u, _ := url.Parse(auth)
	if u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("code_challenge") == "" ||
		u.Query().Get("nonce") != "n-9" || u.Query().Get("state") != "st" {
		t.Errorf("auth url missing PKCE/state/nonce: %s", auth)
	}
	c, err := p.Exchange(context.Background(), "code-1", "verifier-abc", "n-9")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if f.gotForm.Get("code_verifier") != "verifier-abc" || f.gotForm.Get("code") != "code-1" {
		t.Errorf("token request form wrong: %v", f.gotForm)
	}
	if c.Email != "Alice@Example.com" {
		t.Errorf("claims wrong: %+v", c)
	}
}

func TestOIDCUsernameMapping(t *testing.T) {
	f := newFakeIdP(t)
	verified, unverified := true, false
	p := provider(t, f, OIDCConfig{AllowedDomains: []string{"example.com"}})
	if u, err := p.Username(&OIDCClaims{Subject: "x", Email: "Alice@Example.com", EmailVerified: &verified}); err != nil || u != "alice@example.com" {
		t.Errorf("email mapping = %q %v", u, err)
	}
	if _, err := p.Username(&OIDCClaims{Subject: "x", Email: "alice@example.com", EmailVerified: &unverified}); err == nil {
		t.Error("unverified email accepted")
	}
	if _, err := p.Username(&OIDCClaims{Subject: "x", Email: "eve@evil.com", EmailVerified: &verified}); err == nil {
		t.Error("disallowed domain accepted")
	}
	if _, err := p.Username(&OIDCClaims{Subject: "x", Email: "eve@notexample.com", EmailVerified: &verified}); err == nil {
		t.Error("suffix domain accepted")
	}
	pu := provider(t, f, OIDCConfig{UsernameClaim: "preferred_username"})
	if u, err := pu.Username(&OIDCClaims{Subject: "x", PreferredUsername: "bob"}); err != nil || u != "bob" {
		t.Errorf("preferred_username mapping = %q %v", u, err)
	}
	if _, err := pu.Username(&OIDCClaims{Subject: "x", PreferredUsername: "bob smith'--"}); err == nil {
		t.Error("invalid username accepted")
	}
}

func TestOIDCDiscoveryChecks(t *testing.T) {
	f := newFakeIdP(t)
	ctx := context.Background()
	if _, err := DiscoverOIDC(ctx, OIDCConfig{Issuer: f.srv.URL + "/other", ClientID: "daru", ClientSecret: "s", RedirectURL: "https://x/cb"}); err == nil {
		t.Error("issuer mismatch / missing discovery accepted")
	}
	if _, err := DiscoverOIDC(ctx, OIDCConfig{Issuer: f.srv.URL, ClientID: "daru", ClientSecret: "s", RedirectURL: "http://daru.example.com/cb"}); err == nil {
		t.Error("plain http redirect to a non-loopback host accepted")
	}
	if _, err := DiscoverOIDC(ctx, OIDCConfig{Issuer: f.srv.URL, ClientID: "daru", ClientSecret: "s", RedirectURL: "http://127.0.0.1:8088/api/oidc/callback"}); err != nil {
		t.Errorf("loopback http redirect rejected: %v", err)
	}
	if _, err := DiscoverOIDC(ctx, OIDCConfig{Issuer: f.srv.URL, ClientID: "daru", ClientSecret: "s", RedirectURL: "https://x/cb", UsernameClaim: "name"}); err == nil {
		t.Error("unsupported username claim accepted")
	}
}
