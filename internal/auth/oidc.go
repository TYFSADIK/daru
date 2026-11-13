package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OIDC single sign on, standard library only. Daru is a relying party for
// the authorization code flow with PKCE. ID tokens are verified locally
// against the provider's JWKS: signature (RS256 or ES256 only; "none" and
// HMAC algorithms are refused), issuer, audience, authorized party, expiry,
// issued at, and nonce.
//
// SAML and LDAP are not implemented natively. Identity providers such as
// Keycloak, Authentik, Microsoft Entra ID, and Okta federate SAML and LDAP
// directories and expose them to Daru over OIDC.

// OIDCConfig configures an OIDC provider.
type OIDCConfig struct {
	Issuer       string // e.g. https://accounts.google.com
	ClientID     string
	ClientSecret string
	RedirectURL  string // https://daru.example.com/api/oidc/callback
	// UsernameClaim names the claim mapped to a Daru username:
	// "email" (default) or "preferred_username", or "sub".
	UsernameClaim string
	// AllowedDomains, when set, restricts sign in to these email domains.
	AllowedDomains []string
	HTTPClient     *http.Client
}

// OIDCProvider is a discovered OIDC provider.
type OIDCProvider struct {
	cfg       OIDCConfig
	client    *http.Client
	authURL   string
	tokenURL  string
	jwksURL   string
	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	keysFetch time.Time
	now       func() time.Time
}

// OIDCClaims are the verified ID token claims Daru uses.
type OIDCClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     *bool  `json:"email_verified"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
}

// DiscoverOIDC fetches the provider's discovery document and checks that
// its issuer matches the configured one exactly, as OIDC Discovery 1.0
// requires.
func DiscoverOIDC(ctx context.Context, cfg OIDCConfig) (*OIDCProvider, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURL == "" {
		return nil, fmt.Errorf("oidc: issuer, client id, client secret, and redirect url are required")
	}
	ru, err := url.Parse(cfg.RedirectURL)
	if err != nil || (ru.Scheme != "https" && !(ru.Scheme == "http" && isLoopbackHost(ru.Hostname()))) {
		return nil, fmt.Errorf("oidc: redirect url must be https (http is allowed only for localhost)")
	}
	switch cfg.UsernameClaim {
	case "":
		cfg.UsernameClaim = "email"
	case "email", "preferred_username", "sub":
	default:
		return nil, fmt.Errorf("oidc: username claim must be email, preferred_username, or sub")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	issuer := strings.TrimRight(cfg.Issuer, "/")
	var doc struct {
		Issuer        string `json:"issuer"`
		AuthEndpoint  string `json:"authorization_endpoint"`
		TokenEndpoint string `json:"token_endpoint"`
		JWKSURI       string `json:"jwks_uri"`
	}
	if err := getJSON(ctx, client, issuer+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	if strings.TrimRight(doc.Issuer, "/") != issuer {
		return nil, fmt.Errorf("oidc discovery: issuer %q does not match configured %q", doc.Issuer, cfg.Issuer)
	}
	if doc.AuthEndpoint == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return nil, fmt.Errorf("oidc discovery: document is missing endpoints")
	}
	p := &OIDCProvider{
		cfg: cfg, client: client, authURL: doc.AuthEndpoint, tokenURL: doc.TokenEndpoint,
		jwksURL: doc.JWKSURI, now: time.Now,
	}
	p.cfg.Issuer = doc.Issuer
	return p, nil
}

// UsernameClaim reports which claim maps to a Daru username.
func (p *OIDCProvider) UsernameClaim() string { return p.cfg.UsernameClaim }

// AuthCodeURL builds the authorization request. state and nonce must be
// unguessable and bound to the browser; verifier is the PKCE code verifier.
func (p *OIDCProvider) AuthCodeURL(state, nonce, verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURL)
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	sep := "?"
	if strings.Contains(p.authURL, "?") {
		sep = "&"
	}
	return p.authURL + sep + q.Encode()
}

// Exchange redeems an authorization code and returns the verified claims of
// the ID token it carries.
func (p *OIDCProvider) Exchange(ctx context.Context, code, verifier, nonce string) (*OIDCClaims, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.cfg.RedirectURL)
	form.Set("code_verifier", verifier)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc token endpoint returned %d", resp.StatusCode)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.IDToken == "" {
		return nil, fmt.Errorf("oidc token response has no id_token")
	}
	return p.VerifyIDToken(ctx, tok.IDToken, nonce)
}

// VerifyIDToken checks an ID token's signature and claims.
func (p *OIDCProvider) VerifyIDToken(ctx context.Context, raw, nonce string) (*OIDCClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("oidc: malformed id token")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return nil, errors.New("oidc: malformed id token header")
	}
	if hdr.Alg != "RS256" && hdr.Alg != "ES256" {
		return nil, fmt.Errorf("oidc: unsupported id token algorithm %q", hdr.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("oidc: malformed id token signature")
	}
	key, err := p.key(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch hdr.Alg {
	case "RS256":
		k, ok := key.(*rsa.PublicKey)
		if !ok || rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) != nil {
			return nil, errors.New("oidc: id token signature invalid")
		}
	case "ES256":
		k, ok := key.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return nil, errors.New("oidc: id token signature invalid")
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(k, digest[:], r, s) {
			return nil, errors.New("oidc: id token signature invalid")
		}
	}

	var c struct {
		OIDCClaims
		Issuer   string          `json:"iss"`
		Audience json.RawMessage `json:"aud"`
		AZP      string          `json:"azp"`
		Expiry   json.Number     `json:"exp"`
		IssuedAt json.Number     `json:"iat"`
		Nonce    string          `json:"nonce"`
	}
	if err := decodeSegment(parts[1], &c); err != nil {
		return nil, errors.New("oidc: malformed id token claims")
	}
	if c.Issuer != p.cfg.Issuer {
		return nil, errors.New("oidc: id token issuer mismatch")
	}
	auds, err := audiences(c.Audience)
	if err != nil || !contains(auds, p.cfg.ClientID) {
		return nil, errors.New("oidc: id token audience mismatch")
	}
	if len(auds) > 1 && c.AZP != p.cfg.ClientID {
		return nil, errors.New("oidc: id token authorized party mismatch")
	}
	now := p.now()
	const skew = 2 * time.Minute
	exp, err1 := c.Expiry.Int64()
	iat, err2 := c.IssuedAt.Int64()
	if err1 != nil || err2 != nil {
		return nil, errors.New("oidc: id token missing exp or iat")
	}
	if now.After(time.Unix(exp, 0).Add(skew)) {
		return nil, errors.New("oidc: id token expired")
	}
	if time.Unix(iat, 0).After(now.Add(skew)) || now.Sub(time.Unix(iat, 0)) > 24*time.Hour {
		return nil, errors.New("oidc: id token issued at an implausible time")
	}
	if nonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1 {
		return nil, errors.New("oidc: id token nonce mismatch")
	}
	if c.Subject == "" {
		return nil, errors.New("oidc: id token has no subject")
	}
	claims := c.OIDCClaims
	return &claims, nil
}

// Username maps verified claims to a Daru username, enforcing the email
// domain allowlist and requiring a verified email whenever email is used.
func (p *OIDCProvider) Username(c *OIDCClaims) (string, error) {
	emailOK := c.Email != "" && (c.EmailVerified == nil || *c.EmailVerified)
	if len(p.cfg.AllowedDomains) > 0 {
		if !emailOK {
			return "", errors.New("a verified email is required to sign in")
		}
		at := strings.LastIndexByte(c.Email, '@')
		domain := strings.ToLower(c.Email[at+1:])
		allowed := false
		for _, d := range p.cfg.AllowedDomains {
			if strings.EqualFold(strings.TrimSpace(d), domain) {
				allowed = true
			}
		}
		if at < 0 || !allowed {
			return "", errors.New("email domain is not allowed to sign in")
		}
	}
	var name string
	switch p.cfg.UsernameClaim {
	case "email":
		if !emailOK {
			return "", errors.New("a verified email is required to sign in")
		}
		name = strings.ToLower(c.Email)
	case "preferred_username":
		name = c.PreferredUsername
	case "sub":
		name = c.Subject
	}
	if !validUsername(name) {
		return "", fmt.Errorf("the identity provider's %s is not a valid Daru username", p.cfg.UsernameClaim)
	}
	return name, nil
}

// key returns the JWKS key for kid, refetching the key set at most once a
// minute so a provider key rotation is picked up without a restart.
func (p *OIDCProvider) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if k, ok := p.pick(kid); ok {
		return k, nil
	}
	if !p.keysFetch.IsZero() && p.now().Sub(p.keysFetch) < time.Minute {
		return nil, errors.New("oidc: no signing key matches the id token")
	}
	var set struct {
		Keys []struct {
			Kty, Kid, Use, Alg, N, E, Crv, X, Y string
		} `json:"keys"`
	}
	p.keysFetch = p.now()
	if err := getJSON(ctx, p.client, p.jwksURL, &set); err != nil {
		return nil, fmt.Errorf("oidc jwks: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "RSA":
			n, err1 := base64.RawURLEncoding.DecodeString(k.N)
			e, err2 := base64.RawURLEncoding.DecodeString(k.E)
			if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
				continue
			}
			pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
			if pub.N.BitLen() < 2048 {
				continue // refuse weak keys
			}
			keys[k.Kid] = pub
		case "EC":
			if k.Crv != "P-256" {
				continue
			}
			x, err1 := base64.RawURLEncoding.DecodeString(k.X)
			y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
			// RFC 7518: P-256 coordinates are exactly 32 bytes each.
			if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
				continue
			}
			// Rejects points that are not on the curve.
			pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
			if err != nil {
				continue
			}
			keys[k.Kid] = pub
		}
	}
	p.keys = keys
	if k, ok := p.pick(kid); ok {
		return k, nil
	}
	return nil, errors.New("oidc: no signing key matches the id token")
}

// pick finds a key by kid; with no kid it accepts a single-key set only.
func (p *OIDCProvider) pick(kid string) (crypto.PublicKey, bool) {
	if kid != "" {
		k, ok := p.keys[kid]
		return k, ok
	}
	if len(p.keys) == 1 {
		for _, k := range p.keys {
			return k, true
		}
	}
	return nil, false
}

func getJSON(ctx context.Context, client *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	return dec.Decode(v)
}

func audiences(raw json.RawMessage) ([]string, error) {
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	err := json.Unmarshal(raw, &many)
	return many, err
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}
