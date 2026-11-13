package api

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/TYFSADIK/daru/internal/auth"
)

// SAML 2.0 single sign on, as a service provider (crewjam/saml). Daru sends
// an AuthnRequest with the HTTP-Redirect binding and receives the Response
// at its assertion consumer service with HTTP-POST. The library checks the
// IdP signature (SHA-1 refused), destination, audience, InResponseTo,
// validity window, and issuer; Daru adds a replay cache, refuses IdP
// initiated logins, and binds each request to the browser with a cookie so
// a captured response cannot sign someone else's browser in.

const samlStateCookie = "daru_saml_state"

// SAMLConfig configures the service provider.
type SAMLConfig struct {
	RootURL string // https://daru.example.com
	// IdP metadata: a URL to fetch, or a local XML file.
	IDPMetadataURL  string
	IDPMetadataFile string
	// The SP signing key and certificate (PEM files). The certificate is
	// published in the SP metadata so the IdP can verify signed requests.
	KeyFile, CertFile string
	// Attribute names. Empty UsernameAttr means the Subject NameID.
	UsernameAttr, EmailAttr, GroupAttr string
	// Group values mapped to roles, like LDAP. Both empty keeps roles in Daru.
	AdminGroup, PowerGroup string
	// UnsignedRequests turns off AuthnRequest signing, for an IdP that
	// cannot verify signed requests. Responses are always verified.
	UnsignedRequests bool
	Policy           ExternalAccountPolicy
	HTTPClient       *http.Client
}

// SAMLSettings is a ready service provider.
type SAMLSettings struct {
	SP     *saml.ServiceProvider
	cfg    SAMLConfig
	mu     sync.Mutex
	states map[string]samlPending
}

type samlPending struct {
	requestID string
	expires   time.Time
}

// NewSAML builds the service provider from configuration.
func NewSAML(ctx context.Context, cfg SAMLConfig) (*SAMLSettings, error) {
	root, err := url.Parse(strings.TrimRight(cfg.RootURL, "/"))
	if err != nil || root.Host == "" {
		return nil, fmt.Errorf("saml: root url is required, e.g. https://daru.example.com")
	}
	if root.Scheme != "https" {
		host := root.Hostname()
		ip := net.ParseIP(host)
		if root.Scheme != "http" || !(host == "localhost" || (ip != nil && ip.IsLoopback())) {
			return nil, fmt.Errorf("saml: root url must be https (http only for localhost)")
		}
	}
	if cfg.KeyFile == "" || cfg.CertFile == "" {
		return nil, fmt.Errorf("saml: SP key and certificate files are required")
	}
	pair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("saml: load SP key pair: %w", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("saml: parse SP certificate: %w", err)
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("saml: SP key cannot sign")
	}
	method := ""
	switch signer.(type) {
	case *rsa.PrivateKey:
		method = dsig.RSASHA256SignatureMethod
	case *ecdsa.PrivateKey:
		method = dsig.ECDSASHA256SignatureMethod
	default:
		return nil, fmt.Errorf("saml: SP key must be RSA or ECDSA")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	var md *saml.EntityDescriptor
	switch {
	case cfg.IDPMetadataFile != "":
		b, err := os.ReadFile(cfg.IDPMetadataFile)
		if err != nil {
			return nil, fmt.Errorf("saml: read IdP metadata: %w", err)
		}
		if md, err = samlsp.ParseMetadata(b); err != nil {
			return nil, fmt.Errorf("saml: parse IdP metadata: %w", err)
		}
	case cfg.IDPMetadataURL != "":
		mu, err := url.Parse(cfg.IDPMetadataURL)
		if err != nil {
			return nil, fmt.Errorf("saml: IdP metadata url: %w", err)
		}
		if md, err = samlsp.FetchMetadata(ctx, client, *mu); err != nil {
			return nil, fmt.Errorf("saml: fetch IdP metadata: %w", err)
		}
	default:
		return nil, fmt.Errorf("saml: IdP metadata url or file is required")
	}
	metaURL := *root
	metaURL.Path = "/api/saml/metadata"
	acsURL := *root
	acsURL.Path = "/api/saml/acs"
	sp := &saml.ServiceProvider{
		EntityID:             metaURL.String(),
		Key:                  signer,
		Certificate:          cert,
		HTTPClient:           client,
		MetadataURL:          metaURL,
		AcsURL:               acsURL,
		IDPMetadata:          md,
		SignatureMethod:      method,
		AllowIDPInitiated:    false,
		RejectSHA1Signatures: true,
		ReplayCache:          samlsp.NewMemoryReplayCache(100000),
	}
	if cfg.UnsignedRequests {
		sp.SignatureMethod = ""
	}
	if sp.GetSSOBindingLocation(saml.HTTPRedirectBinding) == "" {
		return nil, fmt.Errorf("saml: IdP metadata has no HTTP-Redirect single sign on endpoint")
	}
	return &SAMLSettings{SP: sp, cfg: cfg, states: map[string]samlPending{}}, nil
}

func (s *Server) handleSAMLConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"enabled": s.SAML != nil})
}

func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	if s.SAML == nil {
		writeError(w, http.StatusNotFound, "saml is not configured")
		return
	}
	b, err := xml.MarshalIndent(s.SAML.SP.Metadata(), "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not build metadata")
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(b)
}

func (s *Server) handleSAMLLogin(w http.ResponseWriter, r *http.Request) {
	sc := s.SAML
	if sc == nil {
		writeError(w, http.StatusNotFound, "saml is not configured")
		return
	}
	state, err := randomString(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start sign in")
		return
	}
	req, err := sc.SP.MakeAuthenticationRequest(sc.SP.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		s.Log.Warn("saml authn request failed", "err", err)
		writeError(w, http.StatusInternalServerError, "could not start sign in")
		return
	}
	dest, err := req.Redirect(state, sc.SP)
	if err != nil {
		s.Log.Warn("saml redirect failed", "err", err)
		writeError(w, http.StatusInternalServerError, "could not start sign in")
		return
	}
	now := time.Now()
	sc.mu.Lock()
	for k, v := range sc.states {
		if now.After(v.expires) {
			delete(sc.states, k)
		}
	}
	if len(sc.states) > 10000 {
		sc.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, "too many sign in attempts in progress")
		return
	}
	sc.states[state] = samlPending{requestID: req.ID, expires: now.Add(10 * time.Minute)}
	sc.mu.Unlock()
	// The IdP returns with a cross site POST, which only carries a
	// SameSite=None cookie, and SameSite=None requires Secure.
	http.SetCookie(w, &http.Cookie{
		Name: samlStateCookie, Value: state, Path: "/api/saml/", MaxAge: 600,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode,
	})
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

func (s *Server) samlFail(w http.ResponseWriter, r *http.Request, user, reason string) {
	s.Log.Warn("saml sign in failed", "user", user, "reason", reason)
	s.audit(r, "login.saml_failure", user, "reason", reason)
	s.metrics.loginFailures.Add(1)
	http.Redirect(w, r, "/?sso=failed", http.StatusSeeOther)
}

func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	sc := s.SAML
	if sc == nil {
		writeError(w, http.StatusNotFound, "saml is not configured")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: samlStateCookie, Value: "", Path: "/api/saml/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode})
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		s.samlFail(w, r, "", "unreadable form")
		return
	}
	state := r.PostForm.Get("RelayState")
	c, err := r.Cookie(samlStateCookie)
	if state == "" || err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 {
		s.samlFail(w, r, "", "relay state missing or not bound to this browser")
		return
	}
	sc.mu.Lock()
	pend, ok := sc.states[state]
	delete(sc.states, state)
	sc.mu.Unlock()
	if !ok || time.Now().After(pend.expires) {
		s.samlFail(w, r, "", "relay state unknown or expired")
		return
	}
	assertion, err := sc.SP.ParseResponse(r, []string{pend.requestID})
	if err != nil {
		reason := err.Error()
		var ie *saml.InvalidResponseError
		if errors.As(err, &ie) && ie.PrivateErr != nil {
			reason = ie.PrivateErr.Error()
		}
		s.samlFail(w, r, "", "invalid response: "+reason)
		return
	}
	username, email, role, err := sc.identity(assertion)
	if err != nil {
		s.samlFail(w, r, "", err.Error())
		return
	}
	u, err := s.resolveExternal(r.Context(), r, auth.SourceSAML, username, email, role, sc.cfg.Policy)
	if err != nil {
		s.samlFail(w, r, username, reasonOf(err))
		return
	}
	if err := s.startSession(w, u); err != nil {
		s.samlFail(w, r, username, "could not create session")
		return
	}
	s.audit(r, "login.success", username, "method", "saml")
	http.Redirect(w, r, "/#/search", http.StatusSeeOther)
}

// identity extracts the username, email, and group mapped role.
func (sc *SAMLSettings) identity(a *saml.Assertion) (string, string, string, error) {
	values := func(name string) []string {
		var out []string
		if name == "" {
			return nil
		}
		for _, st := range a.AttributeStatements {
			for _, at := range st.Attributes {
				if at.Name == name || at.FriendlyName == name {
					for _, v := range at.Values {
						out = append(out, v.Value)
					}
				}
			}
		}
		return out
	}
	first := func(name string) string {
		if v := values(name); len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	var username string
	if sc.cfg.UsernameAttr == "" {
		if a.Subject != nil && a.Subject.NameID != nil {
			username = a.Subject.NameID.Value
		}
	} else {
		username = first(sc.cfg.UsernameAttr)
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if !auth.ValidUsername(username) {
		return "", "", "", fmt.Errorf("the IdP's username %q is not a valid Daru username", username)
	}
	email := first(orStr(sc.cfg.EmailAttr, "email"))
	role := ""
	if sc.cfg.AdminGroup != "" || sc.cfg.PowerGroup != "" {
		role = auth.RoleUser
		groups := values(orStr(sc.cfg.GroupAttr, "groups"))
		in := func(want string) bool {
			for _, g := range groups {
				if want != "" && strings.EqualFold(strings.TrimSpace(g), want) {
					return true
				}
			}
			return false
		}
		switch {
		case in(sc.cfg.AdminGroup):
			role = auth.RoleAdmin
		case in(sc.cfg.PowerGroup):
			role = auth.RolePower
		}
	}
	return username, email, role, nil
}

func orStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
