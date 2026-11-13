package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"html"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml/samlidp"

	"github.com/TYFSADIK/daru/internal/auth"
	"github.com/TYFSADIK/daru/internal/ingest"
	"github.com/TYFSADIK/daru/internal/search"
	"github.com/TYFSADIK/daru/internal/store"
)

func selfSigned(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate, []byte, []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	return k, c, certPEM, keyPEM
}

type samlRig struct {
	idp     *httptest.Server
	daru    *httptest.Server
	f       *fakeCH
	client  *http.Client
	lastACS url.Values
}

// newSAMLRig starts a crewjam samlidp IdP and a Daru server (TLS, since the
// SAML state cookie is Secure) wired to each other.
func newSAMLRig(t *testing.T, autoCreate bool) *samlRig {
	t.Helper()
	return newSAMLRigSigned(t, autoCreate, false)
}

func newSAMLRigSigned(t *testing.T, autoCreate, signed bool) *samlRig {
	t.Helper()
	rig := &samlRig{f: newFakeCH()}
	// IdP.
	idpKey, idpCert, _, _ := selfSigned(t, "test-idp")
	rig.idp = httptest.NewUnstartedServer(nil)
	rig.idp.Start()
	t.Cleanup(rig.idp.Close)
	iu, _ := url.Parse(rig.idp.URL)
	idp, err := samlidp.New(samlidp.Options{URL: *iu, Key: idpKey, Certificate: idpCert, Store: &samlidp.MemoryStore{}})
	if err != nil {
		t.Fatal(err)
	}
	rig.idp.Config.Handler = idp
	for _, u := range []string{
		`{"name":"alice","password":"Idp-Pass-123","email":"alice@example.com","groups":["daru-admins"]}`,
		`{"name":"bob","password":"Idp-Pass-123","email":"bob@example.com","groups":["staff"]}`,
	} {
		name := regexp.MustCompile(`"name":"(\w+)"`).FindStringSubmatch(u)[1]
		req, _ := http.NewRequest(http.MethodPut, rig.idp.URL+"/users/"+name, strings.NewReader(u))
		if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode >= 300 {
			t.Fatalf("add idp user: %v %v", err, resp)
		}
	}
	// Daru.
	ch := httptest.NewServer(rig.f)
	t.Cleanup(ch.Close)
	rig.daru = httptest.NewUnstartedServer(nil)
	rig.daru.StartTLS()
	t.Cleanup(rig.daru.Close)
	dir := t.TempDir()
	_, _, certPEM, keyPEM := selfSigned(t, "daru-sp")
	os.WriteFile(filepath.Join(dir, "sp.crt"), certPEM, 0o600)
	os.WriteFile(filepath.Join(dir, "sp.key"), keyPEM, 0o600)
	st := store.New(store.Config{URL: ch.URL, Database: "daru"})
	sc, err := NewSAML(context.Background(), SAMLConfig{
		RootURL: rig.daru.URL, IDPMetadataURL: rig.idp.URL + "/metadata",
		KeyFile: filepath.Join(dir, "sp.key"), CertFile: filepath.Join(dir, "sp.crt"),
		UsernameAttr: "uid", GroupAttr: "eduPersonAffiliation", AdminGroup: "daru-admins",
		// samlidp's login form re-posts the AuthnRequest without the
		// redirect signature and then refuses its own repost, so this test
		// IdP needs unsigned requests. Responses are verified either way.
		UnsignedRequests: !signed,
		Policy:           ExternalAccountPolicy{AutoCreate: autoCreate},
	}, st)
	if err != nil {
		t.Fatalf("NewSAML: %v", err)
	}
	s := &Server{Store: st, Auth: auth.New(st), Ingest: ingest.New(st), Search: search.New(st),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), SAML: sc, Secure: true}
	rig.daru.Config.Handler = s.Handler()
	// Register Daru's SP metadata at the IdP.
	md, err := rig.daru.Client().Get(rig.daru.URL + "/api/saml/metadata")
	if err != nil {
		t.Fatal(err)
	}
	mdBytes, _ := io.ReadAll(md.Body)
	req, _ := http.NewRequest(http.MethodPut, rig.idp.URL+"/services/daru", bytes.NewReader(mdBytes))
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode >= 300 {
		t.Fatalf("register SP: %v %v", err, resp)
	}
	jar, _ := cookiejar.New(nil)
	rig.client = &http.Client{Jar: jar, Transport: rig.daru.Client().Transport}
	return rig
}

var (
	formAction = regexp.MustCompile(`<form[^>]*action="([^"]*)"`)
	hiddenIn   = regexp.MustCompile(`<input type="hidden" name="(\w+)" value="([^"]*)"`)
)

func parseForm(t *testing.T, body string) (string, url.Values) {
	t.Helper()
	m := formAction.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no form in page: %.400s", body)
	}
	v := url.Values{}
	for _, h := range hiddenIn.FindAllStringSubmatch(body, -1) {
		v.Set(h[1], html.UnescapeString(h[2]))
	}
	return html.UnescapeString(m[1]), v
}

// login runs the browser flow and returns where it ended.
func (rig *samlRig) login(t *testing.T, user string) string {
	t.Helper()
	resp, err := rig.client.Get(rig.daru.URL + "/api/saml/login")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	action, form := parseForm(t, string(page))
	form.Set("user", user)
	form.Set("password", "Idp-Pass-123")
	resp, err = rig.client.PostForm(resolve(resp.Request.URL, action), form)
	if err != nil {
		t.Fatal(err)
	}
	page, _ = io.ReadAll(resp.Body)
	acs, form := parseForm(t, string(page))
	if form.Get("SAMLResponse") == "" {
		t.Fatalf("IdP did not return a SAMLResponse: %.400s", page)
	}
	rig.lastACS = form
	return rig.postACS(t, acs, form)
}

func (rig *samlRig) postACS(t *testing.T, acs string, form url.Values) string {
	t.Helper()
	noFollow := *rig.client
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noFollow.PostForm(acs, form)
	if err != nil {
		t.Fatal(err)
	}
	return resp.Header.Get("Location")
}

func resolve(base *url.URL, ref string) string {
	u, err := base.Parse(ref)
	if err != nil {
		return ref
	}
	return u.String()
}

func (rig *samlRig) hasSession() bool {
	u, _ := url.Parse(rig.daru.URL)
	for _, c := range rig.client.Jar.Cookies(u) {
		if c.Name == sessionCookie && c.Value != "" {
			return true
		}
	}
	return false
}

func TestSAMLLoginEndToEnd(t *testing.T) {
	rig := newSAMLRig(t, false)
	rig.f.addUserSource("alice", auth.RoleUser, "main", "unused", auth.SourceSAML)
	if loc := rig.login(t, "alice"); loc != "/#/search" || !rig.hasSession() {
		t.Fatalf("saml login ended at %q, session=%v", loc, rig.hasSession())
	}
	// alice is in daru-admins at the IdP: her role is synced to admin.
	rig.f.mu.Lock()
	synced := false
	for _, q := range rig.f.queries {
		if strings.HasPrefix(q, "INSERT INTO users") && strings.Contains(q, "'alice'") && strings.Contains(q, "'admin'") {
			synced = true
		}
	}
	rig.f.mu.Unlock()
	if !synced {
		t.Error("group mapped role was not synced to admin")
	}
	// Replaying the same response is refused (state consumed, replay cache).
	acs := rig.daru.URL + "/api/saml/acs"
	if loc := rig.postACS(t, acs, rig.lastACS); loc != "/?sso=failed" {
		t.Errorf("replayed SAMLResponse ended at %q, want failure", loc)
	}
}

func TestSAMLRefusals(t *testing.T) {
	rig := newSAMLRig(t, true)
	// bob exists as a local account: a SAML identity must not take it over,
	// even with auto create on.
	rig.f.addUser("bob", auth.RoleAdmin, "*", "unused")
	if loc := rig.login(t, "bob"); loc != "/?sso=failed" || rig.hasSession() {
		t.Errorf("SAML identity signed in to a local account: %q", loc)
	}
	// A tampered response is refused: flip a byte inside the signed XML.
	rig2 := newSAMLRig(t, true)
	rig2.f.addUserSource("alice", auth.RoleUser, "*", "unused", auth.SourceSAML)
	resp, _ := rig2.client.Get(rig2.daru.URL + "/api/saml/login")
	page, _ := io.ReadAll(resp.Body)
	action, form := parseForm(t, string(page))
	form.Set("user", "alice")
	form.Set("password", "Idp-Pass-123")
	resp, _ = rig2.client.PostForm(resolve(resp.Request.URL, action), form)
	page, _ = io.ReadAll(resp.Body)
	acs, form := parseForm(t, string(page))
	raw := form.Get("SAMLResponse")
	dec, _ := decodeB64(raw)
	// The IdP encrypts the assertion to Daru's certificate, so tamper with
	// the signed plaintext when present, else with the ciphertext.
	tampered := strings.Replace(string(dec), ">alice<", ">admin<", 1)
	if tampered == string(dec) {
		i := strings.LastIndex(tampered, "CipherValue>")
		if i < 0 {
			t.Fatal("response has neither a plaintext username nor ciphertext to tamper with")
		}
		b := []byte(tampered)
		pos := i + len("CipherValue>") + 20
		if b[pos] == 'A' {
			b[pos] = 'B'
		} else {
			b[pos] = 'A'
		}
		tampered = string(b)
	}
	form.Set("SAMLResponse", encodeB64([]byte(tampered)))
	if loc := rig2.postACS(t, acs, form); loc != "/?sso=failed" {
		t.Errorf("tampered SAMLResponse ended at %q, want failure", loc)
	}
	// An ACS post without the browser-bound state cookie (login CSRF).
	if loc := (&samlRig{client: &http.Client{Transport: rig2.daru.Client().Transport}, daru: rig2.daru}).postACS(t, acs, form); loc != "/?sso=failed" {
		t.Errorf("ACS without state cookie ended at %q", loc)
	}
}

func TestSAMLMetadataAndConfig(t *testing.T) {
	rig := newSAMLRig(t, false)
	resp, err := rig.client.Get(rig.daru.URL + "/api/saml/metadata")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "/api/saml/acs") || !strings.Contains(resp.Header.Get("Content-Type"), "samlmetadata") {
		t.Errorf("metadata wrong: %s %.300s", resp.Header.Get("Content-Type"), b)
	}
	resp, _ = rig.client.Get(rig.daru.URL + "/api/saml/config")
	b, _ = io.ReadAll(resp.Body)
	if !strings.Contains(string(b), `"enabled":true`) {
		t.Errorf("config = %s", b)
	}
	h := newTestServer(t, newFakeCH(), nil)
	if rec := doJSON(h, "GET", "/api/saml/login", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("saml login with SAML off = %d", rec.Code)
	}
}

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
func encodeB64(b []byte) string          { return base64.StdEncoding.EncodeToString(b) }

// With request signing on (the default), the IdP must verify Daru's
// signed HTTP-Redirect AuthnRequest against the certificate in Daru's SP
// metadata, and refuse it once the signature is corrupted.
func TestSAMLSignedAuthnRequestVerifiedByIdP(t *testing.T) {
	rig := newSAMLRigSigned(t, false, true)
	noFollow := *rig.client
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noFollow.Get(rig.daru.URL + "/api/saml/login")
	if err != nil {
		t.Fatal(err)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Query().Get("Signature") == "" || !strings.Contains(loc.Query().Get("SigAlg"), "rsa-sha256") {
		t.Fatalf("redirect is not a signed RSA-SHA256 request: %s", resp.Header.Get("Location"))
	}
	// Correct signature: the IdP accepts the request and shows its login form.
	ok, err := http.Get(loc.String())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(ok.Body)
	if ok.StatusCode != http.StatusOK || !strings.Contains(string(body), `name="password"`) {
		t.Fatalf("IdP refused a correctly signed request: %d %.200s", ok.StatusCode, body)
	}
	// Corrupted signature: the IdP refuses it.
	q := loc.Query()
	sig, _ := base64.StdEncoding.DecodeString(q.Get("Signature"))
	sig[len(sig)/2] ^= 0xff
	raw := strings.Replace(loc.RawQuery, "Signature="+url.QueryEscape(q.Get("Signature")),
		"Signature="+url.QueryEscape(base64.StdEncoding.EncodeToString(sig)), 1)
	if raw == loc.RawQuery {
		t.Fatal("could not corrupt the signature parameter")
	}
	bad := *loc
	bad.RawQuery = raw
	resp2, err := http.Get(bad.String())
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode == http.StatusOK {
		t.Error("IdP accepted a request with a corrupted signature")
	}
}
