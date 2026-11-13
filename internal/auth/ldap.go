package auth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig configures directory sign in. Daru binds as a service account,
// searches for the user, then binds as the user's DN with the supplied
// password. The connection is TLS (ldaps://, or ldap:// with StartTLS);
// plain LDAP is allowed only to a loopback host and only when Insecure is
// set, so passwords never cross a network in cleartext.
type LDAPConfig struct {
	URL          string // ldaps://dc.example.com:636 or ldap://dc.example.com:389
	StartTLS     bool
	Insecure     bool   // allow plain ldap:// to loopback (tests, a local slapd)
	CAFile       string // PEM bundle to trust instead of the system roots
	BindDN       string // service account, e.g. cn=daru,ou=svc,dc=example,dc=com
	BindPassword string
	BaseDN       string // where users live
	// UserFilter finds a user; %s is replaced by the escaped username.
	// Default (uid=%s); Active Directory uses (sAMAccountName=%s).
	UserFilter string
	// Attribute names. Defaults: uid, mail, memberOf.
	UsernameAttr, EmailAttr, GroupAttr string
	// Group DNs mapped to roles. A user in AdminGroup is admin, else in
	// PowerGroup is power, else user. Leave both empty to keep roles
	// managed in Daru.
	AdminGroup, PowerGroup string
	Timeout                time.Duration
}

// LDAPIdentity is a directory user who just proved their password.
type LDAPIdentity struct {
	Username string
	Email    string
	// Role is the role mapped from groups, or "" when no group mapping is
	// configured.
	Role string
}

// LDAPAuthenticator checks passwords against a directory.
type LDAPAuthenticator struct {
	cfg  LDAPConfig
	tls  *tls.Config
	host string
}

// ErrLDAPInvalid means the username or password was wrong.
var ErrLDAPInvalid = errors.New("invalid username or password")

// NewLDAPAuthenticator validates the configuration.
func NewLDAPAuthenticator(cfg LDAPConfig) (*LDAPAuthenticator, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Hostname() == "" {
		return nil, fmt.Errorf("ldap: url must be ldaps://host[:port] or ldap://host[:port]")
	}
	if u.Scheme == "ldap" && !cfg.StartTLS {
		ip := net.ParseIP(u.Hostname())
		loop := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
		if !cfg.Insecure || !loop {
			return nil, fmt.Errorf("ldap: plain ldap:// sends passwords in cleartext; use ldaps://, StartTLS, or (loopback only) the insecure flag")
		}
	}
	if cfg.BaseDN == "" {
		return nil, fmt.Errorf("ldap: base DN is required")
	}
	if cfg.UserFilter == "" {
		cfg.UserFilter = "(uid=%s)"
	}
	if strings.Count(cfg.UserFilter, "%s") != 1 {
		return nil, fmt.Errorf("ldap: user filter must contain exactly one %%s")
	}
	if cfg.UsernameAttr == "" {
		cfg.UsernameAttr = "uid"
	}
	if cfg.EmailAttr == "" {
		cfg.EmailAttr = "mail"
	}
	if cfg.GroupAttr == "" {
		cfg.GroupAttr = "memberOf"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	tc := &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ldap: read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ldap: CA file has no certificates")
		}
		tc.RootCAs = pool
	}
	return &LDAPAuthenticator{cfg: cfg, tls: tc, host: u.Hostname()}, nil
}

func (a *LDAPAuthenticator) dial() (*ldap.Conn, error) {
	conn, err := ldap.DialURL(a.cfg.URL, ldap.DialWithTLSConfig(a.tls),
		ldap.DialWithDialer(&net.Dialer{Timeout: a.cfg.Timeout}))
	if err != nil {
		return nil, fmt.Errorf("ldap dial: %w", err)
	}
	conn.SetTimeout(a.cfg.Timeout)
	if a.cfg.StartTLS {
		if err := conn.StartTLS(a.tls); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("ldap starttls: %w", err)
		}
	}
	return conn, nil
}

// Authenticate checks a username and password against the directory.
func (a *LDAPAuthenticator) Authenticate(username, password string) (*LDAPIdentity, error) {
	// An empty password is an "unauthenticated bind" (RFC 4513 5.1.2), which
	// many servers accept as success. Refuse it before touching the wire.
	if username == "" || password == "" || len(username) > 256 || len(password) > 1024 {
		return nil, ErrLDAPInvalid
	}
	conn, err := a.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if a.cfg.BindDN != "" {
		if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("ldap service bind: %w", err)
		}
	}
	filter := fmt.Sprintf(a.cfg.UserFilter, ldap.EscapeFilter(username))
	res, err := conn.Search(ldap.NewSearchRequest(a.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, int(a.cfg.Timeout/time.Second), false, filter,
		[]string{"dn", a.cfg.UsernameAttr, a.cfg.EmailAttr, a.cfg.GroupAttr}, nil))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
			return nil, ErrLDAPInvalid
		}
		return nil, fmt.Errorf("ldap search: %w", err)
	}
	// Exactly one entry, or the filter is ambiguous and nobody signs in.
	if len(res.Entries) != 1 {
		return nil, ErrLDAPInvalid
	}
	e := res.Entries[0]
	if err := conn.Bind(e.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, ErrLDAPInvalid
		}
		return nil, fmt.Errorf("ldap user bind: %w", err)
	}
	id := &LDAPIdentity{
		Username: e.GetAttributeValue(a.cfg.UsernameAttr),
		Email:    e.GetAttributeValue(a.cfg.EmailAttr),
	}
	if id.Username == "" {
		id.Username = username
	}
	// The directory's spelling must match what was typed (case aside), so
	// a filter on another attribute cannot sign one person in as another.
	if !strings.EqualFold(id.Username, username) {
		return nil, ErrLDAPInvalid
	}
	id.Username = strings.ToLower(id.Username)
	if !validUsername(id.Username) {
		return nil, fmt.Errorf("ldap: directory username %q is not a valid Daru username", id.Username)
	}
	id.Role = a.mapRole(e.GetAttributeValues(a.cfg.GroupAttr))
	return id, nil
}

func (a *LDAPAuthenticator) mapRole(groups []string) string {
	if a.cfg.AdminGroup == "" && a.cfg.PowerGroup == "" {
		return ""
	}
	has := func(want string) bool {
		if want == "" {
			return false
		}
		for _, g := range groups {
			if strings.EqualFold(normalizeDN(g), normalizeDN(want)) {
				return true
			}
		}
		return false
	}
	switch {
	case has(a.cfg.AdminGroup):
		return RoleAdmin
	case has(a.cfg.PowerGroup):
		return RolePower
	default:
		return RoleUser
	}
}

// normalizeDN parses and re-serializes a DN, so spacing differences such
// as "cn=a, dc=b" and "cn=a,dc=b" compare equal.
func normalizeDN(dn string) string {
	p, err := ldap.ParseDN(dn)
	if err != nil {
		return strings.TrimSpace(dn)
	}
	return p.String()
}
