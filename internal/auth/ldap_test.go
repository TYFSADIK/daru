package auth

import (
	"os"
	"testing"
)

func TestLDAPConfigValidation(t *testing.T) {
	bad := []LDAPConfig{
		{URL: "http://dc.example.com", BaseDN: "dc=x"},                         // not ldap
		{URL: "ldap://dc.example.com", BaseDN: "dc=x"},                         // cleartext to a remote host
		{URL: "ldap://dc.example.com", BaseDN: "dc=x", Insecure: true},         // insecure only for loopback
		{URL: "ldaps://dc.example.com"},                                        // no base DN
		{URL: "ldaps://dc.example.com", BaseDN: "dc=x", UserFilter: "(uid=x)"}, // no %s
		{URL: "ldaps://dc.example.com", BaseDN: "dc=x", UserFilter: "(|(uid=%s)(mail=%s))"},
	}
	for i, c := range bad {
		if _, err := NewLDAPAuthenticator(c); err == nil {
			t.Errorf("config %d should be rejected: %+v", i, c)
		}
	}
	good := []LDAPConfig{
		{URL: "ldaps://dc.example.com:636", BaseDN: "dc=x"},
		{URL: "ldap://dc.example.com:389", BaseDN: "dc=x", StartTLS: true},
		{URL: "ldap://127.0.0.1:3893", BaseDN: "dc=x", Insecure: true},
	}
	for i, c := range good {
		if _, err := NewLDAPAuthenticator(c); err != nil {
			t.Errorf("config %d should be accepted: %v", i, err)
		}
	}
}

func TestLDAPRefusesEmptyPasswordWithoutDialing(t *testing.T) {
	// Port 1 on loopback: any dial would fail with a connection error, so
	// getting ErrLDAPInvalid proves the empty password was refused first.
	a, err := NewLDAPAuthenticator(LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=x", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate("alice", ""); err != ErrLDAPInvalid {
		t.Errorf("empty password = %v, want ErrLDAPInvalid (unauthenticated bind must never be attempted)", err)
	}
	if _, err := a.Authenticate("", "pw"); err != ErrLDAPInvalid {
		t.Errorf("empty username = %v, want ErrLDAPInvalid", err)
	}
}

func TestLDAPRoleMapping(t *testing.T) {
	a, _ := NewLDAPAuthenticator(LDAPConfig{URL: "ldaps://x", BaseDN: "dc=x",
		AdminGroup: "cn=admins,ou=groups,dc=x", PowerGroup: "cn=ops,ou=groups,dc=x"})
	if r := a.mapRole([]string{"CN=Admins, OU=Groups, DC=x"}); r != RoleAdmin {
		t.Errorf("admin group (case and spacing differ) = %q", r)
	}
	if r := a.mapRole([]string{"cn=ops,ou=groups,dc=x"}); r != RolePower {
		t.Errorf("power group = %q", r)
	}
	if r := a.mapRole([]string{"cn=other,dc=x"}); r != RoleUser {
		t.Errorf("no mapped group = %q", r)
	}
	none, _ := NewLDAPAuthenticator(LDAPConfig{URL: "ldaps://x", BaseDN: "dc=x"})
	if r := none.mapRole([]string{"cn=admins,ou=groups,dc=x"}); r != "" {
		t.Errorf("without group mapping the role must stay Daru managed, got %q", r)
	}
}

// TestLDAPLive runs against a real directory when DARU_TEST_LDAP_URL is set
// (see FIXLOG for the glauth setup used to verify this).
func TestLDAPLive(t *testing.T) {
	url := os.Getenv("DARU_TEST_LDAP_URL")
	if url == "" {
		t.Skip("set DARU_TEST_LDAP_URL to run against a live directory")
	}
	a, err := NewLDAPAuthenticator(LDAPConfig{
		URL: url, Insecure: true, BaseDN: os.Getenv("DARU_TEST_LDAP_BASE"),
		BindDN: os.Getenv("DARU_TEST_LDAP_BIND_DN"), BindPassword: os.Getenv("DARU_TEST_LDAP_BIND_PW"),
		UserFilter: "(uid=%s)", AdminGroup: os.Getenv("DARU_TEST_LDAP_ADMIN_GROUP"),
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := a.Authenticate("alice", "Alice-Ldap-123")
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	if id.Username != "alice" || id.Role != RoleAdmin {
		t.Errorf("alice identity = %+v, want admin via group", id)
	}
	if id, err := a.Authenticate("bob", "Bob-Ldap-123"); err != nil || id.Role != RoleUser {
		t.Errorf("bob = %+v %v, want role user", id, err)
	}
	for _, c := range []struct{ user, pw string }{
		{"alice", "wrong"}, {"*", "Alice-Ldap-123"}, {"al*", "Alice-Ldap-123"},
		{"alice)(uid=*", "Alice-Ldap-123"}, {"nobody", "x"},
	} {
		// Any error is a refusal; some servers answer an escaped filter
		// with an operations error instead of an empty result.
		if id, err := a.Authenticate(c.user, c.pw); err == nil {
			t.Errorf("%q/%q signed in as %+v, want refusal", c.user, c.pw, id)
		}
	}
}
