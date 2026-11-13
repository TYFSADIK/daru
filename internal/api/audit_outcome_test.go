package api

import "testing"

func TestAuditOutcome(t *testing.T) {
	for event, want := range map[string]string{
		"login.success": "ok", "login.failure": "failure", "login.rate_limited": "failure",
		"login.ldap_refused": "failure", "tools.update_blocked": "failure", "token.create": "ok",
		"totp.enable_failure": "failure", "scan.start": "ok",
	} {
		if got := auditOutcome(event); got != want {
			t.Errorf("auditOutcome(%q) = %q, want %q", event, got, want)
		}
	}
}
