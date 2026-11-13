package auth

import (
	"testing"
	"time"
)

func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !VerifyPassword("correct horse battery", hash) {
		t.Error("correct password did not verify")
	}
	if VerifyPassword("wrong password", hash) {
		t.Error("wrong password verified")
	}
	// Each hash uses a fresh salt.
	hash2, _ := HashPassword("correct horse battery")
	if hash == hash2 {
		t.Error("two hashes of the same password are identical (salt not random)")
	}
}

func TestPasswordRules(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Error("short password should be rejected")
	}
}

func TestVerifyBadHash(t *testing.T) {
	for _, h := range []string{"", "not-a-hash", "$argon2id$bad"} {
		if VerifyPassword("x", h) {
			t.Errorf("malformed hash %q verified", h)
		}
	}
}

func TestTokens(t *testing.T) {
	tok, hash, err := NewToken("daru_test")
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if tok == "" || hash == "" || tok == hash {
		t.Error("token or hash is empty or equal")
	}
	if hashToken(tok) != hash {
		t.Error("hashToken is not stable")
	}
	tok2, _, err := NewToken("daru_test")
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if tok == tok2 {
		t.Error("tokens are not unique")
	}
}

func TestVerifyPasswordRejectsExtremeParams(t *testing.T) {
	// A stored hash claiming 16 GiB of Argon2 memory must not be honoured.
	bad := "$argon2id$v=19$m=16777216,t=2,p=4$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if VerifyPassword("password", bad) {
		t.Error("hash with excessive memory verified")
	}
	badTime := "$argon2id$v=19$m=65536,t=99,p=4$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if VerifyPassword("password", badTime) {
		t.Error("hash with excessive time verified")
	}
}

func TestTOTP(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if secret == "" {
		t.Fatal("empty secret")
	}
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	code, err := totpCode(secret, uint64(now.Unix()/30))
	if err != nil {
		t.Fatalf("totpCode: %v", err)
	}
	if !VerifyTOTP(secret, code, now) {
		t.Error("current TOTP code did not verify")
	}
	if VerifyTOTP(secret, "000000", now) && code != "000000" {
		t.Error("wrong TOTP code verified")
	}
	if VerifyTOTP(secret, code, now.Add(5*time.Minute)) {
		t.Error("stale TOTP code verified outside the skew window")
	}
	if VerifyTOTP("not-base32!!!", code, now) {
		t.Error("bad secret verified")
	}
	if got := TOTPProvisioningURI(secret, "alice", "Daru"); got == "" {
		t.Error("empty provisioning URI")
	}
}

func TestRoles(t *testing.T) {
	if !ValidRole("admin") || !ValidRole("power") || !ValidRole("user") {
		t.Error("valid roles rejected")
	}
	if ValidRole("superuser") {
		t.Error("invalid role accepted")
	}
}
