package auth

import "testing"

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
	tok, hash := NewToken("daru_test")
	if tok == "" || hash == "" || tok == hash {
		t.Error("token or hash is empty or equal")
	}
	if hashToken(tok) != hash {
		t.Error("hashToken is not stable")
	}
	tok2, _ := NewToken("daru_test")
	if tok == tok2 {
		t.Error("tokens are not unique")
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
