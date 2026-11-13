package main

import (
	"errors"
	"testing"
)

func TestIsAuthError(t *testing.T) {
	yes := []string{"Code: 516. DB::Exception: daru: Authentication failed: password is incorrect", "Code: 194. default: Authentication failed"}
	no := []string{"connection refused", "context deadline exceeded", ""}
	for _, s := range yes {
		if !isAuthError(errors.New(s)) {
			t.Errorf("should be auth error: %q", s)
		}
	}
	for _, s := range no {
		if s != "" && isAuthError(errors.New(s)) {
			t.Errorf("should NOT be auth error: %q", s)
		}
	}
	if isAuthError(nil) {
		t.Error("nil should not be auth error")
	}
}
