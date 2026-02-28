package auth

import "testing"

func TestHashVerify(t *testing.T) {
	h, err := HashPassword("secret-123")
	if err != nil {
		t.Fatalf("hash error: %v", err)
	}
	if !VerifyPassword(h, "secret-123") {
		t.Fatalf("expected verify to pass")
	}
	if VerifyPassword(h, "wrong") {
		t.Fatalf("expected verify to fail")
	}
}
