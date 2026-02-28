package service

import (
	"testing"

	"mailclient/internal/config"
)

func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "Example.COM", want: "example.com"},
		{in: "https://mail.example.com/", want: "mail.example.com"},
		{in: "http://example.com.", want: "example.com"},
	}

	for _, tc := range cases {
		got := normalizeDomain(tc.in)
		if got != tc.want {
			t.Fatalf("normalizeDomain(%q)=%q want=%q", tc.in, got, tc.want)
		}
	}
}

func TestDefaultAdminEmail(t *testing.T) {
	if got := defaultAdminEmail("example.com"); got != "webmaster@example.com" {
		t.Fatalf("defaultAdminEmail mismatch: %q", got)
	}
	if got := defaultAdminEmail(""); got != "webmaster@example.com" {
		t.Fatalf("defaultAdminEmail empty mismatch: %q", got)
	}
}

func TestValidatePasswordPolicy(t *testing.T) {
	svc := &Service{cfg: config.Config{PasswordMinLength: 12, PasswordMaxLength: 128}}
	if err := svc.ValidatePassword("short1A!"); err == nil {
		t.Fatalf("expected short password to fail")
	}
	if err := svc.ValidatePassword("alllowercasepassword"); err == nil {
		t.Fatalf("expected weak class password to fail")
	}
	if err := svc.ValidatePassword("StrongPass123!"); err != nil {
		t.Fatalf("expected strong password to pass: %v", err)
	}
}
