package config

import (
	"net/http/httptest"
	"testing"
)

func TestLoadRejectsDefaultSessionKey(t *testing.T) {
	t.Setenv("SESSION_ENCRYPT_KEY", "CHANGE_ME_PRODUCTION_SESSION_KEY")
	_, err := Load()
	if err == nil {
		t.Fatalf("expected Load to fail with default session key")
	}
}

func TestLoadPasswordBounds(t *testing.T) {
	t.Setenv("SESSION_ENCRYPT_KEY", "this_is_a_valid_long_session_encrypt_key_123456")
	t.Setenv("PASSWORD_MIN_LENGTH", "16")
	t.Setenv("PASSWORD_MAX_LENGTH", "12")
	_, err := Load()
	if err == nil {
		t.Fatalf("expected Load to fail for invalid password bounds")
	}
}

func TestLoadRejectsInvalidDovecotAuthMode(t *testing.T) {
	t.Setenv("SESSION_ENCRYPT_KEY", "this_is_a_valid_long_session_encrypt_key_123456")
	t.Setenv("DOVECOT_AUTH_MODE", "ldap")
	_, err := Load()
	if err == nil {
		t.Fatalf("expected Load to fail for invalid DOVECOT_AUTH_MODE")
	}
}

func TestLoadCookieSecureModeLegacyFallback(t *testing.T) {
	t.Setenv("SESSION_ENCRYPT_KEY", "this_is_a_valid_long_session_encrypt_key_123456")
	t.Setenv("COOKIE_SECURE_MODE", "")
	t.Setenv("COOKIE_SECURE", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CookieSecureMode != "always" {
		t.Fatalf("expected legacy true to map to always, got %q", cfg.CookieSecureMode)
	}

	t.Setenv("COOKIE_SECURE", "false")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CookieSecureMode != "never" {
		t.Fatalf("expected legacy false to map to never, got %q", cfg.CookieSecureMode)
	}
}

func TestResolveCookieSecureAuto(t *testing.T) {
	t.Setenv("SESSION_ENCRYPT_KEY", "this_is_a_valid_long_session_encrypt_key_123456")
	t.Setenv("COOKIE_SECURE_MODE", "auto")
	t.Setenv("TRUST_PROXY", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.test", nil)
	if got := cfg.ResolveCookieSecure(req); got {
		t.Fatalf("expected http request to resolve secure=false")
	}

	req.Header.Set("X-Forwarded-Proto", "https")
	if got := cfg.ResolveCookieSecure(req); !got {
		t.Fatalf("expected proxied https request to resolve secure=true")
	}

	tlsReq := httptest.NewRequest("GET", "https://example.test", nil)
	if got := cfg.ResolveCookieSecure(tlsReq); !got {
		t.Fatalf("expected tls request to resolve secure=true")
	}
}
