package config

import "testing"

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
