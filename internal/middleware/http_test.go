package middleware

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mailclient/internal/config"
	"mailclient/internal/db"
	"mailclient/internal/service"
	"mailclient/internal/store"
)

func TestClientIPTrustProxy(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:12345"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.5")

	if got := ClientIP(r, false); got != "10.0.0.5" {
		t.Fatalf("unexpected direct IP: %s", got)
	}
	if got := ClientIP(r, true); got != "1.2.3.4" {
		t.Fatalf("unexpected proxied IP: %s", got)
	}
}

func TestAuthnMissingCookieReturnsSessionMissing(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := Authn(nil, "mailclient_session", false)(next)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if body := rec.Body.String(); body == "" || !strings.Contains(body, `"code":"session_missing"`) {
		t.Fatalf("expected session_missing code, got: %s", body)
	}
}

func TestAuthnInvalidCookieReturnsSessionInvalid(t *testing.T) {
	sqdb, err := db.OpenSQLite(filepath.Join(t.TempDir(), "app.db"), 1, 1, time.Minute)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sqdb.Close() })
	for _, migration := range []string{
		filepath.Join("..", "..", "migrations", "001_init.sql"),
		filepath.Join("..", "..", "migrations", "002_users_mail_login.sql"),
		filepath.Join("..", "..", "migrations", "003_cleanup_rejected_users.sql"),
		filepath.Join("..", "..", "migrations", "004_cleanup_rejected_users_casefold.sql"),
		filepath.Join("..", "..", "migrations", "005_admin_query_indexes.sql"),
	} {
		if err := db.ApplyMigrationFile(sqdb, migration); err != nil {
			t.Fatalf("apply migration %s: %v", migration, err)
		}
	}
	cfg := config.Config{SessionEncryptKey: "this_is_a_valid_long_session_encrypt_key_123456"}
	svc := service.New(cfg, store.New(sqdb), nil, nil, nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := Authn(svc, "mailclient_session", false)(next)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.AddCookie(&http.Cookie{Name: "mailclient_session", Value: "invalid-token"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if body := rec.Body.String(); body == "" || !strings.Contains(body, `"code":"session_invalid"`) {
		t.Fatalf("expected session_invalid code, got: %s", body)
	}
}
