package middleware

import (
	"net/http/httptest"
	"testing"
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
