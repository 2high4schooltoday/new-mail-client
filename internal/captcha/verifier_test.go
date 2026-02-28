package captcha

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPVerifierSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer ts.Close()

	v := &HTTPVerifier{verifyURL: ts.URL, secret: "secret", client: ts.Client()}
	if err := v.Verify(context.Background(), "token", "127.0.0.1"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestHTTPVerifierFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
	}))
	defer ts.Close()

	v := &HTTPVerifier{verifyURL: ts.URL, secret: "secret", client: ts.Client()}
	if err := v.Verify(context.Background(), "token", "127.0.0.1"); err == nil {
		t.Fatalf("expected failure")
	}
}
