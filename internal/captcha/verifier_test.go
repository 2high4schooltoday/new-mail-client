package captcha

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPVerifierSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer ts.Close()

	v := &HTTPVerifier{provider: "turnstile", verifyURL: ts.URL, secret: "secret", client: ts.Client()}
	if err := v.Verify(context.Background(), "token", "127.0.0.1"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestHTTPVerifierFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
	}))
	defer ts.Close()

	v := &HTTPVerifier{provider: "turnstile", verifyURL: ts.URL, secret: "secret", client: ts.Client()}
	err := v.Verify(context.Background(), "token", "127.0.0.1")
	if err == nil {
		t.Fatalf("expected failure")
	}
	if !errors.Is(err, ErrCaptchaRequired) {
		t.Fatalf("expected ErrCaptchaRequired, got %v", err)
	}
}

func TestHTTPVerifierCAPSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("expected JSON content type, got %q", got)
		}
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer ts.Close()

	v := &HTTPVerifier{provider: "cap", verifyURL: ts.URL, secret: "secret", client: ts.Client()}
	if err := v.Verify(context.Background(), "token", "127.0.0.1"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestHTTPVerifierCAPUnavailable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"upstream unavailable"}`))
	}))
	defer ts.Close()

	v := &HTTPVerifier{provider: "cap", verifyURL: ts.URL, secret: "secret", client: ts.Client()}
	err := v.Verify(context.Background(), "token", "127.0.0.1")
	if err == nil {
		t.Fatalf("expected failure")
	}
	if !errors.Is(err, ErrCaptchaUnavailable) {
		t.Fatalf("expected ErrCaptchaUnavailable, got %v", err)
	}
}
