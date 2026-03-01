package mail

import (
	"context"
	"errors"
	"testing"
)

func TestIsSMTPSenderPolicyError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "sender_address_rejected", err: errors.New("550 5.7.1 Sender address rejected: not owned by user"), want: true},
		{name: "sender_match_error", err: errors.New("sender must match authenticated user"), want: true},
		{name: "transport_error", err: errors.New("dial tcp 127.0.0.1:587: connect: connection refused"), want: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsSMTPSenderPolicyError(tc.err); got != tc.want {
				t.Fatalf("IsSMTPSenderPolicyError() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSendWithSenderFallbackRetriesWithAuthIdentity(t *testing.T) {
	c := &IMAPSMTPClient{}
	var attempts []string
	sendFn := func(ctx context.Context, user, pass, from string, rcpt []string, raw []byte) error {
		attempts = append(attempts, from)
		if len(attempts) == 1 {
			return errors.New("550 5.7.1 Sender address rejected: not owned by user")
		}
		return nil
	}

	req := SendRequest{
		From: "webmaster@example.com",
		To:   []string{"alice@example.com"},
	}
	err := c.sendWithSenderFallback(context.Background(), "webmaster", "secret", req, []byte("raw"), sendFn)
	if err != nil {
		t.Fatalf("expected retry fallback to succeed, got: %v", err)
	}
	if len(attempts) != 2 {
		t.Fatalf("expected 2 attempts, got %d (%v)", len(attempts), attempts)
	}
	if attempts[0] != "webmaster@example.com" || attempts[1] != "webmaster" {
		t.Fatalf("unexpected envelope from attempts: %#v", attempts)
	}
}

func TestSendWithSenderFallbackReturnsTypedErrorWhenRejected(t *testing.T) {
	c := &IMAPSMTPClient{}
	var attempts []string
	sendFn := func(ctx context.Context, user, pass, from string, rcpt []string, raw []byte) error {
		attempts = append(attempts, from)
		return errors.New("sender must match authenticated user")
	}

	req := SendRequest{
		From: "webmaster@example.com",
		To:   []string{"alice@example.com"},
	}
	err := c.sendWithSenderFallback(context.Background(), "webmaster", "secret", req, []byte("raw"), sendFn)
	if !errors.Is(err, ErrSMTPSenderRejected) {
		t.Fatalf("expected ErrSMTPSenderRejected, got: %v", err)
	}
	if len(attempts) != 2 {
		t.Fatalf("expected 2 attempts, got %d (%v)", len(attempts), attempts)
	}
}

func TestSendWithSenderFallbackNoRetryOnTransportError(t *testing.T) {
	c := &IMAPSMTPClient{}
	var attempts []string
	sendFn := func(ctx context.Context, user, pass, from string, rcpt []string, raw []byte) error {
		attempts = append(attempts, from)
		return errors.New("dial tcp 127.0.0.1:587: connect: connection refused")
	}

	req := SendRequest{
		From: "webmaster@example.com",
		To:   []string{"alice@example.com"},
	}
	err := c.sendWithSenderFallback(context.Background(), "webmaster", "secret", req, []byte("raw"), sendFn)
	if err == nil {
		t.Fatalf("expected transport error")
	}
	if errors.Is(err, ErrSMTPSenderRejected) {
		t.Fatalf("did not expect sender policy classification, got: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt, got %d (%v)", len(attempts), attempts)
	}
}

func TestSendWithSenderFallbackNoRetryWhenAlreadyAuthIdentity(t *testing.T) {
	c := &IMAPSMTPClient{}
	var attempts []string
	sendFn := func(ctx context.Context, user, pass, from string, rcpt []string, raw []byte) error {
		attempts = append(attempts, from)
		return errors.New("sender address rejected")
	}

	req := SendRequest{
		From: "webmaster",
		To:   []string{"alice@example.com"},
	}
	err := c.sendWithSenderFallback(context.Background(), "webmaster", "secret", req, []byte("raw"), sendFn)
	if !errors.Is(err, ErrSMTPSenderRejected) {
		t.Fatalf("expected ErrSMTPSenderRejected, got: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt, got %d (%v)", len(attempts), attempts)
	}
}
