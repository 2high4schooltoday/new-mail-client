package captcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"mailclient/internal/config"
)

var (
	ErrCaptchaRequired    = errors.New("captcha_required")
	ErrCaptchaUnavailable = errors.New("captcha_unavailable")
)

type Verifier interface {
	Verify(ctx context.Context, token, remoteIP string) error
}

type NoopVerifier struct{}

func (NoopVerifier) Verify(ctx context.Context, token, remoteIP string) error { return nil }

type HTTPVerifier struct {
	provider  string
	verifyURL string
	secret    string
	client    *http.Client
}

func NewVerifier(cfg config.Config) Verifier {
	if !cfg.CaptchaEnabled {
		return NoopVerifier{}
	}
	return &HTTPVerifier{
		provider:  strings.TrimSpace(cfg.CaptchaProvider),
		verifyURL: strings.TrimSpace(cfg.CaptchaVerifyURL),
		secret:    strings.TrimSpace(cfg.CaptchaSecret),
		client:    &http.Client{Timeout: 8 * time.Second},
	}
}

type verifyResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
	Error      string   `json:"error"`
	Message    string   `json:"message"`
}

func (v *HTTPVerifier) Verify(ctx context.Context, token, remoteIP string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("%w: captcha token is required", ErrCaptchaRequired)
	}
	provider := strings.ToLower(strings.TrimSpace(v.provider))
	if provider == "" || provider == "turnstile" || provider == "hcaptcha" {
		return v.verifyFormEncoded(ctx, token, remoteIP)
	}
	if provider == "cap" {
		return v.verifyCAP(ctx, token, remoteIP)
	}
	return fmt.Errorf("%w: unsupported captcha provider %q", ErrCaptchaUnavailable, provider)
}

func (v *HTTPVerifier) verifyFormEncoded(ctx context.Context, token, remoteIP string) error {
	form := url.Values{}
	form.Set("secret", v.secret)
	form.Set("response", token)
	if strings.TrimSpace(remoteIP) != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCaptchaUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return v.doVerifyRequest(req, false)
}

func (v *HTTPVerifier) verifyCAP(ctx context.Context, token, remoteIP string) error {
	payload := map[string]string{
		"secret":   v.secret,
		"response": token,
	}
	if strings.TrimSpace(remoteIP) != "" {
		payload["remoteip"] = strings.TrimSpace(remoteIP)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCaptchaUnavailable, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCaptchaUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/json")
	return v.doVerifyRequest(req, true)
}

func (v *HTTPVerifier) doVerifyRequest(req *http.Request, capProvider bool) error {
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCaptchaUnavailable, err)
	}
	defer resp.Body.Close()
	if capProvider && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return fmt.Errorf("%w: captcha verify HTTP %d", ErrCaptchaUnavailable, resp.StatusCode)
	}
	if resp.StatusCode >= 500 {
		return fmt.Errorf("%w: captcha verify HTTP %d", ErrCaptchaUnavailable, resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: captcha verify HTTP %d", ErrCaptchaRequired, resp.StatusCode)
	}

	var out verifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("%w: %v", ErrCaptchaUnavailable, err)
	}
	if !out.Success {
		if capProvider && strings.TrimSpace(out.Error) != "" {
			return fmt.Errorf("%w: %s", ErrCaptchaRequired, out.Error)
		}
		if capProvider && strings.TrimSpace(out.Message) != "" {
			return fmt.Errorf("%w: %s", ErrCaptchaRequired, out.Message)
		}
		if len(out.ErrorCodes) > 0 {
			return fmt.Errorf("%w: captcha rejected: %s", ErrCaptchaRequired, strings.Join(out.ErrorCodes, ","))
		}
		return fmt.Errorf("%w: captcha rejected", ErrCaptchaRequired)
	}
	return nil
}
