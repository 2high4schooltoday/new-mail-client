package captcha

import (
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

type Verifier interface {
	Verify(ctx context.Context, token, remoteIP string) error
}

type NoopVerifier struct{}

func (NoopVerifier) Verify(ctx context.Context, token, remoteIP string) error { return nil }

type HTTPVerifier struct {
	verifyURL string
	secret    string
	client    *http.Client
}

func NewVerifier(cfg config.Config) Verifier {
	if !cfg.CaptchaEnabled {
		return NoopVerifier{}
	}
	return &HTTPVerifier{
		verifyURL: strings.TrimSpace(cfg.CaptchaVerifyURL),
		secret:    strings.TrimSpace(cfg.CaptchaSecret),
		client:    &http.Client{Timeout: 8 * time.Second},
	}
}

type verifyResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

func (v *HTTPVerifier) Verify(ctx context.Context, token, remoteIP string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("captcha token is required")
	}

	form := url.Values{}
	form.Set("secret", v.secret)
	form.Set("response", token)
	if strings.TrimSpace(remoteIP) != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("captcha verify HTTP %d", resp.StatusCode)
	}

	var out verifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if !out.Success {
		if len(out.ErrorCodes) > 0 {
			return fmt.Errorf("captcha rejected: %s", strings.Join(out.ErrorCodes, ","))
		}
		return errors.New("captcha rejected")
	}
	return nil
}
