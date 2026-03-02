package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/smtp"
	"strings"

	"mailclient/internal/config"
)

type Sender interface {
	SendPasswordReset(ctx context.Context, toEmail, token string) error
}

type LogSender struct {
	baseURL string
}

func (s LogSender) SendPasswordReset(ctx context.Context, toEmail, token string) error {
	_ = ctx
	link := strings.TrimRight(s.baseURL, "/")
	if link != "" {
		link = fmt.Sprintf("%s/#/reset?token=%s", link, token)
	}
	sum := sha256.Sum256([]byte(token))
	prefix := hex.EncodeToString(sum[:])[:16]
	if link != "" {
		log.Printf("password reset generated for %s token_hash_prefix=%s", toEmail, prefix)
		return nil
	}
	log.Printf("password reset generated for %s token_hash_prefix=%s", toEmail, prefix)
	return nil
}

type SMTPSender struct {
	host    string
	port    int
	from    string
	baseURL string
}

func passwordResetFromAddress(cfg config.Config) string {
	candidate := strings.ToLower(strings.TrimSpace(cfg.PasswordResetFrom))
	if candidate == "" || strings.HasSuffix(candidate, "@example.com") {
		domain := strings.ToLower(strings.TrimSpace(cfg.BaseDomain))
		if domain == "" {
			domain = "example.com"
		}
		candidate = "recovery@" + domain
	}
	return candidate
}

func NewSender(cfg config.Config) Sender {
	switch cfg.PasswordResetSender {
	case "smtp":
		return SMTPSender{
			host:    cfg.SMTPHost,
			port:    cfg.SMTPPort,
			from:    passwordResetFromAddress(cfg),
			baseURL: cfg.PasswordResetBaseURL,
		}
	default:
		return LogSender{baseURL: cfg.PasswordResetBaseURL}
	}
}

func (s SMTPSender) SendPasswordReset(ctx context.Context, toEmail, token string) error {
	_ = ctx
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	link := strings.TrimRight(s.baseURL, "/")
	if link != "" {
		link = fmt.Sprintf("%s/#/reset?token=%s", link, token)
	}
	body := "Subject: Password Reset Token\r\n\r\nUse this token to reset your password:\r\n" + token + "\r\n"
	if link != "" {
		body += "\r\nOr open this link:\r\n" + link + "\r\n"
	}
	return smtp.SendMail(addr, nil, s.from, []string{toEmail}, []byte(body))
}
