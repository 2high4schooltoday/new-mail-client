package notify

import (
	"context"
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
	log.Printf("password reset token generated for %s token=%s link=%s", toEmail, token, link)
	return nil
}

type SMTPSender struct {
	host    string
	port    int
	from    string
	baseURL string
}

func NewSender(cfg config.Config) Sender {
	switch cfg.PasswordResetSender {
	case "smtp":
		return SMTPSender{
			host:    cfg.SMTPHost,
			port:    cfg.SMTPPort,
			from:    cfg.PasswordResetFrom,
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
	} else {
		link = token
	}
	body := "Subject: Password Reset\r\n\r\nUse this link to reset your password:\r\n" + link + "\r\n"
	return smtp.SendMail(addr, nil, s.from, []string{toEmail}, []byte(body))
}
