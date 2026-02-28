package mail

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"time"

	"mailclient/internal/config"
)

func ProbeIMAP(ctx context.Context, cfg config.Config) error {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	addr := net.JoinHostPort(cfg.IMAPHost, strconv.Itoa(cfg.IMAPPort))
	tlsCfg := &tls.Config{ServerName: cfg.IMAPHost, InsecureSkipVerify: cfg.IMAPInsecureSkipVerify}

	if cfg.IMAPTLS {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		if err != nil {
			return err
		}
		_ = conn.Close()
		return nil
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func ProbeSMTP(ctx context.Context, cfg config.Config) error {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	addr := net.JoinHostPort(cfg.SMTPHost, strconv.Itoa(cfg.SMTPPort))
	tlsCfg := &tls.Config{ServerName: cfg.SMTPHost, InsecureSkipVerify: cfg.SMTPInsecureSkipVerify}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	if cfg.SMTPTLS {
		conn = tls.Client(conn, tlsCfg)
	}

	client, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		return err
	}
	defer client.Close()

	if cfg.SMTPStartTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsCfg); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("SMTP STARTTLS extension not available")
		}
	}
	return client.Quit()
}
