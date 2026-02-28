package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr string
	BaseDomain string

	DBPath            string
	DBMaxOpenConns    int
	DBMaxIdleConns    int
	DBConnMaxLifetime time.Duration

	SessionCookieName   string
	SessionIdleMinutes  int
	SessionAbsoluteHour int
	SessionEncryptKey   string
	CSRFCookieName      string
	CookieSecure        bool
	TrustProxy          bool
	CORSAllowedOrigins  []string

	CaptchaEnabled   bool
	CaptchaProvider  string
	CaptchaVerifyURL string
	CaptchaSecret    string

	PasswordMinLength int
	PasswordMaxLength int

	IMAPHost               string
	IMAPPort               int
	IMAPTLS                bool
	IMAPStartTLS           bool
	IMAPInsecureSkipVerify bool

	SMTPHost               string
	SMTPPort               int
	SMTPTLS                bool
	SMTPStartTLS           bool
	SMTPInsecureSkipVerify bool

	DovecotAuthDBDriver  string
	DovecotAuthDBDSN     string
	DovecotAuthMode      string
	DovecotAuthTable     string
	DovecotEmailColumn   string
	DovecotPassColumn    string
	DovecotActiveColumn  string
	DovecotMaildirColumn string
	DovecotMaildirBase   string

	HTTPReadTimeoutSec       int
	HTTPReadHeaderTimeoutSec int
	HTTPWriteTimeoutSec      int
	HTTPIdleTimeoutSec       int

	BootstrapAdminEmail    string
	BootstrapAdminPassword string

	PasswordResetSender  string
	PasswordResetFrom    string
	PasswordResetBaseURL string
}

func Load() (Config, error) {
	cfg := Config{
		ListenAddr:               env("LISTEN_ADDR", ":8080"),
		BaseDomain:               env("BASE_DOMAIN", "example.com"),
		DBPath:                   env("APP_DB_PATH", "./data/app.db"),
		DBMaxOpenConns:           envInt("APP_DB_MAX_OPEN_CONNS", 4),
		DBMaxIdleConns:           envInt("APP_DB_MAX_IDLE_CONNS", 2),
		DBConnMaxLifetime:        time.Duration(envInt("APP_DB_CONN_MAX_LIFETIME_MIN", 30)) * time.Minute,
		SessionCookieName:        env("SESSION_COOKIE_NAME", "mailclient_session"),
		SessionIdleMinutes:       envInt("SESSION_IDLE_MINUTES", 30),
		SessionAbsoluteHour:      envInt("SESSION_ABSOLUTE_HOURS", 24),
		SessionEncryptKey:        env("SESSION_ENCRYPT_KEY", "CHANGE_ME_PRODUCTION_SESSION_KEY"),
		CSRFCookieName:           env("CSRF_COOKIE_NAME", "mailclient_csrf"),
		CookieSecure:             envBool("COOKIE_SECURE", false),
		TrustProxy:               envBool("TRUST_PROXY", false),
		CORSAllowedOrigins:       envCSV("CORS_ALLOWED_ORIGINS"),
		CaptchaEnabled:           envBool("CAPTCHA_ENABLED", false),
		CaptchaProvider:          strings.ToLower(env("CAPTCHA_PROVIDER", "turnstile")),
		CaptchaVerifyURL:         env("CAPTCHA_VERIFY_URL", ""),
		CaptchaSecret:            env("CAPTCHA_SECRET", ""),
		PasswordMinLength:        envInt("PASSWORD_MIN_LENGTH", 12),
		PasswordMaxLength:        envInt("PASSWORD_MAX_LENGTH", 128),
		IMAPHost:                 env("IMAP_HOST", "127.0.0.1"),
		IMAPPort:                 envInt("IMAP_PORT", 993),
		IMAPTLS:                  envBool("IMAP_TLS", true),
		IMAPStartTLS:             envBool("IMAP_STARTTLS", false),
		IMAPInsecureSkipVerify:   envBool("IMAP_INSECURE_SKIP_VERIFY", false),
		SMTPHost:                 env("SMTP_HOST", "127.0.0.1"),
		SMTPPort:                 envInt("SMTP_PORT", 587),
		SMTPTLS:                  envBool("SMTP_TLS", false),
		SMTPStartTLS:             envBool("SMTP_STARTTLS", true),
		SMTPInsecureSkipVerify:   envBool("SMTP_INSECURE_SKIP_VERIFY", false),
		DovecotAuthMode:          strings.ToLower(env("DOVECOT_AUTH_MODE", "sql")),
		DovecotAuthDBDriver:      env("DOVECOT_AUTH_DB_DRIVER", ""),
		DovecotAuthDBDSN:         env("DOVECOT_AUTH_DB_DSN", ""),
		DovecotAuthTable:         env("DOVECOT_AUTH_TABLE", "users"),
		DovecotEmailColumn:       env("DOVECOT_AUTH_EMAIL_COL", "email"),
		DovecotPassColumn:        env("DOVECOT_AUTH_PASS_COL", "password_hash"),
		DovecotActiveColumn:      env("DOVECOT_AUTH_ACTIVE_COL", "active"),
		DovecotMaildirColumn:     env("DOVECOT_AUTH_MAILDIR_COL", "maildir"),
		DovecotMaildirBase:       env("DOVECOT_MAILDIR_BASE", "/var/mail/vhosts"),
		HTTPReadTimeoutSec:       envInt("HTTP_READ_TIMEOUT_SEC", 10),
		HTTPReadHeaderTimeoutSec: envInt("HTTP_READ_HEADER_TIMEOUT_SEC", 5),
		HTTPWriteTimeoutSec:      envInt("HTTP_WRITE_TIMEOUT_SEC", 30),
		HTTPIdleTimeoutSec:       envInt("HTTP_IDLE_TIMEOUT_SEC", 60),
		BootstrapAdminEmail:      env("BOOTSTRAP_ADMIN_EMAIL", ""),
		BootstrapAdminPassword:   env("BOOTSTRAP_ADMIN_PASSWORD", ""),
		PasswordResetSender:      strings.ToLower(env("PASSWORD_RESET_SENDER", "log")),
		PasswordResetFrom:        env("PASSWORD_RESET_FROM", "webmaster@example.com"),
		PasswordResetBaseURL:     env("PASSWORD_RESET_BASE_URL", ""),
	}

	if cfg.SessionIdleMinutes <= 0 || cfg.SessionAbsoluteHour <= 0 {
		return Config{}, fmt.Errorf("session timeouts must be positive")
	}
	if cfg.DBMaxOpenConns <= 0 || cfg.DBMaxIdleConns < 0 {
		return Config{}, fmt.Errorf("invalid DB pool config")
	}
	if cfg.IMAPPort <= 0 || cfg.SMTPPort <= 0 {
		return Config{}, fmt.Errorf("invalid mail host port")
	}
	if cfg.PasswordMinLength < 8 {
		return Config{}, fmt.Errorf("password min length must be >= 8")
	}
	if cfg.PasswordMaxLength < cfg.PasswordMinLength {
		return Config{}, fmt.Errorf("password max length must be >= min length")
	}
	switch cfg.DovecotAuthMode {
	case "", "sql", "pam":
		if cfg.DovecotAuthMode == "" {
			cfg.DovecotAuthMode = "sql"
		}
	default:
		return Config{}, fmt.Errorf("DOVECOT_AUTH_MODE must be one of: sql, pam")
	}
	if strings.TrimSpace(cfg.SessionEncryptKey) == "" ||
		cfg.SessionEncryptKey == "CHANGE_ME_PRODUCTION_SESSION_KEY" ||
		len(cfg.SessionEncryptKey) < 24 {
		return Config{}, fmt.Errorf("SESSION_ENCRYPT_KEY must be set to a strong non-default value (>=24 chars)")
	}
	if !cfg.CookieSecure && !isLocalListen(cfg.ListenAddr) {
		return Config{}, fmt.Errorf("COOKIE_SECURE=false is allowed only for local listen addresses")
	}
	if cfg.CaptchaEnabled {
		if strings.TrimSpace(cfg.CaptchaSecret) == "" {
			return Config{}, fmt.Errorf("CAPTCHA_SECRET is required when CAPTCHA_ENABLED=true")
		}
		if strings.TrimSpace(cfg.CaptchaVerifyURL) == "" {
			switch cfg.CaptchaProvider {
			case "turnstile", "":
				cfg.CaptchaVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
			case "hcaptcha":
				cfg.CaptchaVerifyURL = "https://hcaptcha.com/siteverify"
			default:
				return Config{}, fmt.Errorf("unsupported CAPTCHA_PROVIDER: %s", cfg.CaptchaProvider)
			}
		}
	}
	return cfg, nil
}

func (c Config) SessionIdleDuration() time.Duration {
	return time.Duration(c.SessionIdleMinutes) * time.Minute
}

func (c Config) SessionAbsoluteDuration() time.Duration {
	return time.Duration(c.SessionAbsoluteHour) * time.Hour
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envInt(k string, d int) int {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return d
	}
	return n
}

func envBool(k string, d bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return d
	}
	return b
}

func envCSV(k string) []string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isLocalListen(addr string) bool {
	a := strings.ToLower(strings.TrimSpace(addr))
	return strings.Contains(a, "127.0.0.1") || strings.Contains(a, "localhost") || strings.Contains(a, "[::1]") || strings.HasPrefix(a, ":")
}
