package config

import (
	"fmt"
	"net/http"
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
	CookieSecureMode    string
	CookiePolicyWarning string
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

	UpdateEnabled          bool
	UpdateRepoOwner        string
	UpdateRepoName         string
	UpdateCheckIntervalMin int
	UpdateHTTPTimeoutSec   int
	UpdateGitHubToken      string
	UpdateBackupKeep       int
	UpdateBaseDir          string
	UpdateInstallDir       string
	UpdateServiceName      string
	UpdateSystemdUnitDir   string
}

func Load() (Config, error) {
	cookieSecureLegacy, cookieSecureLegacySet := envBoolWithSet("COOKIE_SECURE", false)
	cookieSecureMode := strings.ToLower(strings.TrimSpace(os.Getenv("COOKIE_SECURE_MODE")))
	if cookieSecureMode == "" {
		if cookieSecureLegacySet {
			if cookieSecureLegacy {
				cookieSecureMode = "always"
			} else {
				cookieSecureMode = "never"
			}
		} else {
			cookieSecureMode = "auto"
		}
	}
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
		CookieSecure:             cookieSecureLegacy,
		CookieSecureMode:         cookieSecureMode,
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
		UpdateEnabled:            envBool("UPDATE_ENABLED", true),
		UpdateRepoOwner:          env("UPDATE_REPO_OWNER", "2high4schooltoday"),
		UpdateRepoName:           env("UPDATE_REPO_NAME", "new-mail-client"),
		UpdateCheckIntervalMin:   envInt("UPDATE_CHECK_INTERVAL_MIN", 60),
		UpdateHTTPTimeoutSec:     envInt("UPDATE_HTTP_TIMEOUT_SEC", 10),
		UpdateGitHubToken:        env("UPDATE_GITHUB_TOKEN", ""),
		UpdateBackupKeep:         envInt("UPDATE_BACKUP_KEEP", 3),
		UpdateBaseDir:            env("UPDATE_BASE_DIR", "/var/lib/mailclient/update"),
		UpdateInstallDir:         env("UPDATE_INSTALL_DIR", "/opt/mailclient"),
		UpdateServiceName:        env("UPDATE_SERVICE_NAME", "mailclient"),
		UpdateSystemdUnitDir:     env("UPDATE_SYSTEMD_UNIT_DIR", "/etc/systemd/system"),
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
	switch cfg.CookieSecureMode {
	case "auto", "always", "never":
	default:
		return Config{}, fmt.Errorf("COOKIE_SECURE_MODE must be one of: auto, always, never")
	}
	cfg.CookieSecure = cfg.CookieSecureMode == "always"
	if cfg.CookieSecureMode == "never" && isPotentiallyPublicListen(cfg.ListenAddr) {
		cfg.CookiePolicyWarning = "COOKIE_SECURE_MODE=never with a potentially public LISTEN_ADDR may expose cookies on plaintext HTTP"
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
	if cfg.UpdateCheckIntervalMin <= 0 {
		return Config{}, fmt.Errorf("UPDATE_CHECK_INTERVAL_MIN must be positive")
	}
	if cfg.UpdateHTTPTimeoutSec <= 0 {
		return Config{}, fmt.Errorf("UPDATE_HTTP_TIMEOUT_SEC must be positive")
	}
	if cfg.UpdateBackupKeep < 1 {
		return Config{}, fmt.Errorf("UPDATE_BACKUP_KEEP must be >= 1")
	}
	if strings.TrimSpace(cfg.UpdateRepoOwner) == "" || strings.TrimSpace(cfg.UpdateRepoName) == "" {
		return Config{}, fmt.Errorf("UPDATE_REPO_OWNER and UPDATE_REPO_NAME are required")
	}
	if strings.TrimSpace(cfg.UpdateBaseDir) == "" {
		return Config{}, fmt.Errorf("UPDATE_BASE_DIR is required")
	}
	if strings.TrimSpace(cfg.UpdateInstallDir) == "" {
		return Config{}, fmt.Errorf("UPDATE_INSTALL_DIR is required")
	}
	if strings.TrimSpace(cfg.UpdateServiceName) == "" {
		return Config{}, fmt.Errorf("UPDATE_SERVICE_NAME is required")
	}
	if strings.TrimSpace(cfg.UpdateSystemdUnitDir) == "" {
		return Config{}, fmt.Errorf("UPDATE_SYSTEMD_UNIT_DIR is required")
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
	b, set := envBoolWithSet(k, d)
	if !set {
		return d
	}
	return b
}

func envBoolWithSet(k string, d bool) (bool, bool) {
	v := os.Getenv(k)
	if v == "" {
		return d, false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return d, true
	}
	return b, true
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

func isLoopbackListen(addr string) bool {
	a := strings.ToLower(strings.TrimSpace(addr))
	return strings.Contains(a, "127.0.0.1") || strings.Contains(a, "localhost") || strings.Contains(a, "[::1]")
}

func isPotentiallyPublicListen(addr string) bool {
	a := strings.ToLower(strings.TrimSpace(addr))
	if a == "" {
		return false
	}
	if strings.HasPrefix(a, ":") || strings.Contains(a, "0.0.0.0") {
		return true
	}
	if strings.Contains(a, "[::]") || a == "::" {
		return true
	}
	return !isLoopbackListen(a)
}

func (c Config) ResolveCookieSecure(r *http.Request) bool {
	switch c.CookieSecureMode {
	case "always":
		return true
	case "never":
		return false
	case "auto":
		if r == nil {
			return false
		}
		if r.TLS != nil {
			return true
		}
		if c.TrustProxy {
			proto := forwardedProto(r.Header.Get("X-Forwarded-Proto"))
			return proto == "https"
		}
		return false
	default:
		return c.CookieSecure
	}
}

func forwardedProto(v string) string {
	p := strings.TrimSpace(strings.ToLower(v))
	if p == "" {
		return ""
	}
	if strings.Contains(p, ",") {
		p = strings.TrimSpace(strings.Split(p, ",")[0])
	}
	if strings.Contains(p, ";") {
		p = strings.TrimSpace(strings.Split(p, ";")[0])
	}
	return p
}
