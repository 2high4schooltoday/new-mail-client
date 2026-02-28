# U.S. Mail Office (Go)

Lightweight self-hosted webmail and admin system for existing Postfix + Dovecot + Maildir infrastructure.

## Implemented
- Single-binary Go server with REST API + web UI.
- Registration with manual admin approval workflow.
- Unified auth model with Argon2id password hashing.
- Session cookies + CSRF protection for mutating routes.
- Startup safety checks for session key strength, cookie security, and CAPTCHA config.
- Admin user lifecycle controls: approve/reject/suspend/unsuspend/reset password.
- Password reset token flow.
- Audit log endpoint + admin UI table.
- Real IMAP integration (list/search/read/flags/move).
- Real SMTP submission with optional STARTTLS/TLS and attachment send.
- Dovecot auth SQL provisioning adapter (MySQL/Postgres via `database/sql`).
- SQLite app DB with WAL mode and conservative pool sizing for low-resource ARM hosts.
- Nginx/Apache2 and systemd deployment templates.

## ARM optimization defaults
- SQLite pool defaults: `max_open=4`, `max_idle=2`.
- HTTP timeouts configured with low overhead defaults.
- API pagination hard-capped (`page_size <= 100`).
- In-memory limiter bucket cleanup to avoid unbounded growth.
- Persistent failed-login counters in SQLite `rate_limit_events`.
- No heavy background workers.

## Quick start
1. Run interactive installer:
   - `./scripts/auto_install.sh`
2. Open:
   - `http://<server-ip>:8080`
3. Complete web OOBE:
   - Choose region
   - Set domain
   - Create admin account (default suggestion: `webmaster@{domain}`)

## Auto installer (recommended)
Interactive, prompt-driven installer (no CLI arguments). Validated for Ubuntu Server on:
- ARM64 (`aarch64` / `arm64`)
- x86-64 (`x86_64` / `amd64`)

Run:
- `./scripts/auto_install.sh`

Standalone mode (run from any Linux server path):
- download `scripts/auto_install.sh` and run it
- if app sources are not present next to the script, it will:
  - prompt for GitHub repo/ref
  - clone/pull the repository automatically
  - install missing dependencies on Ubuntu/Debian with `apt` (interactive confirmation)
  - continue normal interactive install flow

What it auto-detects:
- Dovecot SQL config (`dovecot-sql.conf.ext`)
- SQL driver / connect hints / auth table + columns
- localhost IMAP/SMTP ports and TLS mode hints
- sensible default domain from host (`/etc/mailname` or FQDN)
- installed reverse proxy (`nginx` or `apache2`) and can configure it automatically

What is intentionally deferred to web UI OOBE:
- Admin email/password creation
- Final first-run setup confirmation

Note: fully custom SQL/auth setups may still need manual `.env` tweaks.

## Dovecot provisioning notes
Set `DOVECOT_AUTH_DB_DRIVER` and `DOVECOT_AUTH_DB_DSN` to enable automatic writes to your Dovecot auth DB.

Supported drivers:
- `mysql`
- `pgx` (PostgreSQL)

Adjust table/column env vars if your auth schema differs.

## API
Base: `/api/v1`

- Auth/registration:
  - `GET /setup/status`
  - `POST /setup/complete`
  - `POST /register`
  - `POST /login`
  - `POST /logout`
  - `POST /password/reset/request`
  - `POST /password/reset/confirm`
- User mail:
  - `GET /me`
  - `GET /mailboxes`
  - `GET /messages`
  - `GET /messages/{id}`
  - `POST /messages/send`
  - `POST /messages/{id}/reply`
  - `POST /messages/{id}/forward`
  - `POST /messages/{id}/flags`
  - `POST /messages/{id}/move`
  - `GET /search`
  - `GET /attachments/{id}`
- Admin:
  - `GET /admin/registrations`
  - `POST /admin/registrations/{id}/approve`
  - `POST /admin/registrations/{id}/reject`
  - `GET /admin/users`
  - `POST /admin/users/{id}/suspend`
  - `POST /admin/users/{id}/unsuspend`
  - `POST /admin/users/{id}/reset-password`
  - `GET /admin/audit-log`
  - `GET /admin/system/mail-health`
  - `POST /admin/users/{id}/retry-provision`

## Test
- `go test ./...`
- `./scripts/check_warm_palette.sh`

## Security behavior updates
- Password reset request endpoint no longer returns raw reset tokens.
- CAPTCHA (when enabled) is server-verified.
- CORS now uses explicit allowlist via `CORS_ALLOWED_ORIGINS`.
