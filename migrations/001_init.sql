PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  status TEXT NOT NULL CHECK (status IN ('pending','active','suspended','rejected')),
  provision_state TEXT NOT NULL DEFAULT 'pending',
  provision_error TEXT,
  created_at DATETIME NOT NULL,
  approved_at DATETIME,
  approved_by TEXT,
  last_login_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

CREATE TABLE IF NOT EXISTS registrations (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  source_ip TEXT,
  user_agent_hash TEXT,
  captcha_ok INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected')),
  created_at DATETIME NOT NULL,
  decided_at DATETIME,
  decided_by TEXT,
  reason TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_registrations_email_pending
ON registrations(email, status);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  mail_secret TEXT NOT NULL DEFAULT '',
  ip_hint TEXT,
  user_agent_hash TEXT,
  expires_at DATETIME NOT NULL,
  idle_expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL,
  last_seen_at DATETIME NOT NULL,
  revoked_at DATETIME,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS admin_audit_log (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  metadata_json TEXT,
  created_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_created_at ON admin_audit_log(created_at);

CREATE TABLE IF NOT EXISTS rate_limit_events (
  id TEXT PRIMARY KEY,
  key TEXT NOT NULL,
  route TEXT NOT NULL,
  window_start DATETIME NOT NULL,
  count INTEGER NOT NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rate_key_route_window
ON rate_limit_events(key, route, window_start);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at DATETIME NOT NULL,
  used_at DATETIME,
  created_at DATETIME NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_password_reset_expires ON password_reset_tokens(expires_at);
