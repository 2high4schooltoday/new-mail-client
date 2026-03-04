ALTER TABLE users ADD COLUMN mfa_backup_completed INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS mfa_trusted_devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  ua_hash TEXT NOT NULL DEFAULT '',
  ip_hint TEXT NOT NULL DEFAULT '',
  device_label TEXT NOT NULL DEFAULT '',
  created_at DATETIME NOT NULL,
  last_used_at DATETIME,
  expires_at DATETIME NOT NULL,
  revoked_at DATETIME,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_mfa_trusted_user ON mfa_trusted_devices(user_id, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_mfa_trusted_active ON mfa_trusted_devices(user_id, revoked_at, expires_at);
