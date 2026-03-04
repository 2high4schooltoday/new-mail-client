CREATE TABLE IF NOT EXISTS quota_cache (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  used_bytes INTEGER NOT NULL DEFAULT 0,
  total_bytes INTEGER NOT NULL DEFAULT 0,
  used_messages INTEGER NOT NULL DEFAULT 0,
  total_messages INTEGER NOT NULL DEFAULT 0,
  refreshed_at DATETIME NOT NULL,
  last_error TEXT,
  FOREIGN KEY(account_id) REFERENCES mail_accounts(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_quota_cache_account ON quota_cache(account_id);

CREATE TABLE IF NOT EXISTS mailsec_health (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'unknown',
  version TEXT NOT NULL DEFAULT '',
  checked_at DATETIME NOT NULL,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS remote_image_allowlist (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  message_id TEXT NOT NULL DEFAULT '',
  sender TEXT NOT NULL DEFAULT '',
  created_at DATETIME NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_remote_image_allow_user ON remote_image_allowlist(user_id, sender, message_id);
