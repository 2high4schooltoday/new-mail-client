CREATE TABLE IF NOT EXISTS sieve_profiles (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 4190,
  tls INTEGER NOT NULL DEFAULT 1,
  login TEXT NOT NULL DEFAULT '',
  secret_enc TEXT NOT NULL DEFAULT '',
  active_script TEXT NOT NULL DEFAULT '',
  last_sync_at DATETIME,
  last_error TEXT,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  FOREIGN KEY(account_id) REFERENCES mail_accounts(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sieve_profiles_account ON sieve_profiles(account_id);

CREATE TABLE IF NOT EXISTS sieve_cache (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  script_name TEXT NOT NULL,
  script_body TEXT NOT NULL DEFAULT '',
  checksum_sha256 TEXT NOT NULL DEFAULT '',
  is_active INTEGER NOT NULL DEFAULT 0,
  source TEXT NOT NULL DEFAULT 'cache',
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  FOREIGN KEY(account_id) REFERENCES mail_accounts(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sieve_cache_unique_script ON sieve_cache(account_id, script_name);
CREATE INDEX IF NOT EXISTS idx_sieve_cache_active ON sieve_cache(account_id, is_active);
