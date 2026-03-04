CREATE TABLE IF NOT EXISTS crypto_keyrings (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  account_id TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  user_ids_json TEXT NOT NULL DEFAULT '[]',
  public_key TEXT NOT NULL DEFAULT '',
  private_key_enc TEXT NOT NULL DEFAULT '',
  passphrase_hint TEXT NOT NULL DEFAULT '',
  expires_at DATETIME,
  trust_level TEXT NOT NULL DEFAULT 'unknown',
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_crypto_keyrings_fingerprint ON crypto_keyrings(user_id, fingerprint);

CREATE TABLE IF NOT EXISTS crypto_trust_policies (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  account_id TEXT NOT NULL DEFAULT '',
  sender_pattern TEXT NOT NULL,
  domain_pattern TEXT NOT NULL DEFAULT '',
  min_trust_level TEXT NOT NULL DEFAULT 'unknown',
  require_signed INTEGER NOT NULL DEFAULT 0,
  require_encrypted INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_crypto_trust_user ON crypto_trust_policies(user_id, account_id);
