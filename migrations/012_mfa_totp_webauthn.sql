CREATE TABLE IF NOT EXISTS mfa_totp (
  user_id TEXT PRIMARY KEY,
  secret_enc TEXT NOT NULL DEFAULT '',
  issuer TEXT NOT NULL DEFAULT 'Despatch',
  account_name TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 0,
  enrolled_at DATETIME,
  updated_at DATETIME NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS mfa_webauthn_credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  transports_json TEXT NOT NULL DEFAULT '[]',
  name TEXT NOT NULL DEFAULT '',
  created_at DATETIME NOT NULL,
  last_used_at DATETIME,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credential_id ON mfa_webauthn_credentials(credential_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON mfa_webauthn_credentials(user_id);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  used_at DATETIME,
  created_at DATETIME NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user ON mfa_recovery_codes(user_id);

ALTER TABLE sessions ADD COLUMN mfa_verified_at DATETIME;
ALTER TABLE sessions ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'password';
ALTER TABLE sessions ADD COLUMN active_account_id TEXT;
