CREATE TABLE IF NOT EXISTS mail_accounts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  login TEXT NOT NULL,
  secret_enc TEXT NOT NULL,
  imap_host TEXT NOT NULL,
  imap_port INTEGER NOT NULL,
  imap_tls INTEGER NOT NULL DEFAULT 1,
  imap_starttls INTEGER NOT NULL DEFAULT 0,
  smtp_host TEXT NOT NULL,
  smtp_port INTEGER NOT NULL,
  smtp_tls INTEGER NOT NULL DEFAULT 0,
  smtp_starttls INTEGER NOT NULL DEFAULT 1,
  is_default INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active',
  last_sync_at DATETIME,
  last_error TEXT,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_mail_accounts_user ON mail_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_mail_accounts_default ON mail_accounts(user_id, is_default);

CREATE TABLE IF NOT EXISTS mail_identities (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  from_email TEXT NOT NULL,
  reply_to TEXT NOT NULL DEFAULT '',
  signature_text TEXT NOT NULL DEFAULT '',
  signature_html TEXT NOT NULL DEFAULT '',
  is_default INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  FOREIGN KEY(account_id) REFERENCES mail_accounts(id)
);

CREATE INDEX IF NOT EXISTS idx_mail_identities_account ON mail_identities(account_id);
CREATE INDEX IF NOT EXISTS idx_mail_identities_default ON mail_identities(account_id, is_default);

CREATE TABLE IF NOT EXISTS mailbox_mappings (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  role TEXT NOT NULL,
  mailbox_name TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'manual',
  priority INTEGER NOT NULL DEFAULT 100,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  FOREIGN KEY(account_id) REFERENCES mail_accounts(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_mailbox_mappings_role_unique ON mailbox_mappings(account_id, role, mailbox_name);
CREATE INDEX IF NOT EXISTS idx_mailbox_mappings_priority ON mailbox_mappings(account_id, role, priority);
