CREATE TABLE IF NOT EXISTS sync_state (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  mailbox TEXT NOT NULL,
  uid_validity INTEGER NOT NULL DEFAULT 0,
  uid_next INTEGER NOT NULL DEFAULT 0,
  mod_seq INTEGER NOT NULL DEFAULT 0,
  last_full_sync_at DATETIME,
  last_delta_sync_at DATETIME,
  last_error TEXT,
  updated_at DATETIME NOT NULL,
  FOREIGN KEY(account_id) REFERENCES mail_accounts(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_sync_state_account_mailbox ON sync_state(account_id, mailbox);
