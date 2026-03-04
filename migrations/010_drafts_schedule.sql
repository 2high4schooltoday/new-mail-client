CREATE TABLE IF NOT EXISTS drafts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  identity_id TEXT NOT NULL DEFAULT '',
  to_value TEXT NOT NULL DEFAULT '',
  cc_value TEXT NOT NULL DEFAULT '',
  bcc_value TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  body_text TEXT NOT NULL DEFAULT '',
  body_html TEXT NOT NULL DEFAULT '',
  attachments_json TEXT NOT NULL DEFAULT '[]',
  crypto_options_json TEXT NOT NULL DEFAULT '{}',
  send_mode TEXT NOT NULL DEFAULT 'manual',
  scheduled_for DATETIME,
  status TEXT NOT NULL DEFAULT 'draft',
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(account_id) REFERENCES mail_accounts(id)
);

CREATE INDEX IF NOT EXISTS idx_drafts_user ON drafts(user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_drafts_account ON drafts(account_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS draft_versions (
  id TEXT PRIMARY KEY,
  draft_id TEXT NOT NULL,
  version_no INTEGER NOT NULL,
  snapshot_json TEXT NOT NULL,
  created_at DATETIME NOT NULL,
  FOREIGN KEY(draft_id) REFERENCES drafts(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_draft_versions_unique ON draft_versions(draft_id, version_no);
CREATE INDEX IF NOT EXISTS idx_draft_versions_created ON draft_versions(draft_id, created_at DESC);

CREATE TABLE IF NOT EXISTS scheduled_send_queue (
  id TEXT PRIMARY KEY,
  draft_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  due_at DATETIME NOT NULL,
  state TEXT NOT NULL DEFAULT 'queued',
  retry_count INTEGER NOT NULL DEFAULT 0,
  next_retry_at DATETIME,
  last_error TEXT,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  FOREIGN KEY(draft_id) REFERENCES drafts(id),
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(account_id) REFERENCES mail_accounts(id)
);

CREATE INDEX IF NOT EXISTS idx_scheduled_send_due ON scheduled_send_queue(state, due_at, next_retry_at);
