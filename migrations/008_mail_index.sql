CREATE TABLE IF NOT EXISTS thread_index (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  mailbox TEXT NOT NULL,
  subject_norm TEXT NOT NULL DEFAULT '',
  participants_json TEXT NOT NULL DEFAULT '[]',
  message_count INTEGER NOT NULL DEFAULT 0,
  unread_count INTEGER NOT NULL DEFAULT 0,
  has_attachments INTEGER NOT NULL DEFAULT 0,
  has_flagged INTEGER NOT NULL DEFAULT 0,
  importance INTEGER NOT NULL DEFAULT 0,
  latest_message_id TEXT NOT NULL DEFAULT '',
  latest_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  FOREIGN KEY(account_id) REFERENCES mail_accounts(id)
);

CREATE INDEX IF NOT EXISTS idx_thread_index_account_mailbox_latest
ON thread_index(account_id, mailbox, latest_at DESC);

CREATE TABLE IF NOT EXISTS message_index (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  mailbox TEXT NOT NULL,
  uid INTEGER NOT NULL,
  thread_id TEXT NOT NULL,
  message_id_header TEXT NOT NULL DEFAULT '',
  in_reply_to_header TEXT NOT NULL DEFAULT '',
  references_header TEXT NOT NULL DEFAULT '',
  from_value TEXT NOT NULL DEFAULT '',
  to_value TEXT NOT NULL DEFAULT '',
  cc_value TEXT NOT NULL DEFAULT '',
  bcc_value TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  snippet TEXT NOT NULL DEFAULT '',
  body_text TEXT NOT NULL DEFAULT '',
  body_html_sanitized TEXT NOT NULL DEFAULT '',
  raw_source TEXT NOT NULL DEFAULT '',
  seen INTEGER NOT NULL DEFAULT 0,
  flagged INTEGER NOT NULL DEFAULT 0,
  answered INTEGER NOT NULL DEFAULT 0,
  draft INTEGER NOT NULL DEFAULT 0,
  has_attachments INTEGER NOT NULL DEFAULT 0,
  importance INTEGER NOT NULL DEFAULT 0,
  dkim_status TEXT NOT NULL DEFAULT 'unknown',
  spf_status TEXT NOT NULL DEFAULT 'unknown',
  dmarc_status TEXT NOT NULL DEFAULT 'unknown',
  phishing_score REAL NOT NULL DEFAULT 0,
  remote_images_blocked INTEGER NOT NULL DEFAULT 1,
  remote_images_allowed INTEGER NOT NULL DEFAULT 0,
  date_header DATETIME NOT NULL,
  internal_date DATETIME NOT NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  FOREIGN KEY(account_id) REFERENCES mail_accounts(id),
  FOREIGN KEY(thread_id) REFERENCES thread_index(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_message_index_account_mailbox_uid
ON message_index(account_id, mailbox, uid);
CREATE INDEX IF NOT EXISTS idx_message_index_thread ON message_index(thread_id, date_header DESC);
CREATE INDEX IF NOT EXISTS idx_message_index_account_mailbox_date ON message_index(account_id, mailbox, date_header DESC);
CREATE INDEX IF NOT EXISTS idx_message_index_flag_seen ON message_index(account_id, mailbox, flagged, seen);

CREATE TABLE IF NOT EXISTS attachment_index (
  id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  filename TEXT NOT NULL DEFAULT '',
  content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
  size_bytes INTEGER NOT NULL DEFAULT 0,
  inline_part INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL,
  FOREIGN KEY(message_id) REFERENCES message_index(id),
  FOREIGN KEY(account_id) REFERENCES mail_accounts(id)
);

CREATE INDEX IF NOT EXISTS idx_attachment_index_message ON attachment_index(message_id);

CREATE VIRTUAL TABLE IF NOT EXISTS message_search_fts USING fts5(
  message_id UNINDEXED,
  account_id UNINDEXED,
  mailbox UNINDEXED,
  thread_id UNINDEXED,
  subject,
  from_value,
  to_value,
  snippet,
  body_text
);

CREATE TRIGGER IF NOT EXISTS trg_message_index_ai AFTER INSERT ON message_index
BEGIN
  INSERT INTO message_search_fts(message_id, account_id, mailbox, thread_id, subject, from_value, to_value, snippet, body_text)
  VALUES (new.id, new.account_id, new.mailbox, new.thread_id, new.subject, new.from_value, new.to_value, new.snippet, new.body_text);
END;

CREATE TRIGGER IF NOT EXISTS trg_message_index_au AFTER UPDATE ON message_index
BEGIN
  DELETE FROM message_search_fts WHERE message_id = old.id;
  INSERT INTO message_search_fts(message_id, account_id, mailbox, thread_id, subject, from_value, to_value, snippet, body_text)
  VALUES (new.id, new.account_id, new.mailbox, new.thread_id, new.subject, new.from_value, new.to_value, new.snippet, new.body_text);
END;

CREATE TRIGGER IF NOT EXISTS trg_message_index_ad AFTER DELETE ON message_index
BEGIN
  DELETE FROM message_search_fts WHERE message_id = old.id;
END;
