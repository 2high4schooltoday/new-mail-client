CREATE TABLE IF NOT EXISTS session_mail_profiles (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  from_email TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  reply_to TEXT NOT NULL DEFAULT '',
  signature_text TEXT NOT NULL DEFAULT '',
  signature_html TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  UNIQUE(user_id, from_email),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_session_mail_profiles_user ON session_mail_profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_session_mail_profiles_user_from ON session_mail_profiles(user_id, from_email);
