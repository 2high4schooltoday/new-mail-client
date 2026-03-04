CREATE TABLE IF NOT EXISTS user_sessions_meta (
  session_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  device_label TEXT NOT NULL DEFAULT '',
  ua_summary TEXT NOT NULL DEFAULT '',
  ip_hint TEXT NOT NULL DEFAULT '',
  revoked_reason TEXT NOT NULL DEFAULT '',
  updated_at DATETIME NOT NULL,
  FOREIGN KEY(session_id) REFERENCES sessions(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_meta_user ON user_sessions_meta(user_id, updated_at DESC);
