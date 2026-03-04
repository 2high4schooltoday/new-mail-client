CREATE TABLE IF NOT EXISTS user_preferences (
  user_id TEXT PRIMARY KEY,
  theme TEXT NOT NULL DEFAULT 'machine-dark',
  density TEXT NOT NULL DEFAULT 'comfortable',
  layout_mode TEXT NOT NULL DEFAULT 'three-pane',
  keymap_json TEXT NOT NULL DEFAULT '{}',
  remote_image_policy TEXT NOT NULL DEFAULT 'block',
  timezone TEXT NOT NULL DEFAULT 'UTC',
  page_size INTEGER NOT NULL DEFAULT 50,
  grouping_mode TEXT NOT NULL DEFAULT 'day',
  updated_at DATETIME NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS saved_searches (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  account_id TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL,
  filters_json TEXT NOT NULL DEFAULT '{}',
  pinned INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_saved_searches_user ON saved_searches(user_id, pinned DESC, name ASC);
