CREATE INDEX IF NOT EXISTS idx_attachment_index_account_message
ON attachment_index(account_id, message_id);

CREATE INDEX IF NOT EXISTS idx_message_index_account_id
ON message_index(account_id, id);

CREATE INDEX IF NOT EXISTS idx_thread_index_account_id
ON thread_index(account_id, id);
