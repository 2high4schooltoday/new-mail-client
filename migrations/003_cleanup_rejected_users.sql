PRAGMA foreign_keys = ON;

-- One-time cleanup for legacy behavior where rejected registrations left rows in users.
-- Rejected accounts are denied registrations and should not exist as active user records.
DELETE FROM sessions
WHERE user_id IN (SELECT id FROM users WHERE status = 'rejected');

DELETE FROM password_reset_tokens
WHERE user_id IN (SELECT id FROM users WHERE status = 'rejected');

DELETE FROM users
WHERE status = 'rejected';
