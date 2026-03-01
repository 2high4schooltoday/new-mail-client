PRAGMA foreign_keys = ON;

-- Follow-up cleanup for legacy rejected users where status casing/spacing varied.
-- Rejected accounts are denied registrations and should not persist as users.
DELETE FROM sessions
WHERE user_id IN (
  SELECT id
  FROM users
  WHERE lower(trim(coalesce(status, ''))) = 'rejected'
);

DELETE FROM password_reset_tokens
WHERE user_id IN (
  SELECT id
  FROM users
  WHERE lower(trim(coalesce(status, ''))) = 'rejected'
);

DELETE FROM users
WHERE lower(trim(coalesce(status, ''))) = 'rejected';
