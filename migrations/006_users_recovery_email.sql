ALTER TABLE users ADD COLUMN recovery_email TEXT;

-- New users now default recovery email to account email in store.CreateUser.
-- Keep existing rows nullable so users can be prompted post-update when missing.
