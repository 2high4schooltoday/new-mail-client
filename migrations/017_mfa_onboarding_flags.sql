ALTER TABLE users ADD COLUMN mfa_preference TEXT NOT NULL DEFAULT 'none' CHECK (mfa_preference IN ('none','totp','webauthn'));
ALTER TABLE users ADD COLUMN legacy_mfa_prompt_pending INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN mfa_setup_switch_used INTEGER NOT NULL DEFAULT 0;

ALTER TABLE registrations ADD COLUMN mfa_preference TEXT NOT NULL DEFAULT 'none' CHECK (mfa_preference IN ('none','totp','webauthn'));

UPDATE users
SET legacy_mfa_prompt_pending = 1
WHERE status = 'active'
  AND NOT EXISTS (
    SELECT 1
    FROM mfa_totp t
    WHERE t.user_id = users.id
      AND t.enabled = 1
      AND length(trim(coalesce(t.secret_enc, ''))) > 0
  )
  AND NOT EXISTS (
    SELECT 1
    FROM mfa_webauthn_credentials w
    WHERE w.user_id = users.id
  );
