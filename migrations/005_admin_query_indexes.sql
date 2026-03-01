PRAGMA foreign_keys = ON;

-- Registration listing/filtering/sorting
CREATE INDEX IF NOT EXISTS idx_registrations_status_created_at ON registrations(status, created_at);
CREATE INDEX IF NOT EXISTS idx_registrations_email_created_at ON registrations(email, created_at);

-- User listing/filtering/sorting
CREATE INDEX IF NOT EXISTS idx_users_role_status_created_at ON users(role, status, created_at);
CREATE INDEX IF NOT EXISTS idx_users_provision_created_at ON users(provision_state, created_at);
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login_at);

-- Admin audit listing/filtering/sorting
CREATE INDEX IF NOT EXISTS idx_audit_action_created_at ON admin_audit_log(action, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_actor_created_at ON admin_audit_log(actor_user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_target_created_at ON admin_audit_log(target, created_at);
