package db

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"mailclient/internal/store"
)

func TestApplyMigrationFileAddsCompatibilityColumnsForLegacySchema(t *testing.T) {
	sqdb, err := OpenSQLite(filepath.Join(t.TempDir(), "legacy.db"), 1, 1, time.Minute)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sqdb.Close() })

	legacySchema := `
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  status TEXT NOT NULL CHECK (status IN ('pending','active','suspended','rejected')),
  created_at DATETIME NOT NULL,
  approved_at DATETIME,
  approved_by TEXT,
  last_login_at DATETIME
);
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  ip_hint TEXT,
  user_agent_hash TEXT,
  expires_at DATETIME NOT NULL,
  idle_expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL,
  last_seen_at DATETIME NOT NULL,
  revoked_at DATETIME
);
`
	if _, err := sqdb.Exec(legacySchema); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}

	for _, migration := range []string{
		filepath.Join("..", "..", "migrations", "001_init.sql"),
		filepath.Join("..", "..", "migrations", "002_users_mail_login.sql"),
		filepath.Join("..", "..", "migrations", "003_cleanup_rejected_users.sql"),
		filepath.Join("..", "..", "migrations", "004_cleanup_rejected_users_casefold.sql"),
	} {
		if err := ApplyMigrationFile(sqdb, migration); err != nil {
			t.Fatalf("apply migration %s: %v", migration, err)
		}
	}

	for _, col := range []string{"mail_login", "provision_state", "provision_error"} {
		if !hasColumn(t, sqdb, "users", col) {
			t.Fatalf("expected users.%s to exist after migration", col)
		}
	}
	if !hasColumn(t, sqdb, "sessions", "mail_secret") {
		t.Fatalf("expected sessions.mail_secret to exist after migration")
	}

	now := time.Now().UTC()
	if _, err := sqdb.Exec(
		`INSERT INTO users(id,email,password_hash,role,status,created_at) VALUES(?,?,?,?,?,?)`,
		"u1", "legacy@example.com", "legacy_hash", "admin", "active", now,
	); err != nil {
		t.Fatalf("insert legacy user: %v", err)
	}

	st := store.New(sqdb)
	u, err := st.GetUserByEmail(context.Background(), "legacy@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail should work after compatibility migration, got: %v", err)
	}
	if u.ProvisionState != "pending" {
		t.Fatalf("expected default provision_state pending, got %q", u.ProvisionState)
	}
}

func hasColumn(t *testing.T, sqdb *sql.DB, tableName, colName string) bool {
	t.Helper()
	rows, err := sqdb.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		t.Fatalf("table_info %s: %v", tableName, err)
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan table_info %s: %v", tableName, err)
		}
		if name == colName {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate table_info %s: %v", tableName, err)
	}
	return false
}

func TestCleanupRejectedUsersMigrationRemovesLegacyRows(t *testing.T) {
	sqdb, err := OpenSQLite(filepath.Join(t.TempDir(), "cleanup.db"), 1, 1, time.Minute)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sqdb.Close() })

	if err := ApplyMigrationFile(sqdb, filepath.Join("..", "..", "migrations", "001_init.sql")); err != nil {
		t.Fatalf("apply migration 001: %v", err)
	}
	if err := ApplyMigrationFile(sqdb, filepath.Join("..", "..", "migrations", "002_users_mail_login.sql")); err != nil {
		t.Fatalf("apply migration 002: %v", err)
	}

	now := time.Now().UTC()
	_, err = sqdb.Exec(
		`INSERT INTO users(id,email,password_hash,role,status,provision_state,created_at) VALUES(?,?,?,?,?,?,?)`,
		"u_rej", "rejected@example.com", "hash", "user", "rejected", "pending", now,
	)
	if err != nil {
		t.Fatalf("insert rejected user: %v", err)
	}
	_, err = sqdb.Exec(
		`INSERT INTO sessions(id,user_id,token_hash,mail_secret,expires_at,idle_expires_at,created_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?)`,
		"s_rej", "u_rej", "token_hash_rej", "", now.Add(time.Hour), now.Add(time.Hour), now, now,
	)
	if err != nil {
		t.Fatalf("insert rejected user session: %v", err)
	}
	_, err = sqdb.Exec(
		`INSERT INTO password_reset_tokens(id,user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)`,
		"p_rej", "u_rej", "reset_hash_rej", now.Add(time.Hour), now,
	)
	if err != nil {
		t.Fatalf("insert rejected reset token: %v", err)
	}

	if err := ApplyMigrationFile(sqdb, filepath.Join("..", "..", "migrations", "003_cleanup_rejected_users.sql")); err != nil {
		t.Fatalf("apply migration 003: %v", err)
	}
	if err := ApplyMigrationFile(sqdb, filepath.Join("..", "..", "migrations", "004_cleanup_rejected_users_casefold.sql")); err != nil {
		t.Fatalf("apply migration 004: %v", err)
	}

	var usersCount int
	if err := sqdb.QueryRowContext(context.Background(), `SELECT COUNT(1) FROM users WHERE lower(trim(coalesce(status, '')))='rejected'`).Scan(&usersCount); err != nil {
		t.Fatalf("count rejected users: %v", err)
	}
	if usersCount != 0 {
		t.Fatalf("expected rejected users cleanup, found %d rows", usersCount)
	}

	var sessCount int
	if err := sqdb.QueryRowContext(context.Background(), `SELECT COUNT(1) FROM sessions WHERE user_id='u_rej'`).Scan(&sessCount); err != nil {
		t.Fatalf("count rejected sessions: %v", err)
	}
	if sessCount != 0 {
		t.Fatalf("expected rejected sessions cleanup, found %d rows", sessCount)
	}

	var resetCount int
	if err := sqdb.QueryRowContext(context.Background(), `SELECT COUNT(1) FROM password_reset_tokens WHERE user_id='u_rej'`).Scan(&resetCount); err != nil {
		t.Fatalf("count rejected reset tokens: %v", err)
	}
	if resetCount != 0 {
		t.Fatalf("expected rejected reset token cleanup, found %d rows", resetCount)
	}
}
