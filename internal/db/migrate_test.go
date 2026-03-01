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
