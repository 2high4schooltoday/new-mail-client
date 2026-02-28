package db

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
)

func ApplyMigrationFile(db *sql.DB, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read migration: %w", err)
	}
	if _, err := db.Exec(string(b)); err != nil && !isDuplicateColumnErr(err) {
		return fmt.Errorf("apply migration: %w", err)
	}

	// Backward-compatible patching for early development schema revisions.
	for _, stmt := range []string{
		`ALTER TABLE sessions ADD COLUMN mail_secret TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN provision_state TEXT NOT NULL DEFAULT 'pending'`,
		`ALTER TABLE users ADD COLUMN provision_error TEXT`,
		`ALTER TABLE users ADD COLUMN mail_login TEXT`,
	} {
		if _, err := db.Exec(stmt); err != nil && !isDuplicateColumnErr(err) {
			return fmt.Errorf("apply compatibility migration %q: %w", stmt, err)
		}
	}
	return nil
}

func isDuplicateColumnErr(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate column") || strings.Contains(msg, "already exists")
}
