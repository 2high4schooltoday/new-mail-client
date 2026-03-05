package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"despatch/internal/mail"
)

const settingScopedIndexedIDsMigrated = "mail_index_scoped_ids_v1"

// EnsureScopedIndexedIDs rewrites legacy unscoped v2 mail index identifiers to
// account-scoped identifiers. The rewrite is idempotent and guarded by a
// settings marker.
func (s *Store) EnsureScopedIndexedIDs(ctx context.Context) error {
	done, err := s.isScopedIndexedIDsMigrationDone(ctx)
	if err != nil {
		return err
	}
	if done {
		return nil
	}
	if !s.tableExists(ctx, "message_index") {
		return nil
	}

	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), `PRAGMA foreign_keys=ON`)
	}()

	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}

	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()

	now := time.Now().UTC()
	if err := rewriteMessageIDs(ctx, conn, now); err != nil {
		return err
	}
	if err := rewriteThreadIDs(ctx, conn, now); err != nil {
		return err
	}
	if err := rewriteAttachmentMessageIDs(ctx, conn); err != nil {
		return err
	}
	if err := rebuildMessageFTS(ctx, conn); err != nil {
		return err
	}
	if err := ensureNoForeignKeyViolations(ctx, conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO settings(key,value,updated_at)
		 VALUES(?,?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		settingScopedIndexedIDsMigrated, "done", now,
	); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *Store) isScopedIndexedIDsMigrationDone(ctx context.Context) (bool, error) {
	v, ok, err := s.GetSetting(ctx, settingScopedIndexedIDsMigrated)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	return strings.EqualFold(strings.TrimSpace(v), "done"), nil
}

func (s *Store) tableExists(ctx context.Context, table string) bool {
	table = strings.TrimSpace(table)
	if table == "" {
		return false
	}
	var count int
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(1)
		 FROM sqlite_master
		 WHERE type='table' AND name=?`,
		table,
	).Scan(&count); err != nil {
		return false
	}
	return count > 0
}

func rewriteMessageIDs(ctx context.Context, conn *sql.Conn, now time.Time) error {
	rows, err := conn.QueryContext(ctx, `SELECT account_id,id,thread_id FROM message_index`)
	if err != nil {
		return err
	}
	type row struct {
		accountID   string
		oldID       string
		newID       string
		oldThreadID string
		newThreadID string
	}
	updates := make([]row, 0, 128)
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.accountID, &r.oldID, &r.oldThreadID); err != nil {
			_ = rows.Close()
			return err
		}
		r.newID = mail.NormalizeIndexedMessageID(r.accountID, r.oldID)
		r.newThreadID = mail.NormalizeIndexedThreadID(r.accountID, r.oldThreadID)
		if r.newThreadID == "" {
			r.newThreadID = mail.NormalizeIndexedThreadID(r.accountID, r.oldID)
		}
		if r.oldID != r.newID || r.oldThreadID != r.newThreadID {
			updates = append(updates, r)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()

	for _, item := range updates {
		if _, err := conn.ExecContext(ctx,
			`UPDATE message_index
			 SET id=?, thread_id=?, updated_at=?
			 WHERE account_id=? AND id=?`,
			item.newID,
			item.newThreadID,
			now,
			item.accountID,
			item.oldID,
		); err != nil {
			return err
		}
	}
	return nil
}

func rewriteThreadIDs(ctx context.Context, conn *sql.Conn, now time.Time) error {
	rows, err := conn.QueryContext(ctx, `SELECT account_id,id,latest_message_id FROM thread_index`)
	if err != nil {
		return err
	}
	type row struct {
		accountID        string
		oldID            string
		newID            string
		oldLatestMessage string
		newLatestMessage string
	}
	updates := make([]row, 0, 64)
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.accountID, &r.oldID, &r.oldLatestMessage); err != nil {
			_ = rows.Close()
			return err
		}
		r.newID = mail.NormalizeIndexedThreadID(r.accountID, r.oldID)
		r.newLatestMessage = mail.NormalizeIndexedMessageID(r.accountID, r.oldLatestMessage)
		if r.oldID != r.newID || r.oldLatestMessage != r.newLatestMessage {
			updates = append(updates, r)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()

	for _, item := range updates {
		if _, err := conn.ExecContext(ctx,
			`UPDATE thread_index
			 SET id=?, latest_message_id=?, updated_at=?
			 WHERE account_id=? AND id=?`,
			item.newID,
			item.newLatestMessage,
			now,
			item.accountID,
			item.oldID,
		); err != nil {
			return err
		}
	}
	return nil
}

func rewriteAttachmentMessageIDs(ctx context.Context, conn *sql.Conn) error {
	rows, err := conn.QueryContext(ctx, `SELECT rowid,account_id,message_id FROM attachment_index`)
	if err != nil {
		return err
	}
	type row struct {
		rowID     int64
		accountID string
		oldID     string
		newID     string
	}
	updates := make([]row, 0, 128)
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.rowID, &r.accountID, &r.oldID); err != nil {
			_ = rows.Close()
			return err
		}
		r.newID = mail.NormalizeIndexedMessageID(r.accountID, r.oldID)
		if r.oldID != r.newID {
			updates = append(updates, r)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()

	for _, item := range updates {
		if _, err := conn.ExecContext(ctx,
			`UPDATE attachment_index SET message_id=? WHERE rowid=?`,
			item.newID,
			item.rowID,
		); err != nil {
			return err
		}
	}
	return nil
}

func rebuildMessageFTS(ctx context.Context, conn *sql.Conn) error {
	if _, err := conn.ExecContext(ctx, `DELETE FROM message_search_fts`); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO message_search_fts(message_id,account_id,mailbox,thread_id,subject,from_value,to_value,snippet,body_text)
		 SELECT id,account_id,mailbox,thread_id,subject,from_value,to_value,snippet,body_text
		 FROM message_index`,
	); err != nil {
		return err
	}
	return nil
}

func ensureNoForeignKeyViolations(ctx context.Context, conn *sql.Conn) error {
	rows, err := conn.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		var table string
		var rowID int64
		var parent string
		var fkID int
		if err := rows.Scan(&table, &rowID, &parent, &fkID); err != nil {
			return err
		}
		return fmt.Errorf("foreign key violation after scoped id migration: table=%s rowid=%d parent=%s fkid=%d", table, rowID, parent, fkID)
	}
	return rows.Err()
}
