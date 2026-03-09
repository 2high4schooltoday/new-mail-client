package store

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/google/uuid"

	"despatch/internal/models"
)

func (s *Store) GetSessionMailProfile(ctx context.Context, userID, fromEmail string) (models.SessionMailProfile, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,user_id,from_email,display_name,reply_to,signature_text,signature_html,created_at,updated_at
		 FROM session_mail_profiles
		 WHERE user_id=? AND from_email=?`,
		userID,
		strings.TrimSpace(fromEmail),
	)
	var item models.SessionMailProfile
	if err := row.Scan(
		&item.ID,
		&item.UserID,
		&item.FromEmail,
		&item.DisplayName,
		&item.ReplyTo,
		&item.SignatureText,
		&item.SignatureHTML,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return models.SessionMailProfile{}, ErrNotFound
		}
		return models.SessionMailProfile{}, err
	}
	return item, nil
}

func (s *Store) GetSessionMailProfileByID(ctx context.Context, userID, id string) (models.SessionMailProfile, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,user_id,from_email,display_name,reply_to,signature_text,signature_html,created_at,updated_at
		 FROM session_mail_profiles
		 WHERE user_id=? AND id=?`,
		userID,
		strings.TrimSpace(id),
	)
	var item models.SessionMailProfile
	if err := row.Scan(
		&item.ID,
		&item.UserID,
		&item.FromEmail,
		&item.DisplayName,
		&item.ReplyTo,
		&item.SignatureText,
		&item.SignatureHTML,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return models.SessionMailProfile{}, ErrNotFound
		}
		return models.SessionMailProfile{}, err
	}
	return item, nil
}

func (s *Store) UpsertSessionMailProfile(ctx context.Context, in models.SessionMailProfile) (models.SessionMailProfile, error) {
	now := time.Now().UTC()
	if strings.TrimSpace(in.ID) == "" {
		in.ID = uuid.NewString()
	}
	if in.CreatedAt.IsZero() {
		in.CreatedAt = now
	}
	in.UpdatedAt = now
	in.FromEmail = strings.TrimSpace(in.FromEmail)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO session_mail_profiles(id,user_id,from_email,display_name,reply_to,signature_text,signature_html,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(user_id,from_email) DO UPDATE SET
		   display_name=excluded.display_name,
		   reply_to=excluded.reply_to,
		   signature_text=excluded.signature_text,
		   signature_html=excluded.signature_html,
		   updated_at=excluded.updated_at`,
		in.ID,
		in.UserID,
		in.FromEmail,
		in.DisplayName,
		in.ReplyTo,
		in.SignatureText,
		in.SignatureHTML,
		in.CreatedAt,
		in.UpdatedAt,
	)
	if err != nil {
		return models.SessionMailProfile{}, err
	}
	return s.GetSessionMailProfile(ctx, in.UserID, in.FromEmail)
}
