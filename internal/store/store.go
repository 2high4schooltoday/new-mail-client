package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"mailclient/internal/models"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) CreateUser(ctx context.Context, email, passwordHash, role string, status models.UserStatus) (models.User, error) {
	now := time.Now().UTC()
	u := models.User{ID: uuid.NewString(), Email: email, PasswordHash: passwordHash, Role: role, Status: status, ProvisionState: "pending", CreatedAt: now}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users(id,email,mail_login,password_hash,role,status,provision_state,provision_error,created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		u.ID, u.Email, nil, u.PasswordHash, u.Role, u.Status, u.ProvisionState, nil, u.CreatedAt,
	)
	return u, err
}

func (s *Store) EnsureAdmin(ctx context.Context, email, passwordHash string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || passwordHash == "" {
		return nil
	}
	u, err := s.GetUserByEmail(ctx, email)
	if err == ErrNotFound {
		now := time.Now().UTC()
		_, err = s.db.ExecContext(ctx,
			`INSERT INTO users(id,email,mail_login,password_hash,role,status,provision_state,provision_error,created_at,approved_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			uuid.NewString(), email, nil, passwordHash, "admin", models.UserActive, "ok", nil, now, now,
		)
		return err
	}
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE users SET role='admin', status='active', password_hash=?, provision_state='ok', provision_error=NULL WHERE id=?`,
		passwordHash, u.ID,
	)
	return err
}

func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users WHERE role='admin'`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) GetSetting(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func (s *Store) UpsertSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		key, value, time.Now().UTC(),
	)
	return err
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (models.User, error) {
	var u models.User
	var approvedAt, lastLogin sql.NullTime
	var approvedBy, provisionErr, mailLogin sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id,email,mail_login,password_hash,role,status,provision_state,provision_error,created_at,approved_at,approved_by,last_login_at FROM users WHERE email=?`,
		email,
	).Scan(&u.ID, &u.Email, &mailLogin, &u.PasswordHash, &u.Role, &u.Status, &u.ProvisionState, &provisionErr, &u.CreatedAt, &approvedAt, &approvedBy, &lastLogin)
	if err == sql.ErrNoRows {
		return models.User{}, ErrNotFound
	}
	if err != nil {
		return models.User{}, err
	}
	if approvedAt.Valid {
		t := approvedAt.Time
		u.ApprovedAt = &t
	}
	if approvedBy.Valid {
		sv := approvedBy.String
		u.ApprovedBy = &sv
	}
	if lastLogin.Valid {
		t := lastLogin.Time
		u.LastLoginAt = &t
	}
	if provisionErr.Valid {
		v := provisionErr.String
		u.ProvisionError = &v
	}
	if mailLogin.Valid {
		v := strings.TrimSpace(mailLogin.String)
		if v != "" {
			u.MailLogin = &v
		}
	}
	return u, nil
}

func (s *Store) GetUserByID(ctx context.Context, id string) (models.User, error) {
	var u models.User
	var approvedAt, lastLogin sql.NullTime
	var approvedBy, provisionErr, mailLogin sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id,email,mail_login,password_hash,role,status,provision_state,provision_error,created_at,approved_at,approved_by,last_login_at FROM users WHERE id=?`,
		id,
	).Scan(&u.ID, &u.Email, &mailLogin, &u.PasswordHash, &u.Role, &u.Status, &u.ProvisionState, &provisionErr, &u.CreatedAt, &approvedAt, &approvedBy, &lastLogin)
	if err == sql.ErrNoRows {
		return models.User{}, ErrNotFound
	}
	if err != nil {
		return models.User{}, err
	}
	if approvedAt.Valid {
		t := approvedAt.Time
		u.ApprovedAt = &t
	}
	if approvedBy.Valid {
		sv := approvedBy.String
		u.ApprovedBy = &sv
	}
	if lastLogin.Valid {
		t := lastLogin.Time
		u.LastLoginAt = &t
	}
	if provisionErr.Valid {
		v := provisionErr.String
		u.ProvisionError = &v
	}
	if mailLogin.Valid {
		v := strings.TrimSpace(mailLogin.String)
		if v != "" {
			u.MailLogin = &v
		}
	}
	return u, nil
}

func (s *Store) UpdateUserStatus(ctx context.Context, userID string, status models.UserStatus, approver *string) error {
	now := time.Now().UTC()
	if status == models.UserActive && approver != nil {
		_, err := s.db.ExecContext(ctx,
			`UPDATE users SET status=?, approved_at=?, approved_by=? WHERE id=?`,
			status, now, *approver, userID,
		)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE users SET status=? WHERE id=?`, status, userID)
	return err
}

func (s *Store) UpdateUserPasswordHash(ctx context.Context, userID, passwordHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE id=?`, passwordHash, userID)
	return err
}

func (s *Store) UpdateUserMailLogin(ctx context.Context, userID, mailLogin string) error {
	mailLogin = strings.TrimSpace(mailLogin)
	if mailLogin == "" {
		_, err := s.db.ExecContext(ctx, `UPDATE users SET mail_login=NULL WHERE id=?`, userID)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE users SET mail_login=? WHERE id=?`, mailLogin, userID)
	return err
}

func (s *Store) TouchUserLastLogin(ctx context.Context, userID string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET last_login_at=? WHERE id=?`, at, userID)
	return err
}

func (s *Store) UpdateProvisionState(ctx context.Context, userID, state string, errMsg *string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET provision_state=?, provision_error=? WHERE id=?`, state, errMsg, userID)
	return err
}

func (s *Store) ListUsers(ctx context.Context, query models.UserQuery) ([]models.User, int, error) {
	where := []string{"lower(trim(coalesce(status, ''))) <> 'rejected'"}
	args := make([]any, 0, 12)

	q := strings.TrimSpace(query.Q)
	if q != "" {
		needle := "%" + strings.ToLower(q) + "%"
		where = append(where, "(lower(email) LIKE ? OR lower(role) LIKE ? OR lower(status) LIKE ? OR lower(provision_state) LIKE ?)")
		args = append(args, needle, needle, needle, needle)
	}
	if status := strings.TrimSpace(strings.ToLower(query.Status)); status != "" && status != "all" {
		where = append(where, "lower(status)=?")
		args = append(args, status)
	}
	if role := strings.TrimSpace(strings.ToLower(query.Role)); role != "" && role != "all" {
		where = append(where, "lower(role)=?")
		args = append(args, role)
	}
	if ps := strings.TrimSpace(strings.ToLower(query.ProvisionState)); ps != "" && ps != "all" {
		where = append(where, "lower(provision_state)=?")
		args = append(args, ps)
	}

	whereSQL := strings.Join(where, " AND ")

	countArgs := append([]any{}, args...)
	countSQL := fmt.Sprintf("SELECT COUNT(1) FROM users WHERE %s", whereSQL)
	var total int
	if err := s.db.QueryRowContext(ctx, countSQL, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	sortExpr := sanitizeUserSort(query.Sort)
	orderExpr := sanitizeSortOrder(query.Order)
	limit := clampLimit(query.Limit)
	offset := clampOffset(query.Offset)

	listSQL := fmt.Sprintf(
		`SELECT id,email,mail_login,password_hash,role,status,provision_state,provision_error,created_at,approved_at,approved_by,last_login_at
		 FROM users
		 WHERE %s
		 ORDER BY %s %s
		 LIMIT ? OFFSET ?`,
		whereSQL,
		sortExpr,
		orderExpr,
	)
	listArgs := append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, listSQL, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]models.User, 0, limit)
	for rows.Next() {
		var u models.User
		var approvedAt, lastLogin sql.NullTime
		var approvedBy, provisionErr, mailLogin sql.NullString
		if err := rows.Scan(&u.ID, &u.Email, &mailLogin, &u.PasswordHash, &u.Role, &u.Status, &u.ProvisionState, &provisionErr, &u.CreatedAt, &approvedAt, &approvedBy, &lastLogin); err != nil {
			return nil, 0, err
		}
		if approvedAt.Valid {
			t := approvedAt.Time
			u.ApprovedAt = &t
		}
		if approvedBy.Valid {
			sv := approvedBy.String
			u.ApprovedBy = &sv
		}
		if lastLogin.Valid {
			t := lastLogin.Time
			u.LastLoginAt = &t
		}
		if provisionErr.Valid {
			v := provisionErr.String
			u.ProvisionError = &v
		}
		if mailLogin.Valid {
			v := strings.TrimSpace(mailLogin.String)
			if v != "" {
				u.MailLogin = &v
			}
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

func (s *Store) CreateRegistration(ctx context.Context, email, ip, uaHash string, captchaOK bool) (models.Registration, error) {
	now := time.Now().UTC()
	r := models.Registration{
		ID:            uuid.NewString(),
		Email:         email,
		SourceIP:      ip,
		UserAgentHash: uaHash,
		CaptchaOK:     captchaOK,
		Status:        "pending",
		CreatedAt:     now,
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO registrations(id,email,source_ip,user_agent_hash,captcha_ok,status,created_at) VALUES(?,?,?,?,?,?,?)`,
		r.ID, r.Email, r.SourceIP, r.UserAgentHash, boolToInt(captchaOK), r.Status, r.CreatedAt,
	)
	return r, err
}

func (s *Store) GetRegistrationByID(ctx context.Context, id string) (models.Registration, error) {
	var r models.Registration
	var cap int
	var decidedAt sql.NullTime
	var decidedBy, reason sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id,email,source_ip,user_agent_hash,captcha_ok,status,created_at,decided_at,decided_by,reason FROM registrations WHERE id=?`,
		id,
	).Scan(&r.ID, &r.Email, &r.SourceIP, &r.UserAgentHash, &cap, &r.Status, &r.CreatedAt, &decidedAt, &decidedBy, &reason)
	if err == sql.ErrNoRows {
		return models.Registration{}, ErrNotFound
	}
	if err != nil {
		return models.Registration{}, err
	}
	r.CaptchaOK = cap == 1
	if decidedAt.Valid {
		t := decidedAt.Time
		r.DecidedAt = &t
	}
	if decidedBy.Valid {
		sv := decidedBy.String
		r.DecidedBy = &sv
	}
	if reason.Valid {
		sv := reason.String
		r.Reason = &sv
	}
	return r, nil
}

func (s *Store) ListRegistrations(ctx context.Context, query models.RegistrationQuery) ([]models.Registration, int, error) {
	where := make([]string, 0, 4)
	args := make([]any, 0, 8)

	status := strings.TrimSpace(strings.ToLower(query.Status))
	if status == "" {
		status = "pending"
	}
	if status != "all" {
		where = append(where, "lower(status)=?")
		args = append(args, status)
	}

	q := strings.TrimSpace(query.Q)
	if q != "" {
		needle := "%" + strings.ToLower(q) + "%"
		where = append(where, "(lower(email) LIKE ? OR lower(coalesce(reason,'')) LIKE ?)")
		args = append(args, needle, needle)
	}

	whereSQL := "1=1"
	if len(where) > 0 {
		whereSQL = strings.Join(where, " AND ")
	}

	countSQL := fmt.Sprintf("SELECT COUNT(1) FROM registrations WHERE %s", whereSQL)
	var total int
	if err := s.db.QueryRowContext(ctx, countSQL, append([]any{}, args...)...).Scan(&total); err != nil {
		return nil, 0, err
	}

	sortExpr := sanitizeRegistrationSort(query.Sort)
	orderExpr := sanitizeSortOrder(query.Order)
	limit := clampLimit(query.Limit)
	offset := clampOffset(query.Offset)

	listSQL := fmt.Sprintf(
		`SELECT id,email,source_ip,user_agent_hash,captcha_ok,status,created_at,decided_at,decided_by,reason
		 FROM registrations
		 WHERE %s
		 ORDER BY %s %s
		 LIMIT ? OFFSET ?`,
		whereSQL,
		sortExpr,
		orderExpr,
	)
	rows, err := s.db.QueryContext(ctx, listSQL, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]models.Registration, 0, limit)
	for rows.Next() {
		var r models.Registration
		var cap int
		var decidedAt sql.NullTime
		var decidedBy, reason sql.NullString
		if err := rows.Scan(&r.ID, &r.Email, &r.SourceIP, &r.UserAgentHash, &cap, &r.Status, &r.CreatedAt, &decidedAt, &decidedBy, &reason); err != nil {
			return nil, 0, err
		}
		r.CaptchaOK = cap == 1
		if decidedAt.Valid {
			t := decidedAt.Time
			r.DecidedAt = &t
		}
		if decidedBy.Valid {
			sv := decidedBy.String
			r.DecidedBy = &sv
		}
		if reason.Valid {
			sv := reason.String
			r.Reason = &sv
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func (s *Store) SetRegistrationDecision(ctx context.Context, regID, status, decidedBy, reason string) error {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`UPDATE registrations SET status=?,decided_at=?,decided_by=?,reason=? WHERE id=? AND status='pending'`,
		status, now, decidedBy, reason, regID,
	)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrConflict
	}
	return nil
}

// RejectRegistrationAndDeletePendingUser marks a pending registration as rejected and
// removes the associated pending user in one transaction.
func (s *Store) RejectRegistrationAndDeletePendingUser(ctx context.Context, regID, decidedBy, reason string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	var email, regStatus string
	if err := tx.QueryRowContext(ctx, `SELECT email,status FROM registrations WHERE id=?`, regID).Scan(&email, &regStatus); err != nil {
		if err == sql.ErrNoRows {
			return "", ErrNotFound
		}
		return "", err
	}
	if regStatus != "pending" {
		return "", ErrConflict
	}

	var userID string
	var userStatus models.UserStatus
	if err := tx.QueryRowContext(ctx, `SELECT id,status FROM users WHERE email=?`, email).Scan(&userID, &userStatus); err != nil {
		if err == sql.ErrNoRows {
			return "", ErrNotFound
		}
		return "", err
	}
	if userStatus != models.UserPending {
		return "", ErrConflict
	}

	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx,
		`UPDATE registrations SET status=?,decided_at=?,decided_by=?,reason=? WHERE id=? AND status='pending'`,
		"rejected", now, decidedBy, reason, regID,
	)
	if err != nil {
		return "", err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return "", err
	}
	if rows == 0 {
		return "", ErrConflict
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM password_reset_tokens WHERE user_id=?`, userID); err != nil {
		return "", err
	}
	res, err = tx.ExecContext(ctx, `DELETE FROM users WHERE id=?`, userID)
	if err != nil {
		return "", err
	}
	rows, err = res.RowsAffected()
	if err != nil {
		return "", err
	}
	if rows == 0 {
		return "", ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}
	return userID, nil
}

func (s *Store) CreateSession(ctx context.Context, sess models.Session) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions(id,user_id,token_hash,mail_secret,ip_hint,user_agent_hash,expires_at,idle_expires_at,created_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		sess.ID, sess.UserID, sess.TokenHash, sess.MailSecret, sess.IPHint, sess.UserAgentHash, sess.ExpiresAt, sess.IdleExpiresAt, sess.CreatedAt, sess.LastSeenAt,
	)
	return err
}

func (s *Store) GetSessionByTokenHash(ctx context.Context, tokenHash string) (models.Session, error) {
	var sess models.Session
	var revoked sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT id,user_id,token_hash,mail_secret,ip_hint,user_agent_hash,expires_at,idle_expires_at,created_at,last_seen_at,revoked_at FROM sessions WHERE token_hash=?`,
		tokenHash,
	).Scan(&sess.ID, &sess.UserID, &sess.TokenHash, &sess.MailSecret, &sess.IPHint, &sess.UserAgentHash, &sess.ExpiresAt, &sess.IdleExpiresAt, &sess.CreatedAt, &sess.LastSeenAt, &revoked)
	if err == sql.ErrNoRows {
		return models.Session{}, ErrNotFound
	}
	if err != nil {
		return models.Session{}, err
	}
	if revoked.Valid {
		t := revoked.Time
		sess.RevokedAt = &t
	}
	return sess, nil
}

func (s *Store) TouchSession(ctx context.Context, id string, idleExpiry time.Time) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at=?, idle_expires_at=? WHERE id=?`, now, idleExpiry, id)
	return err
}

func (s *Store) RevokeSession(ctx context.Context, id string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at=? WHERE id=?`, now, id)
	return err
}

func (s *Store) RevokeUserSessions(ctx context.Context, userID string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, now, userID)
	return err
}

func (s *Store) InsertAudit(ctx context.Context, actorID, action, target, metadata string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_audit_log(id,actor_user_id,action,target,metadata_json,created_at) VALUES(?,?,?,?,?,?)`,
		uuid.NewString(), actorID, action, target, metadata, time.Now().UTC(),
	)
	return err
}

func (s *Store) ListAudit(ctx context.Context, query models.AuditQuery) ([]models.AuditEntry, int, error) {
	where := make([]string, 0, 8)
	args := make([]any, 0, 16)

	if q := strings.TrimSpace(query.Q); q != "" {
		needle := "%" + strings.ToLower(q) + "%"
		where = append(where, "(lower(a.action) LIKE ? OR lower(a.target) LIKE ? OR lower(a.metadata_json) LIKE ? OR lower(coalesce(u.email,'')) LIKE ?)")
		args = append(args, needle, needle, needle, needle)
	}
	if action := strings.TrimSpace(strings.ToLower(query.Action)); action != "" && action != "all" {
		where = append(where, "lower(a.action)=?")
		args = append(args, action)
	}
	if actor := strings.TrimSpace(strings.ToLower(query.Actor)); actor != "" {
		where = append(where, "lower(coalesce(u.email,'')) LIKE ?")
		args = append(args, "%"+actor+"%")
	}
	if target := strings.TrimSpace(strings.ToLower(query.Target)); target != "" {
		where = append(where, "lower(a.target) LIKE ?")
		args = append(args, "%"+target+"%")
	}
	if !query.From.IsZero() {
		where = append(where, "a.created_at >= ?")
		args = append(args, query.From.UTC())
	}
	if !query.To.IsZero() {
		where = append(where, "a.created_at <= ?")
		args = append(args, query.To.UTC())
	}

	whereSQL := "1=1"
	if len(where) > 0 {
		whereSQL = strings.Join(where, " AND ")
	}

	countSQL := fmt.Sprintf(
		`SELECT COUNT(1)
		 FROM admin_audit_log a
		 LEFT JOIN users u ON u.id = a.actor_user_id
		 WHERE %s`,
		whereSQL,
	)
	var total int
	if err := s.db.QueryRowContext(ctx, countSQL, append([]any{}, args...)...).Scan(&total); err != nil {
		return nil, 0, err
	}

	sortExpr := sanitizeAuditSort(query.Sort)
	orderExpr := sanitizeSortOrder(query.Order)
	limit := clampLimit(query.Limit)
	offset := clampOffset(query.Offset)
	listSQL := fmt.Sprintf(
		`SELECT a.id,a.actor_user_id,coalesce(u.email,''),a.action,a.target,a.metadata_json,a.created_at
		 FROM admin_audit_log a
		 LEFT JOIN users u ON u.id = a.actor_user_id
		 WHERE %s
		 ORDER BY %s %s
		 LIMIT ? OFFSET ?`,
		whereSQL,
		sortExpr,
		orderExpr,
	)
	rows, err := s.db.QueryContext(ctx, listSQL, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]models.AuditEntry, 0, limit)
	for rows.Next() {
		var e models.AuditEntry
		if err := rows.Scan(&e.ID, &e.ActorUserID, &e.ActorEmail, &e.Action, &e.Target, &e.MetadataJSON, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

func clampLimit(limit int) int {
	switch {
	case limit <= 0:
		return 25
	case limit > 100:
		return 100
	default:
		return limit
	}
}

func clampOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
}

func sanitizeSortOrder(order string) string {
	if strings.EqualFold(strings.TrimSpace(order), "asc") {
		return "ASC"
	}
	return "DESC"
}

func sanitizeRegistrationSort(sort string) string {
	switch strings.ToLower(strings.TrimSpace(sort)) {
	case "email":
		return "email"
	case "status":
		return "status"
	case "decided_at":
		return "decided_at"
	case "created_at":
		fallthrough
	default:
		return "created_at"
	}
}

func sanitizeUserSort(sort string) string {
	switch strings.ToLower(strings.TrimSpace(sort)) {
	case "email":
		return "email"
	case "role":
		return "role"
	case "status":
		return "status"
	case "provision_state":
		return "provision_state"
	case "last_login_at":
		return "last_login_at"
	case "created_at":
		fallthrough
	default:
		return "created_at"
	}
}

func sanitizeAuditSort(sort string) string {
	switch strings.ToLower(strings.TrimSpace(sort)) {
	case "action":
		return "a.action"
	case "actor":
		return "u.email"
	case "target":
		return "a.target"
	case "created_at":
		fallthrough
	default:
		return "a.created_at"
	}
}

func (s *Store) CreatePasswordResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (models.PasswordResetToken, error) {
	t := models.PasswordResetToken{ID: uuid.NewString(), UserID: userID, TokenHash: tokenHash, ExpiresAt: expiresAt, CreatedAt: time.Now().UTC()}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO password_reset_tokens(id,user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)`,
		t.ID, t.UserID, t.TokenHash, t.ExpiresAt, t.CreatedAt,
	)
	return t, err
}

func (s *Store) ConsumePasswordResetToken(ctx context.Context, tokenHash string) (models.PasswordResetToken, error) {
	var t models.PasswordResetToken
	var used sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT id,user_id,token_hash,expires_at,used_at,created_at FROM password_reset_tokens WHERE token_hash=?`, tokenHash,
	).Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &used, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return models.PasswordResetToken{}, ErrNotFound
	}
	if err != nil {
		return models.PasswordResetToken{}, err
	}
	if used.Valid {
		tm := used.Time
		t.UsedAt = &tm
	}
	if t.UsedAt != nil || time.Now().UTC().After(t.ExpiresAt) {
		return models.PasswordResetToken{}, ErrNotFound
	}
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `UPDATE password_reset_tokens SET used_at=? WHERE id=? AND used_at IS NULL`, now, t.ID); err != nil {
		return models.PasswordResetToken{}, err
	}
	return t, nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *Store) IncrementRateEvent(ctx context.Context, key, route string, windowStart time.Time) (int, error) {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rate_limit_events(id,key,route,window_start,count,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(key, route, window_start)
		 DO UPDATE SET count = rate_limit_events.count + 1, updated_at = excluded.updated_at`,
		uuid.NewString(), key, route, windowStart, 1, now, now,
	)
	if err != nil {
		return 0, err
	}

	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT count FROM rate_limit_events WHERE key=? AND route=? AND window_start=?`, key, route, windowStart).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) DeleteRateEvents(ctx context.Context, key, route string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM rate_limit_events WHERE key=? AND route=?`, key, route)
	return err
}

func (s *Store) CleanupRateEventsBefore(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM rate_limit_events WHERE window_start < ?`, before)
	return err
}
