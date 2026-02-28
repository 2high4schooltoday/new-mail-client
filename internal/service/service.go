package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	netmail "net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"mailclient/internal/auth"
	"mailclient/internal/config"
	"mailclient/internal/mail"
	"mailclient/internal/models"
	"mailclient/internal/notify"
	"mailclient/internal/store"
	"mailclient/internal/util"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrPendingApproval    = errors.New("pending approval")
	ErrSuspended          = errors.New("account suspended")
	ErrForbidden          = errors.New("forbidden")
	ErrPAMPasswordManaged = errors.New("password is managed by PAM; change it in the system account")
	ErrPAMVerifierDown    = errors.New("cannot reach Dovecot IMAP for PAM verification")
)

var domainRx = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

type SetupStatus struct {
	Required          bool   `json:"required"`
	BaseDomain        string `json:"base_domain"`
	DefaultAdminEmail string `json:"default_admin_email"`
	AuthMode          string `json:"auth_mode"`
	PasswordMinLength int    `json:"password_min_length"`
	PasswordMaxLength int    `json:"password_max_length"`
	PasswordClassMin  int    `json:"password_class_min"`
}

type SetupCompleteRequest struct {
	BaseDomain    string
	AdminEmail    string
	AdminPassword string
	Region        string
}

type Service struct {
	cfg        config.Config
	st         *store.Store
	mail       mail.Client
	provision  mail.AuthProvisioner
	sender     notify.Sender
	encryptKey []byte
}

func New(cfg config.Config, st *store.Store, m mail.Client, p mail.AuthProvisioner, sender notify.Sender) *Service {
	if sender == nil {
		sender = notify.LogSender{}
	}
	return &Service{cfg: cfg, st: st, mail: m, provision: p, sender: sender, encryptKey: util.Derive32ByteKey(cfg.SessionEncryptKey)}
}

func hashUA(ua string) string {
	s := sha256.Sum256([]byte(ua))
	return hex.EncodeToString(s[:])
}

func (s *Service) Register(ctx context.Context, email, password, ip, userAgent string, captchaOK bool) error {
	status, err := s.SetupStatus(ctx)
	if err != nil {
		return err
	}
	if status.Required {
		return errors.New("setup is not complete")
	}

	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || password == "" {
		return errors.New("email and password are required")
	}
	if err := s.ValidatePassword(password); err != nil {
		return err
	}
	if !strings.HasSuffix(email, "@"+status.BaseDomain) {
		return fmt.Errorf("email must use @%s", status.BaseDomain)
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	if _, err := s.st.CreateUser(ctx, email, hash, "user", models.UserPending); err != nil {
		return err
	}
	_, err = s.st.CreateRegistration(ctx, email, ip, hashUA(userAgent), captchaOK)
	return err
}

func (s *Service) Login(ctx context.Context, email, password, ip, userAgent string) (rawToken string, user models.User, err error) {
	u, err := s.st.GetUserByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		return "", models.User{}, ErrInvalidCredentials
	}
	if s.usesPAMAuth() {
		if err := s.verifyMailCredentials(ctx, u.Email, password); err != nil {
			return "", models.User{}, ErrInvalidCredentials
		}
	} else {
		if !auth.VerifyPassword(u.PasswordHash, password) {
			return "", models.User{}, ErrInvalidCredentials
		}
	}
	switch u.Status {
	case models.UserPending:
		return "", models.User{}, ErrPendingApproval
	case models.UserSuspended:
		return "", models.User{}, ErrSuspended
	case models.UserRejected:
		return "", models.User{}, ErrForbidden
	}
	if u.Status != models.UserActive && u.Role != "admin" {
		return "", models.User{}, ErrForbidden
	}

	raw, tokenHash, err := auth.NewOpaqueToken()
	if err != nil {
		return "", models.User{}, err
	}
	mailSecret, err := util.EncryptString(s.encryptKey, password)
	if err != nil {
		return "", models.User{}, err
	}

	now := time.Now().UTC()
	sess := models.Session{
		ID:            uuid.NewString(),
		UserID:        u.ID,
		TokenHash:     tokenHash,
		MailSecret:    mailSecret,
		IPHint:        ip,
		UserAgentHash: hashUA(userAgent),
		ExpiresAt:     now.Add(s.cfg.SessionAbsoluteDuration()),
		IdleExpiresAt: now.Add(s.cfg.SessionIdleDuration()),
		CreatedAt:     now,
		LastSeenAt:    now,
	}
	if err := s.st.CreateSession(ctx, sess); err != nil {
		return "", models.User{}, err
	}
	_ = s.st.TouchUserLastLogin(ctx, u.ID, now)
	return raw, u, nil
}

func (s *Service) ValidateSession(ctx context.Context, rawToken string) (models.User, models.Session, error) {
	sum := sha256.Sum256([]byte(rawToken))
	hash := hex.EncodeToString(sum[:])
	sess, err := s.st.GetSessionByTokenHash(ctx, hash)
	if err != nil {
		return models.User{}, models.Session{}, ErrInvalidCredentials
	}
	now := time.Now().UTC()
	if sess.RevokedAt != nil || now.After(sess.ExpiresAt) || now.After(sess.IdleExpiresAt) {
		return models.User{}, models.Session{}, ErrInvalidCredentials
	}
	_ = s.st.TouchSession(ctx, sess.ID, now.Add(s.cfg.SessionIdleDuration()))

	u, err := s.st.GetUserByID(ctx, sess.UserID)
	if err != nil {
		return models.User{}, models.Session{}, ErrInvalidCredentials
	}
	if u.Status != models.UserActive && u.Role != "admin" {
		return models.User{}, models.Session{}, ErrForbidden
	}
	return u, sess, nil
}

func (s *Service) SessionMailPassword(sess models.Session) (string, error) {
	if strings.TrimSpace(sess.MailSecret) == "" {
		return "", fmt.Errorf("missing mail credentials")
	}
	return util.DecryptString(s.encryptKey, sess.MailSecret)
}

func (s *Service) Logout(ctx context.Context, rawToken string) error {
	sum := sha256.Sum256([]byte(rawToken))
	hash := hex.EncodeToString(sum[:])
	sess, err := s.st.GetSessionByTokenHash(ctx, hash)
	if err != nil {
		return nil
	}
	return s.st.RevokeSession(ctx, sess.ID)
}

func (s *Service) ListRegistrations(ctx context.Context, status string, limit, offset int) ([]models.Registration, error) {
	return s.st.ListRegistrations(ctx, status, limit, offset)
}

func (s *Service) ApproveRegistration(ctx context.Context, adminID, regID string) error {
	r, err := s.st.GetRegistrationByID(ctx, regID)
	if err != nil {
		return err
	}
	if r.Status != "pending" {
		return store.ErrConflict
	}
	u, err := s.st.GetUserByEmail(ctx, r.Email)
	if err != nil {
		return err
	}
	if err := s.provision.UpsertActiveUser(ctx, u.Email, u.PasswordHash); err != nil {
		msg := err.Error()
		_ = s.st.UpdateProvisionState(ctx, u.ID, "error", &msg)
		return err
	}
	_ = s.st.UpdateProvisionState(ctx, u.ID, "ok", nil)
	if err := s.st.SetRegistrationDecision(ctx, regID, "approved", adminID, ""); err != nil {
		return err
	}
	if err := s.st.UpdateUserStatus(ctx, u.ID, models.UserActive, &adminID); err != nil {
		return err
	}
	meta, _ := json.Marshal(map[string]string{"registration_id": regID, "user_id": u.ID})
	return s.st.InsertAudit(ctx, adminID, "registration.approve", u.ID, string(meta))
}

func (s *Service) RejectRegistration(ctx context.Context, adminID, regID, reason string) error {
	r, err := s.st.GetRegistrationByID(ctx, regID)
	if err != nil {
		return err
	}
	if r.Status != "pending" {
		return store.ErrConflict
	}
	u, err := s.st.GetUserByEmail(ctx, r.Email)
	if err != nil {
		return err
	}
	if err := s.st.SetRegistrationDecision(ctx, regID, "rejected", adminID, reason); err != nil {
		return err
	}
	if err := s.st.UpdateUserStatus(ctx, u.ID, models.UserRejected, nil); err != nil {
		return err
	}
	meta, _ := json.Marshal(map[string]string{"registration_id": regID, "user_id": u.ID, "reason": reason})
	return s.st.InsertAudit(ctx, adminID, "registration.reject", u.ID, string(meta))
}

func (s *Service) SuspendUser(ctx context.Context, adminID, userID string) error {
	u, err := s.st.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.provision.DisableUser(ctx, u.Email); err != nil {
		return err
	}
	if err := s.st.UpdateUserStatus(ctx, userID, models.UserSuspended, nil); err != nil {
		return err
	}
	if err := s.st.RevokeUserSessions(ctx, userID); err != nil {
		return err
	}
	return s.st.InsertAudit(ctx, adminID, "user.suspend", userID, `{}`)
}

func (s *Service) UnsuspendUser(ctx context.Context, adminID, userID string) error {
	u, err := s.st.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.provision.UpsertActiveUser(ctx, u.Email, u.PasswordHash); err != nil {
		msg := err.Error()
		_ = s.st.UpdateProvisionState(ctx, u.ID, "error", &msg)
		return err
	}
	_ = s.st.UpdateProvisionState(ctx, u.ID, "ok", nil)
	if err := s.st.UpdateUserStatus(ctx, userID, models.UserActive, &adminID); err != nil {
		return err
	}
	return s.st.InsertAudit(ctx, adminID, "user.unsuspend", userID, `{}`)
}

func (s *Service) ListUsers(ctx context.Context, limit, offset int) ([]models.User, error) {
	return s.st.ListUsers(ctx, limit, offset)
}

func (s *Service) ListAudit(ctx context.Context, limit, offset int) ([]models.AuditEntry, error) {
	return s.st.ListAudit(ctx, limit, offset)
}

func (s *Service) RetryProvisionUser(ctx context.Context, adminID, userID string) error {
	u, err := s.st.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.provision.UpsertActiveUser(ctx, u.Email, u.PasswordHash); err != nil {
		msg := err.Error()
		_ = s.st.UpdateProvisionState(ctx, u.ID, "error", &msg)
		return err
	}
	_ = s.st.UpdateProvisionState(ctx, u.ID, "ok", nil)
	meta, _ := json.Marshal(map[string]string{"user_id": userID})
	return s.st.InsertAudit(ctx, adminID, "user.retry_provision", userID, string(meta))
}

func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	if s.usesPAMAuth() {
		return ErrPAMPasswordManaged
	}
	u, err := s.st.GetUserByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		// don't leak existence
		return nil
	}
	raw, hash, err := auth.NewOpaqueToken()
	if err != nil {
		return err
	}
	if _, err := s.st.CreatePasswordResetToken(ctx, u.ID, hash, time.Now().UTC().Add(30*time.Minute)); err != nil {
		return err
	}
	return s.sender.SendPasswordReset(ctx, u.Email, raw)
}

func (s *Service) ConfirmPasswordReset(ctx context.Context, rawToken, newPassword string) error {
	if s.usesPAMAuth() {
		return ErrPAMPasswordManaged
	}
	if err := s.ValidatePassword(newPassword); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(sum[:])
	t, err := s.st.ConsumePasswordResetToken(ctx, tokenHash)
	if err != nil {
		return ErrInvalidCredentials
	}
	h, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.st.UpdateUserPasswordHash(ctx, t.UserID, h); err != nil {
		return err
	}
	u, err := s.st.GetUserByID(ctx, t.UserID)
	if err == nil {
		if err := s.provision.UpsertActiveUser(ctx, u.Email, h); err != nil {
			msg := err.Error()
			_ = s.st.UpdateProvisionState(ctx, u.ID, "error", &msg)
		} else {
			_ = s.st.UpdateProvisionState(ctx, u.ID, "ok", nil)
		}
	}
	_ = s.st.RevokeUserSessions(ctx, t.UserID)
	return nil
}

func (s *Service) AdminResetPassword(ctx context.Context, adminID, userID, newPassword string) error {
	if s.usesPAMAuth() {
		return ErrPAMPasswordManaged
	}
	if err := s.ValidatePassword(newPassword); err != nil {
		return err
	}
	h, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.st.UpdateUserPasswordHash(ctx, userID, h); err != nil {
		return err
	}
	u, err := s.st.GetUserByID(ctx, userID)
	if err == nil {
		if err := s.provision.UpsertActiveUser(ctx, u.Email, h); err != nil {
			msg := err.Error()
			_ = s.st.UpdateProvisionState(ctx, u.ID, "error", &msg)
		} else {
			_ = s.st.UpdateProvisionState(ctx, u.ID, "ok", nil)
		}
	}
	_ = s.st.RevokeUserSessions(ctx, userID)
	meta, _ := json.Marshal(map[string]string{"user_id": userID})
	return s.st.InsertAudit(ctx, adminID, "user.reset_password", userID, string(meta))
}

func (s *Service) Mail() mail.Client   { return s.mail }
func (s *Service) Store() *store.Store { return s.st }

func (s *Service) SetupStatus(ctx context.Context) (SetupStatus, error) {
	baseDomain, err := s.baseDomain(ctx)
	if err != nil {
		return SetupStatus{}, err
	}
	adminCount, err := s.st.CountAdmins(ctx)
	if err != nil {
		return SetupStatus{}, err
	}
	return SetupStatus{
		Required:          adminCount == 0,
		BaseDomain:        baseDomain,
		DefaultAdminEmail: defaultAdminEmail(baseDomain),
		AuthMode:          s.cfg.DovecotAuthMode,
		PasswordMinLength: s.cfg.PasswordMinLength,
		PasswordMaxLength: s.cfg.PasswordMaxLength,
		PasswordClassMin:  3,
	}, nil
}

func (s *Service) CompleteSetup(ctx context.Context, req SetupCompleteRequest, ip, userAgent string) (string, models.User, error) {
	adminCount, err := s.st.CountAdmins(ctx)
	if err != nil {
		return "", models.User{}, err
	}
	if adminCount > 0 {
		return "", models.User{}, errors.New("setup already completed")
	}

	baseDomain := normalizeDomain(req.BaseDomain)
	if baseDomain == "" {
		baseDomain = normalizeDomain(s.cfg.BaseDomain)
	}
	if !domainRx.MatchString(baseDomain) {
		return "", models.User{}, errors.New("invalid domain name")
	}

	adminEmail := strings.ToLower(strings.TrimSpace(req.AdminEmail))
	if adminEmail == "" {
		adminEmail = defaultAdminEmail(baseDomain)
	}
	parsed, err := netmail.ParseAddress(adminEmail)
	if err != nil {
		return "", models.User{}, errors.New("invalid admin email")
	}
	adminEmail = strings.ToLower(strings.TrimSpace(parsed.Address))
	if !strings.HasSuffix(adminEmail, "@"+baseDomain) {
		return "", models.User{}, fmt.Errorf("admin email must use @%s", baseDomain)
	}

	if s.usesPAMAuth() {
		if strings.TrimSpace(req.AdminPassword) == "" {
			return "", models.User{}, errors.New("admin password is required")
		}
		if err := s.verifyMailCredentials(ctx, adminEmail, req.AdminPassword); err != nil {
			if isMailConnectivityError(err) {
				return "", models.User{}, fmt.Errorf("%w: %v", ErrPAMVerifierDown, err)
			}
			return "", models.User{}, errors.New("admin credentials are not valid for Dovecot/PAM")
		}
	} else {
		if err := s.ValidatePassword(req.AdminPassword); err != nil {
			return "", models.User{}, err
		}
	}

	passwordHash, err := auth.HashPassword(req.AdminPassword)
	if err != nil {
		return "", models.User{}, err
	}
	if err := s.st.EnsureAdmin(ctx, adminEmail, passwordHash); err != nil {
		return "", models.User{}, err
	}
	adminUser, err := s.st.GetUserByEmail(ctx, adminEmail)
	if err != nil {
		return "", models.User{}, err
	}
	if err := s.st.UpsertSetting(ctx, "base_domain", baseDomain); err != nil {
		return "", models.User{}, err
	}
	if err := s.st.UpsertSetting(ctx, "primary_admin_email", adminEmail); err != nil {
		return "", models.User{}, err
	}
	if err := s.st.UpsertSetting(ctx, "setup_completed_at", time.Now().UTC().Format(time.RFC3339)); err != nil {
		return "", models.User{}, err
	}
	region := strings.TrimSpace(req.Region)
	if region != "" {
		if err := s.st.UpsertSetting(ctx, "region", region); err != nil {
			return "", models.User{}, err
		}
	}

	if err := s.provision.UpsertActiveUser(ctx, adminEmail, passwordHash); err != nil {
		msg := err.Error()
		_ = s.st.UpdateProvisionState(ctx, adminUser.ID, "error", &msg)
		return "", models.User{}, err
	}
	_ = s.st.UpdateProvisionState(ctx, adminUser.ID, "ok", nil)

	return s.Login(ctx, adminEmail, req.AdminPassword, ip, userAgent)
}

func (s *Service) baseDomain(ctx context.Context) (string, error) {
	if v, ok, err := s.st.GetSetting(ctx, "base_domain"); err != nil {
		return "", err
	} else if ok {
		domain := normalizeDomain(v)
		if domain != "" {
			return domain, nil
		}
	}
	domain := normalizeDomain(s.cfg.BaseDomain)
	if domain == "" {
		domain = "example.com"
	}
	return domain, nil
}

func normalizeDomain(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "https://")
	v = strings.TrimPrefix(v, "http://")
	v = strings.TrimSuffix(v, "/")
	v = strings.TrimSuffix(v, ".")
	return v
}

func defaultAdminEmail(domain string) string {
	if domain == "" {
		return "webmaster@example.com"
	}
	return "webmaster@" + domain
}

func (s *Service) ValidatePassword(pw string) error {
	pw = strings.TrimSpace(pw)
	if pw == "" {
		return errors.New("password is required")
	}
	if len(pw) < s.cfg.PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters", s.cfg.PasswordMinLength)
	}
	if len(pw) > s.cfg.PasswordMaxLength {
		return fmt.Errorf("password must be at most %d characters", s.cfg.PasswordMaxLength)
	}
	classes := 0
	if strings.IndexFunc(pw, func(r rune) bool { return r >= 'a' && r <= 'z' }) >= 0 {
		classes++
	}
	if strings.IndexFunc(pw, func(r rune) bool { return r >= 'A' && r <= 'Z' }) >= 0 {
		classes++
	}
	if strings.IndexFunc(pw, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0 {
		classes++
	}
	if strings.IndexFunc(pw, func(r rune) bool {
		return (r >= 33 && r <= 47) || (r >= 58 && r <= 64) || (r >= 91 && r <= 96) || (r >= 123 && r <= 126)
	}) >= 0 {
		classes++
	}
	if classes < 3 {
		return errors.New("password must include at least 3 character classes (lower/upper/number/symbol)")
	}
	return nil
}

func (s *Service) usesPAMAuth() bool {
	return strings.EqualFold(strings.TrimSpace(s.cfg.DovecotAuthMode), "pam")
}

func (s *Service) verifyMailCredentials(ctx context.Context, email, password string) error {
	if strings.TrimSpace(email) == "" || strings.TrimSpace(password) == "" {
		return ErrInvalidCredentials
	}
	_, err := s.mail.ListMailboxes(ctx, email, password)
	return err
}

func isMailConnectivityError(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	connectivityHints := []string{
		"dial",
		"connect",
		"timeout",
		"i/o timeout",
		"no such host",
		"connection refused",
		"tls",
		"certificate",
		"eof",
		"network is unreachable",
	}
	for _, hint := range connectivityHints {
		if strings.Contains(m, hint) {
			return true
		}
	}
	return false
}
