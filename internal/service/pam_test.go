package service

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"mailclient/internal/auth"
	"mailclient/internal/config"
	"mailclient/internal/db"
	"mailclient/internal/mail"
	"mailclient/internal/models"
	"mailclient/internal/store"
)

type pamTestMailClient struct {
	acceptPassword string
	acceptedUsers  map[string]bool
	failWith       error
}

func (m pamTestMailClient) ListMailboxes(ctx context.Context, user, pass string) ([]mail.Mailbox, error) {
	if m.failWith != nil {
		return nil, m.failWith
	}
	if pass != m.acceptPassword {
		return nil, errors.New("imap auth failed")
	}
	if len(m.acceptedUsers) > 0 && !m.acceptedUsers[user] {
		return nil, errors.New("imap auth failed")
	}
	return []mail.Mailbox{{Name: "INBOX", Messages: 1}}, nil
}
func (m pamTestMailClient) ListMessages(ctx context.Context, user, pass, mailbox string, page, pageSize int) ([]mail.MessageSummary, error) {
	return nil, nil
}
func (m pamTestMailClient) GetMessage(ctx context.Context, user, pass, id string) (mail.Message, error) {
	return mail.Message{}, nil
}
func (m pamTestMailClient) Search(ctx context.Context, user, pass, mailbox, query string, page, pageSize int) ([]mail.MessageSummary, error) {
	return nil, nil
}
func (m pamTestMailClient) Send(ctx context.Context, user, pass string, req mail.SendRequest) error {
	return nil
}
func (m pamTestMailClient) SetFlags(ctx context.Context, user, pass, id string, flags []string) error {
	return nil
}
func (m pamTestMailClient) Move(ctx context.Context, user, pass, id, mailbox string) error {
	return nil
}
func (m pamTestMailClient) GetAttachment(ctx context.Context, user, pass, attachmentID string) (mail.AttachmentContent, error) {
	return mail.AttachmentContent{}, nil
}
func (m pamTestMailClient) GetAttachmentStream(ctx context.Context, user, pass, attachmentID string) (mail.AttachmentMeta, io.ReadCloser, error) {
	return mail.AttachmentMeta{}, nil, errors.New("not implemented")
}

func newPAMTestService(t *testing.T, acceptedPass string, acceptedUsers ...string) (*Service, *store.Store) {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "app.db")
	sqdb, err := db.OpenSQLite(tmp, 2, 1, 5*time.Minute)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sqdb.Close() })
	if err := db.ApplyMigrationFile(sqdb, filepath.Join("..", "..", "migrations", "001_init.sql")); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := db.ApplyMigrationFile(sqdb, filepath.Join("..", "..", "migrations", "002_users_mail_login.sql")); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	st := store.New(sqdb)
	cfg := config.Config{
		DovecotAuthMode:     "pam",
		SessionEncryptKey:   "this_is_a_test_session_key_that_is_long_enough_123456",
		SessionIdleMinutes:  30,
		SessionAbsoluteHour: 24,
	}
	accepted := map[string]bool{}
	for _, v := range acceptedUsers {
		accepted[v] = true
	}
	svc := New(cfg, st, pamTestMailClient{acceptPassword: acceptedPass, acceptedUsers: accepted}, mail.NoopProvisioner{}, nil)
	return svc, st
}

func TestPAMModeLoginUsesMailCredentials(t *testing.T) {
	ctx := context.Background()
	svc, st := newPAMTestService(t, "PamPass123!")

	localHash, err := auth.HashPassword("LocalOnly123!")
	if err != nil {
		t.Fatalf("hash local: %v", err)
	}
	u, err := st.CreateUser(ctx, "alice@example.com", localHash, "user", models.UserActive)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := st.UpdateProvisionState(ctx, u.ID, "ok", nil); err != nil {
		t.Fatalf("set provision state: %v", err)
	}

	if _, _, err := svc.Login(ctx, "alice@example.com", "LocalOnly123!", "127.0.0.1", "test-agent"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials for local hash password, got: %v", err)
	}
	if _, _, err := svc.Login(ctx, "alice@example.com", "PamPass123!", "127.0.0.1", "test-agent"); err != nil {
		t.Fatalf("expected PAM-backed login success, got: %v", err)
	}
}

func TestPAMModeDisablesPasswordResetOperations(t *testing.T) {
	ctx := context.Background()
	svc, _ := newPAMTestService(t, "PamPass123!")

	if err := svc.RequestPasswordReset(ctx, "alice@example.com"); !errors.Is(err, ErrPAMPasswordManaged) {
		t.Fatalf("expected RequestPasswordReset to return ErrPAMPasswordManaged, got: %v", err)
	}
	if err := svc.ConfirmPasswordReset(ctx, "token", "NewPassword123!"); !errors.Is(err, ErrPAMPasswordManaged) {
		t.Fatalf("expected ConfirmPasswordReset to return ErrPAMPasswordManaged, got: %v", err)
	}
	if err := svc.AdminResetPassword(ctx, "admin-id", "user-id", "NewPassword123!"); !errors.Is(err, ErrPAMPasswordManaged) {
		t.Fatalf("expected AdminResetPassword to return ErrPAMPasswordManaged, got: %v", err)
	}
}

func TestPAMSetupDetectsConnectivityErrors(t *testing.T) {
	ctx := context.Background()
	tmp := filepath.Join(t.TempDir(), "app.db")
	sqdb, err := db.OpenSQLite(tmp, 2, 1, 5*time.Minute)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sqdb.Close() })
	if err := db.ApplyMigrationFile(sqdb, filepath.Join("..", "..", "migrations", "001_init.sql")); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := db.ApplyMigrationFile(sqdb, filepath.Join("..", "..", "migrations", "002_users_mail_login.sql")); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	st := store.New(sqdb)
	cfg := config.Config{
		DovecotAuthMode:     "pam",
		SessionEncryptKey:   "this_is_a_test_session_key_that_is_long_enough_123456",
		SessionIdleMinutes:  30,
		SessionAbsoluteHour: 24,
		BaseDomain:          "example.com",
	}
	svc := New(cfg, st, pamTestMailClient{failWith: errors.New("dial tcp 127.0.0.1:993: connect: connection refused")}, mail.NoopProvisioner{}, nil)

	_, _, err = svc.CompleteSetup(ctx, SetupCompleteRequest{
		BaseDomain:    "example.com",
		AdminEmail:    "webmaster@example.com",
		AdminPassword: "AnyPassword123!",
		Region:        "us-east",
	}, "127.0.0.1", "agent")
	if !errors.Is(err, ErrPAMVerifierDown) {
		t.Fatalf("expected ErrPAMVerifierDown, got: %v", err)
	}
}

func TestPAMSetupFallsBackToLocalPartAndPersistsLogin(t *testing.T) {
	ctx := context.Background()
	svc, st := newPAMTestService(t, "PamPass123!", "webmaster")

	_, user, err := svc.CompleteSetup(ctx, SetupCompleteRequest{
		BaseDomain:    "example.com",
		AdminEmail:    "webmaster@example.com",
		AdminPassword: "PamPass123!",
		Region:        "us-east",
	}, "127.0.0.1", "agent")
	if err != nil {
		t.Fatalf("expected setup success with localpart fallback, got: %v", err)
	}
	if user.MailLogin == nil || *user.MailLogin != "webmaster" {
		t.Fatalf("expected mail_login to be webmaster, got: %#v", user.MailLogin)
	}

	dbUser, err := st.GetUserByEmail(ctx, "webmaster@example.com")
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	if dbUser.MailLogin == nil || *dbUser.MailLogin != "webmaster" {
		t.Fatalf("expected persisted mail_login webmaster, got: %#v", dbUser.MailLogin)
	}
}

func TestPAMSetupAcceptsExplicitMailboxLoginOverride(t *testing.T) {
	ctx := context.Background()
	svc, st := newPAMTestService(t, "PamPass123!", "custom_login")

	_, user, err := svc.CompleteSetup(ctx, SetupCompleteRequest{
		BaseDomain:        "example.com",
		AdminEmail:        "webmaster@example.com",
		AdminMailboxLogin: "custom_login",
		AdminPassword:     "PamPass123!",
		Region:            "us-east",
	}, "127.0.0.1", "agent")
	if err != nil {
		t.Fatalf("expected setup success with explicit login override, got: %v", err)
	}
	if user.MailLogin == nil || *user.MailLogin != "custom_login" {
		t.Fatalf("expected mail_login custom_login, got: %#v", user.MailLogin)
	}

	dbUser, err := st.GetUserByEmail(ctx, "webmaster@example.com")
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	if dbUser.MailLogin == nil || *dbUser.MailLogin != "custom_login" {
		t.Fatalf("expected persisted custom mail_login, got: %#v", dbUser.MailLogin)
	}
}

func TestPAMSetupReturnsIdentityErrorWhenNoCandidateAuthenticates(t *testing.T) {
	ctx := context.Background()
	svc, _ := newPAMTestService(t, "PamPass123!", "other_login")

	_, _, err := svc.CompleteSetup(ctx, SetupCompleteRequest{
		BaseDomain:    "example.com",
		AdminEmail:    "webmaster@example.com",
		AdminPassword: "PamPass123!",
		Region:        "us-east",
	}, "127.0.0.1", "agent")
	if err == nil {
		t.Fatalf("expected PAM identity error, got nil")
	}
	var pamErr *PAMCredentialsInvalidError
	if !errors.As(err, &pamErr) {
		t.Fatalf("expected PAMCredentialsInvalidError, got: %T %v", err, err)
	}
	if len(pamErr.Attempts) != 2 || pamErr.Attempts[0] != "webmaster@example.com" || pamErr.Attempts[1] != "webmaster" {
		t.Fatalf("unexpected attempts list: %#v", pamErr.Attempts)
	}
}

func TestMailIdentityPrefersStoredMailLogin(t *testing.T) {
	u := models.User{Email: "webmaster@example.com"}
	if got := MailIdentity(u); got != "webmaster@example.com" {
		t.Fatalf("expected fallback email identity, got %q", got)
	}

	stored := "webmaster"
	u.MailLogin = &stored
	if got := MailIdentity(u); got != "webmaster" {
		t.Fatalf("expected stored mail_login identity, got %q", got)
	}
}
