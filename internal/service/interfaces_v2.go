package service

import (
	"context"

	"despatch/internal/models"
)

// MailIndexer provides indexed-thread/query primitives over synchronized mailbox state.
type MailIndexer interface {
	ListThreads(ctx context.Context, accountID, mailbox, sort string, limit, offset int) ([]models.ThreadSummary, int, error)
	ListMessagesByThread(ctx context.Context, accountID, threadID string, limit, offset int) ([]models.IndexedMessage, error)
	SearchIndexedMessages(ctx context.Context, accountID, mailbox, query string, limit, offset int) ([]models.IndexedMessage, int, error)
	InvalidateAccount(ctx context.Context, accountID string) error
}

// MailSecurityClient delegates parser/security-sensitive work to isolated Rust components.
type MailSecurityClient interface {
	ParseAndClassify(ctx context.Context, accountID, messageID string, raw []byte) (map[string]any, error)
	VerifyAuth(ctx context.Context, accountID, messageID string, raw []byte) (map[string]any, error)
	CryptoOp(ctx context.Context, accountID, op string, payload map[string]any) (map[string]any, error)
}

// ManageSieveClient controls Sieve script lifecycle for an account.
type ManageSieveClient interface {
	ListScripts(ctx context.Context, accountID string) ([]models.SieveScript, error)
	GetScript(ctx context.Context, accountID, scriptName string) (models.SieveScript, error)
	PutScript(ctx context.Context, script models.SieveScript) (models.SieveScript, error)
	ActivateScript(ctx context.Context, accountID, scriptName string) error
	DeleteScript(ctx context.Context, accountID, scriptName string) error
	ValidateScript(ctx context.Context, accountID, scriptBody string) error
}

// MFAService encapsulates multi-factor enrollment and verification lifecycle.
type MFAService interface {
	EnrollTOTP(ctx context.Context, userID, issuer, accountName string) (secret string, otpauthURL string, recoveryCodes []string, err error)
	ConfirmTOTP(ctx context.Context, userID, code string) error
	BeginWebAuthnRegistration(ctx context.Context, userID string) (map[string]any, error)
	FinishWebAuthnRegistration(ctx context.Context, userID string, response map[string]any) error
}
