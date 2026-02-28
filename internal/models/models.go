package models

import "time"

type UserStatus string

const (
	UserPending   UserStatus = "pending"
	UserActive    UserStatus = "active"
	UserSuspended UserStatus = "suspended"
	UserRejected  UserStatus = "rejected"
)

type User struct {
	ID             string
	Email          string
	MailLogin      *string
	PasswordHash   string
	Role           string
	Status         UserStatus
	ProvisionState string
	ProvisionError *string
	CreatedAt      time.Time
	ApprovedAt     *time.Time
	ApprovedBy     *string
	LastLoginAt    *time.Time
}

type Registration struct {
	ID            string
	Email         string
	SourceIP      string
	UserAgentHash string
	CaptchaOK     bool
	Status        string
	CreatedAt     time.Time
	DecidedAt     *time.Time
	DecidedBy     *string
	Reason        *string
}

type Session struct {
	ID            string
	UserID        string
	TokenHash     string
	MailSecret    string
	IPHint        string
	UserAgentHash string
	ExpiresAt     time.Time
	IdleExpiresAt time.Time
	CreatedAt     time.Time
	LastSeenAt    time.Time
	RevokedAt     *time.Time
}

type PasswordResetToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

type AuditEntry struct {
	ID           string    `json:"id"`
	ActorUserID  string    `json:"actor_user_id"`
	Action       string    `json:"action"`
	Target       string    `json:"target"`
	MetadataJSON string    `json:"metadata_json"`
	CreatedAt    time.Time `json:"created_at"`
}
