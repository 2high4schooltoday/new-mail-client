package mail

import "context"

type AuthProvisioner interface {
	UpsertActiveUser(ctx context.Context, email, passwordHash string) error
	DisableUser(ctx context.Context, email string) error
}

type NoopProvisioner struct{}

func (NoopProvisioner) UpsertActiveUser(ctx context.Context, email, passwordHash string) error {
	return nil
}
func (NoopProvisioner) DisableUser(ctx context.Context, email string) error { return nil }
