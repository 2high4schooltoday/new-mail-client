package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"despatch/internal/models"
	"despatch/internal/store"
)

type ResolvedComposeSender struct {
	IdentityID      string
	AccountID       string
	HeaderFromName  string
	HeaderFromEmail string
	EnvelopeFrom    string
	ReplyTo         string
}

func (s *Service) EnsureSessionMailProfile(ctx context.Context, u models.User) (models.SessionMailProfile, error) {
	fromEmail := strings.TrimSpace(MailIdentity(u))
	if fromEmail == "" {
		return models.SessionMailProfile{}, fmt.Errorf("authenticated session mail identity is required")
	}
	profile, err := s.st.GetSessionMailProfile(ctx, u.ID, fromEmail)
	if err == nil {
		return profile, nil
	}
	if err != nil && err != store.ErrNotFound {
		return models.SessionMailProfile{}, err
	}
	return s.st.UpsertSessionMailProfile(ctx, models.SessionMailProfile{
		ID:        uuid.NewString(),
		UserID:    u.ID,
		FromEmail: fromEmail,
	})
}

func (s *Service) ResolveComposeSender(ctx context.Context, u models.User, fromMode, identityID, fromManual string) (ResolvedComposeSender, error) {
	authEmail := strings.TrimSpace(MailIdentity(u))
	if authEmail == "" {
		return ResolvedComposeSender{}, fmt.Errorf("authenticated session mail identity is required")
	}
	sessionProfile, err := s.EnsureSessionMailProfile(ctx, u)
	if err != nil {
		return ResolvedComposeSender{}, err
	}
	switch strings.ToLower(strings.TrimSpace(fromMode)) {
	case "", "default":
		return ResolvedComposeSender{
			IdentityID:      sessionProfile.ID,
			HeaderFromName:  strings.TrimSpace(sessionProfile.DisplayName),
			HeaderFromEmail: authEmail,
			EnvelopeFrom:    authEmail,
			ReplyTo:         strings.TrimSpace(sessionProfile.ReplyTo),
		}, nil
	case "manual":
		manualSender := strings.TrimSpace(fromManual)
		if manualSender == "" {
			manualSender = authEmail
		}
		if !strings.EqualFold(manualSender, authEmail) {
			return ResolvedComposeSender{}, fmt.Errorf("manual sender must match authenticated account email")
		}
		return ResolvedComposeSender{
			IdentityID:      sessionProfile.ID,
			HeaderFromName:  strings.TrimSpace(sessionProfile.DisplayName),
			HeaderFromEmail: authEmail,
			EnvelopeFrom:    authEmail,
			ReplyTo:         strings.TrimSpace(sessionProfile.ReplyTo),
		}, nil
	case "identity":
		identityID = strings.TrimSpace(identityID)
		if identityID == "" {
			return ResolvedComposeSender{}, fmt.Errorf("identity_id is required when from_mode=identity")
		}
		identity, err := s.st.GetMailIdentityByID(ctx, identityID)
		if err == nil {
			account, accountErr := s.st.GetMailAccountByID(ctx, u.ID, identity.AccountID)
			if accountErr != nil {
				return ResolvedComposeSender{}, accountErr
			}
			fromEmail := strings.TrimSpace(identity.FromEmail)
			if fromEmail == "" {
				return ResolvedComposeSender{}, fmt.Errorf("selected identity is missing from_email")
			}
			return ResolvedComposeSender{
				IdentityID:      identity.ID,
				AccountID:       account.ID,
				HeaderFromName:  strings.TrimSpace(identity.DisplayName),
				HeaderFromEmail: fromEmail,
				EnvelopeFrom:    fromEmail,
				ReplyTo:         strings.TrimSpace(identity.ReplyTo),
			}, nil
		}
		if err != store.ErrNotFound {
			return ResolvedComposeSender{}, err
		}
		profile, profileErr := s.st.GetSessionMailProfileByID(ctx, u.ID, identityID)
		if profileErr != nil {
			return ResolvedComposeSender{}, profileErr
		}
		fromEmail := strings.TrimSpace(profile.FromEmail)
		if fromEmail == "" {
			fromEmail = authEmail
		}
		return ResolvedComposeSender{
			IdentityID:      profile.ID,
			HeaderFromName:  strings.TrimSpace(profile.DisplayName),
			HeaderFromEmail: fromEmail,
			EnvelopeFrom:    fromEmail,
			ReplyTo:         strings.TrimSpace(profile.ReplyTo),
		}, nil
	default:
		return ResolvedComposeSender{}, fmt.Errorf("unsupported from_mode")
	}
}
