package service

import (
	"context"
	"strings"

	"despatch/internal/models"
)

const (
	AuthStageAuthenticated  = "authenticated"
	AuthStageMFARequired    = "mfa_required"
	AuthStageMFASetupNeeded = "mfa_setup_required"
	MFAPreferenceNone       = "none"
	MFAPreferenceTOTP       = "totp"
	MFAPreferenceWebAuthn   = "webauthn"
	MFASetupStepMethod      = "method"
	MFASetupStepBackup      = "backup"
)

type MFAStage struct {
	AuthStage        string `json:"auth_stage"`
	MFARequired      bool   `json:"mfa_required"`
	MFASetupRequired bool   `json:"mfa_setup_required"`
	MFASetupMethod   string `json:"mfa_setup_method,omitempty"`
	MFASetupStep     string `json:"mfa_setup_step,omitempty"`
	MFAEnrolled      bool   `json:"mfa_enrolled"`
	LegacyMFAPrompt  bool   `json:"legacy_mfa_prompt"`
	MFAPreference    string `json:"mfa_preference"`
}

func NormalizeMFAPreference(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case MFAPreferenceTOTP:
		return MFAPreferenceTOTP
	case MFAPreferenceWebAuthn:
		return MFAPreferenceWebAuthn
	default:
		return MFAPreferenceNone
	}
}

func (s *Service) ResolveMFAStage(ctx context.Context, user models.User, sess *models.Session) (MFAStage, error) {
	mfaStatus, err := s.st.GetMFAStatus(ctx, user.ID)
	if err != nil {
		return MFAStage{}, err
	}

	pref := NormalizeMFAPreference(user.MFAPreference)
	hasEnabledTOTP := mfaStatus.TOTPEnabled
	hasWebAuthn := mfaStatus.WebAuthnCount > 0
	mfaEnrolled := hasEnabledTOTP || hasWebAuthn
	if strings.EqualFold(strings.TrimSpace(user.Role), "admin") {
		enforced, err := s.isAdminMFAEnforced(ctx)
		if err != nil {
			return MFAStage{}, err
		}
		if enforced && pref == MFAPreferenceNone {
			switch {
			case hasEnabledTOTP:
				pref = MFAPreferenceTOTP
			case hasWebAuthn:
				pref = MFAPreferenceWebAuthn
			default:
				pref = MFAPreferenceTOTP
			}
		}
	}

	setupRequired := false
	setupMethod := ""
	setupStep := ""
	switch pref {
	case MFAPreferenceTOTP:
		setupRequired = !hasEnabledTOTP
		if setupRequired {
			setupMethod = MFAPreferenceTOTP
			setupStep = MFASetupStepMethod
		}
	case MFAPreferenceWebAuthn:
		setupRequired = !hasWebAuthn
		if setupRequired {
			setupMethod = MFAPreferenceWebAuthn
			setupStep = MFASetupStepMethod
		}
	}

	if !setupRequired && (pref == MFAPreferenceTOTP || pref == MFAPreferenceWebAuthn) && !user.MFABackupCompleted {
		setupRequired = true
		setupMethod = pref
		setupStep = MFASetupStepBackup
		if setupMethod == "" {
			setupMethod = pref
		}
	}

	mfaRequired := false
	if !setupRequired && mfaEnrolled {
		if sess == nil || sess.MFAVerifiedAt == nil {
			mfaRequired = true
		}
	}

	authStage := AuthStageAuthenticated
	if setupRequired {
		authStage = AuthStageMFASetupNeeded
	} else if mfaRequired {
		authStage = AuthStageMFARequired
	}

	return MFAStage{
		AuthStage:        authStage,
		MFARequired:      mfaRequired,
		MFASetupRequired: setupRequired,
		MFASetupMethod:   setupMethod,
		MFASetupStep:     setupStep,
		MFAEnrolled:      mfaEnrolled,
		LegacyMFAPrompt:  user.LegacyMFAPromptPending,
		MFAPreference:    pref,
	}, nil
}

func (s *Service) isAdminMFAEnforced(ctx context.Context) (bool, error) {
	return s.AdminMFARequired(ctx)
}
