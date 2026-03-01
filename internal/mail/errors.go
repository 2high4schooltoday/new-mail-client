package mail

import (
	"errors"
	"fmt"
	"strings"
)

var ErrSMTPSenderRejected = errors.New("smtp sender rejected by policy")

func WrapSMTPSenderRejected(err error) error {
	if err == nil {
		return ErrSMTPSenderRejected
	}
	return fmt.Errorf("%w: %v", ErrSMTPSenderRejected, err)
}

func IsSMTPSenderPolicyError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	hints := []string{
		"sender must match authenticated user",
		"sender address rejected",
		"not owned by user",
		"sender login mismatch",
		"not authorized to send as",
		"must be authenticated as",
		"sender rejected",
	}
	for _, hint := range hints {
		if strings.Contains(msg, hint) {
			return true
		}
	}
	return false
}
