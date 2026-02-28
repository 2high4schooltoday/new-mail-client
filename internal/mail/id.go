package mail

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

func EncodeMessageID(mailbox string, uid uint32) string {
	raw := fmt.Sprintf("%s|%d", mailbox, uid)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func DecodeMessageID(id string) (mailbox string, uid uint32, err error) {
	b, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return "", 0, fmt.Errorf("invalid message id")
	}
	parts := strings.SplitN(string(b), "|", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid message id")
	}
	u, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return "", 0, fmt.Errorf("invalid message id")
	}
	return parts[0], uint32(u), nil
}

func EncodeAttachmentID(messageID string, part int) string {
	raw := fmt.Sprintf("%s|%d", messageID, part)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func DecodeAttachmentID(attachmentID string) (messageID string, part int, err error) {
	b, err := base64.RawURLEncoding.DecodeString(attachmentID)
	if err != nil {
		return "", 0, fmt.Errorf("invalid attachment id")
	}
	parts := strings.SplitN(string(b), "|", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid attachment id")
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("invalid attachment id")
	}
	if n < 0 {
		return "", 0, fmt.Errorf("invalid attachment id")
	}
	return parts[0], n, nil
}
