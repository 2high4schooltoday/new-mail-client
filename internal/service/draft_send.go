package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"despatch/internal/mail"
	"despatch/internal/models"
)

func (s *Service) BuildDraftSendRequest(ctx context.Context, u models.User, login, pass string, draft models.Draft) (mail.SendRequest, string, bool, error) {
	sendAccountID := strings.TrimSpace(draft.AccountID)
	if sendAccountID != "" {
		if _, err := s.st.GetMailAccountByID(ctx, u.ID, sendAccountID); err != nil {
			return mail.SendRequest{}, "", false, err
		}
	}
	req := mail.SendRequest{
		To:       splitDraftCSV(draft.ToValue),
		CC:       splitDraftCSV(draft.CCValue),
		BCC:      splitDraftCSV(draft.BCCValue),
		Subject:  draft.Subject,
		Body:     draft.BodyText,
		BodyHTML: draft.BodyHTML,
	}
	attachments, err := s.buildDraftSendAttachments(ctx, u.ID, draft)
	if err != nil {
		return mail.SendRequest{}, "", false, err
	}
	req.Attachments = attachments
	sender, err := s.ResolveComposeSender(ctx, u, draft.FromMode, draft.IdentityID, draft.FromManual)
	if err != nil {
		return mail.SendRequest{}, "", false, err
	}
	req.HeaderFromName = sender.HeaderFromName
	req.HeaderFromEmail = sender.HeaderFromEmail
	req.EnvelopeFrom = sender.EnvelopeFrom
	req.ReplyTo = sender.ReplyTo
	req.From = sender.HeaderFromEmail
	if sender.AccountID != "" {
		sendAccountID = sender.AccountID
	}
	if strings.ToLower(strings.TrimSpace(draft.ComposeMode)) != "reply" || strings.TrimSpace(draft.ContextMessageID) == "" {
		return req, sendAccountID, false, nil
	}
	original, err := s.mail.GetMessage(ctx, login, pass, strings.TrimSpace(draft.ContextMessageID))
	if err != nil {
		return mail.SendRequest{}, "", false, err
	}
	req.InReplyToID = strings.TrimSpace(original.MessageID)
	req.References = append([]string{}, original.References...)
	return req, sendAccountID, true, nil
}

func (s *Service) buildDraftSendAttachments(ctx context.Context, userID string, draft models.Draft) ([]mail.SendAttachment, error) {
	trimmed := strings.TrimSpace(draft.AttachmentsJSON)
	if trimmed == "" || trimmed == "[]" {
		return nil, nil
	}
	var refs []models.DraftAttachment
	if err := json.Unmarshal([]byte(trimmed), &refs); err != nil {
		return nil, fmt.Errorf("invalid attachments_json")
	}
	out := make([]mail.SendAttachment, 0, len(refs))
	for _, ref := range refs {
		attachmentID := strings.TrimSpace(ref.ID)
		if attachmentID == "" {
			continue
		}
		item, err := s.st.GetDraftAttachmentByID(ctx, userID, draft.ID, attachmentID)
		if err != nil {
			return nil, err
		}
		out = append(out, mail.SendAttachment{
			Filename:    item.Filename,
			ContentType: item.ContentType,
			Data:        append([]byte(nil), item.Data...),
			Inline:      item.InlinePart,
			ContentID:   item.ContentID,
		})
	}
	return out, nil
}

func splitDraftCSV(v string) []string {
	out := make([]string, 0, 4)
	seen := map[string]struct{}{}
	for _, item := range strings.Split(v, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
