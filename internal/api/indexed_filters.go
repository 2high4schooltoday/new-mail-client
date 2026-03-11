package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"despatch/internal/mail"
	"despatch/internal/models"
)

func normalizeIndexedFilterAccountIDs(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func queryBoolEnabled(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func indexedFilterLocation(ctx context.Context, h *Handlers, userID string) *time.Location {
	prefs, err := h.svc.Store().GetUserPreferences(ctx, userID)
	if err != nil {
		return time.UTC
	}
	name := strings.TrimSpace(prefs.Timezone)
	if name == "" {
		return time.UTC
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return time.UTC
	}
	return loc
}

func parseIndexedCalendarDate(raw string, loc *time.Location, endOfDay bool) (time.Time, bool, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return time.Time{}, false, nil
	}
	parsed, err := time.ParseInLocation("2006-01-02", trimmed, loc)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("invalid date %q", trimmed)
	}
	if endOfDay {
		parsed = parsed.AddDate(0, 0, 1).Add(-time.Nanosecond)
	}
	return parsed.UTC(), true, nil
}

func applyLegacyIndexedViewFilter(view string, filter *models.IndexedMessageFilter) {
	if filter == nil {
		return
	}
	switch strings.ToLower(strings.TrimSpace(view)) {
	case "unread":
		filter.Unread = true
	case "flagged":
		filter.Flagged = true
	case "attachments":
		filter.HasAttachments = true
	case "waiting":
		filter.Waiting = true
	}
}

func resolveIndexedFilteredAccounts(accounts []models.MailAccount, filterAccountIDs []string) ([]models.MailAccount, error) {
	filterAccountIDs = normalizeIndexedFilterAccountIDs(filterAccountIDs)
	if len(filterAccountIDs) == 0 {
		return accounts, nil
	}
	allowed := make(map[string]models.MailAccount, len(accounts))
	for _, account := range accounts {
		allowed[strings.TrimSpace(account.ID)] = account
	}
	filtered := make([]models.MailAccount, 0, len(filterAccountIDs))
	for _, accountID := range filterAccountIDs {
		account, ok := allowed[accountID]
		if !ok {
			return nil, fmt.Errorf("filter_account_id %q does not belong to current user scope", accountID)
		}
		filtered = append(filtered, account)
	}
	return filtered, nil
}

func (h *Handlers) parseIndexedMessageFilter(ctx context.Context, u models.User, r *http.Request, accounts []models.MailAccount) (models.IndexedMessageFilter, []models.MailAccount, error) {
	filter := models.IndexedMessageFilter{
		Query:          strings.TrimSpace(r.URL.Query().Get("q")),
		From:           strings.TrimSpace(r.URL.Query().Get("from")),
		To:             strings.TrimSpace(r.URL.Query().Get("to")),
		Subject:        strings.TrimSpace(r.URL.Query().Get("subject")),
		Unread:         queryBoolEnabled(r.URL.Query().Get("unread")),
		Flagged:        queryBoolEnabled(r.URL.Query().Get("flagged")),
		HasAttachments: queryBoolEnabled(r.URL.Query().Get("has_attachments")),
		Waiting:        queryBoolEnabled(r.URL.Query().Get("waiting")),
		AccountIDs:     normalizeIndexedFilterAccountIDs(r.URL.Query()["filter_account_id"]),
	}
	applyLegacyIndexedViewFilter(r.URL.Query().Get("view"), &filter)
	loc := indexedFilterLocation(ctx, h, u.ID)
	var err error
	filter.DateFrom, filter.HasDateFrom, err = parseIndexedCalendarDate(r.URL.Query().Get("date_from"), loc, false)
	if err != nil {
		return models.IndexedMessageFilter{}, nil, err
	}
	filter.DateTo, filter.HasDateTo, err = parseIndexedCalendarDate(r.URL.Query().Get("date_to"), loc, true)
	if err != nil {
		return models.IndexedMessageFilter{}, nil, err
	}
	if filter.HasDateFrom && filter.HasDateTo && filter.DateTo.Before(filter.DateFrom) {
		return models.IndexedMessageFilter{}, nil, fmt.Errorf("date_to must not be earlier than date_from")
	}
	filteredAccounts, err := resolveIndexedFilteredAccounts(accounts, filter.AccountIDs)
	if err != nil {
		return models.IndexedMessageFilter{}, nil, err
	}
	return filter, filteredAccounts, nil
}

func (h *Handlers) queryIndexedMessages(
	ctx context.Context,
	u models.User,
	accounts []models.MailAccount,
	mailbox string,
	mailboxFilters map[string][]string,
	filter models.IndexedMessageFilter,
	page,
	pageSize int,
	sortOrder string,
	preferSearch bool,
) ([]models.IndexedMessage, int, error) {
	accountIDs := indexedScopeAccountIDs(accounts)
	if len(accountIDs) == 0 {
		return []models.IndexedMessage{}, 0, nil
	}
	offset := (page - 1) * pageSize
	useSearch := preferSearch || strings.TrimSpace(filter.Query) != ""
	multiAccount := len(accountIDs) > 1
	if filter.Waiting {
		selfEmails := indexedAccountsSelfEmails(ctx, h, u, accounts)
		sampleLimit := pageSize * page
		if sampleLimit < 200 {
			sampleLimit = 200
		}
		if sampleLimit > 600 {
			sampleLimit = 600
		}
		candidateFilter := filter
		candidateFilter.Waiting = false
		var recent []models.IndexedMessage
		var err error
		switch {
		case multiAccount && useSearch:
			recent, _, err = h.svc.Store().SearchIndexedMessagesByAccounts(ctx, accountIDs, mailboxFilters, candidateFilter, sampleLimit, 0)
		case multiAccount:
			recent, _, err = h.svc.Store().ListIndexedMessagesByAccounts(ctx, accountIDs, mailboxFilters, candidateFilter, sortOrder, sampleLimit, 0)
		case useSearch:
			recent, _, err = h.svc.Store().SearchIndexedMessages(ctx, accountIDs[0], mailbox, candidateFilter, sampleLimit, 0)
		default:
			recent, _, err = h.svc.Store().ListIndexedMessages(ctx, accountIDs[0], mailbox, candidateFilter, sortOrder, sampleLimit, 0)
		}
		if err != nil {
			return nil, 0, err
		}
		filtered := filterWaitingIndexedMessages(recent, selfEmails)
		total := len(filtered)
		if offset > total {
			offset = total
		}
		end := offset + pageSize
		if end > total {
			end = total
		}
		if offset >= end {
			return []models.IndexedMessage{}, total, nil
		}
		return append([]models.IndexedMessage(nil), filtered[offset:end]...), total, nil
	}

	switch {
	case multiAccount && useSearch:
		return h.svc.Store().SearchIndexedMessagesByAccounts(ctx, accountIDs, mailboxFilters, filter, pageSize, offset)
	case multiAccount:
		return h.svc.Store().ListIndexedMessagesByAccounts(ctx, accountIDs, mailboxFilters, filter, sortOrder, pageSize, offset)
	case useSearch:
		return h.svc.Store().SearchIndexedMessages(ctx, accountIDs[0], mailbox, filter, pageSize, offset)
	default:
		return h.svc.Store().ListIndexedMessages(ctx, accountIDs[0], mailbox, filter, sortOrder, pageSize, offset)
	}
}

func presentIndexedMessageSummaries(items []models.IndexedMessage) []mail.MessageSummary {
	out := make([]mail.MessageSummary, 0, len(items))
	for _, item := range items {
		out = append(out, indexedMessageSummary(item))
	}
	return out
}
