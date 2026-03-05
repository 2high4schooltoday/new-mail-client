package mail

import "testing"

func TestMessageIDRoundTrip(t *testing.T) {
	id := EncodeMessageID("INBOX", 42)
	mbox, uid, err := DecodeMessageID(id)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if mbox != "INBOX" || uid != 42 {
		t.Fatalf("roundtrip mismatch: got %s %d", mbox, uid)
	}
}

func TestAttachmentIDRoundTrip(t *testing.T) {
	id := EncodeAttachmentID("abc123", 7)
	msgID, part, err := DecodeAttachmentID(id)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if msgID != "abc123" || part != 7 {
		t.Fatalf("roundtrip mismatch: got %s %d", msgID, part)
	}
}

func TestScopeIndexedMessageID(t *testing.T) {
	accountID := "acct-123"
	legacyID := "legacy-message-id"
	scoped := ScopeIndexedMessageID(accountID, legacyID)
	if scoped == legacyID {
		t.Fatalf("expected scoped message id to differ from legacy id")
	}
	if !IsScopedIndexedMessageID(scoped) {
		t.Fatalf("expected scoped message id to be recognized")
	}
	if got := NormalizeIndexedMessageID(accountID, legacyID); got != scoped {
		t.Fatalf("normalize mismatch: got %q want %q", got, scoped)
	}
	if got := NormalizeIndexedMessageID(accountID, scoped); got != scoped {
		t.Fatalf("normalize should keep scoped id unchanged")
	}
}

func TestScopeIndexedThreadID(t *testing.T) {
	accountID := "acct-123"
	legacyID := "thread-legacy"
	scoped := ScopeIndexedThreadID(accountID, legacyID)
	if scoped == legacyID {
		t.Fatalf("expected scoped thread id to differ from legacy id")
	}
	if !IsScopedIndexedThreadID(scoped) {
		t.Fatalf("expected scoped thread id to be recognized")
	}
	if got := NormalizeIndexedThreadID(accountID, legacyID); got != scoped {
		t.Fatalf("normalize mismatch: got %q want %q", got, scoped)
	}
	if got := NormalizeIndexedThreadID(accountID, scoped); got != scoped {
		t.Fatalf("normalize should keep scoped id unchanged")
	}
}
