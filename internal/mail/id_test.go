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
