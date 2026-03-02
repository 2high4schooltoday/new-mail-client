package update

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestContractFixturesUpdaterRequestAndStatus(t *testing.T) {
	base := filepath.Join("..", "..", "rust", "contracts", "tests", "fixtures", "updater")

	reqRaw, err := os.ReadFile(filepath.Join(base, "request.json"))
	if err != nil {
		t.Fatalf("read request fixture: %v", err)
	}
	var req ApplyRequest
	if err := json.Unmarshal(reqRaw, &req); err != nil {
		t.Fatalf("decode request fixture: %v", err)
	}
	if req.RequestID == "" {
		t.Fatalf("request_id should not be empty")
	}

	statusRaw, err := os.ReadFile(filepath.Join(base, "status_in_progress.json"))
	if err != nil {
		t.Fatalf("read status fixture: %v", err)
	}
	var st ApplyStatus
	if err := json.Unmarshal(statusRaw, &st); err != nil {
		t.Fatalf("decode status fixture: %v", err)
	}
	if st.State != ApplyStateInProgress {
		t.Fatalf("unexpected state: %q", st.State)
	}
	if st.RequestID != req.RequestID {
		t.Fatalf("request/status id mismatch: %q vs %q", req.RequestID, st.RequestID)
	}
	if st.TargetVersion != req.TargetVersion {
		t.Fatalf("request/status target mismatch: %q vs %q", req.TargetVersion, st.TargetVersion)
	}
}
