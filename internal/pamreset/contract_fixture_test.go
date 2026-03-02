package pamreset

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestContractFixturesPamRequestAndResponse(t *testing.T) {
	base := filepath.Join("..", "..", "rust", "contracts", "tests", "fixtures", "pam")

	reqRaw, err := os.ReadFile(filepath.Join(base, "request_ok.json"))
	if err != nil {
		t.Fatalf("read request fixture: %v", err)
	}
	var req Request
	if err := json.Unmarshal(reqRaw, &req); err != nil {
		t.Fatalf("decode request fixture: %v", err)
	}
	if err := validateRequest(req); err != nil {
		t.Fatalf("fixture request should be valid: %v", err)
	}

	respRaw, err := os.ReadFile(filepath.Join(base, "response_ok.json"))
	if err != nil {
		t.Fatalf("read response fixture: %v", err)
	}
	var resp Response
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		t.Fatalf("decode response fixture: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected ok response fixture")
	}
	if resp.Code != ProtocolCodeOK {
		t.Fatalf("unexpected response code: %q", resp.Code)
	}
	if resp.RequestID != req.RequestID {
		t.Fatalf("request/response id mismatch: %q vs %q", req.RequestID, resp.RequestID)
	}
}
