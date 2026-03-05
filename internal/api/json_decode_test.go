package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSONTooLargeReturns413(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Value string `json:"value"`
		}
		if err := decodeJSON(w, r, &req, 16, false); err != nil {
			writeJSONDecodeError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	body := `{"value":"abcdefghijklmnopqrstuvwxyz"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status %d, got %d", http.StatusRequestEntityTooLarge, rec.Code)
	}
	var apiErr struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &apiErr); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if apiErr.Code != "request_too_large" {
		t.Fatalf("expected request_too_large code, got %q", apiErr.Code)
	}
}
