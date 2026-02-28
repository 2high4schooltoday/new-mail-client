package util

import (
	"encoding/json"
	"net/http"
)

type APIError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func WriteError(w http.ResponseWriter, status int, code, msg, reqID string) {
	WriteJSON(w, status, APIError{Code: code, Message: msg, RequestID: reqID})
}
