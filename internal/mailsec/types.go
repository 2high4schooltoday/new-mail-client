package mailsec

type Request struct {
	RequestID  string         `json:"request_id"`
	Op         string         `json:"op"`
	AccountID  string         `json:"account_id"`
	MessageID  string         `json:"message_id"`
	Payload    map[string]any `json:"payload,omitempty"`
	DeadlineMS int            `json:"deadline_ms"`
}

type Response struct {
	RequestID string         `json:"request_id"`
	OK        bool           `json:"ok"`
	Code      string         `json:"code"`
	Error     string         `json:"error,omitempty"`
	Result    map[string]any `json:"result,omitempty"`
}
