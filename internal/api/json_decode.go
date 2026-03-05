package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"despatch/internal/middleware"
	"despatch/internal/util"
)

const (
	jsonLimitAuthControl int64 = 64 << 10
	jsonLimitMutation    int64 = 256 << 10
	jsonLimitLarge       int64 = 1 << 20
)

var errJSONTooLarge = errors.New("json request body too large")

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, limitBytes int64, allowEOF bool) error {
	if limitBytes <= 0 {
		limitBytes = jsonLimitMutation
	}
	r.Body = http.MaxBytesReader(w, r.Body, limitBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		if allowEOF && errors.Is(err, io.EOF) {
			return nil
		}
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) || strings.Contains(strings.ToLower(err.Error()), "request body too large") {
			return errJSONTooLarge
		}
		return err
	}
	return nil
}

func writeJSONDecodeError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errJSONTooLarge) {
		util.WriteError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body too large", middleware.RequestID(r.Context()))
		return
	}
	util.WriteError(w, http.StatusBadRequest, "bad_request", "invalid json", middleware.RequestID(r.Context()))
}
