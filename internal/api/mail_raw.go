package api

import (
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var rawMessageFilenameUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func rawMessageDownloadRequested(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("download"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func rawMessageFilename(subject, fallback string) string {
	base := strings.TrimSpace(subject)
	if base == "" {
		base = strings.TrimSpace(fallback)
	}
	if base == "" {
		base = "message"
	}
	base = strings.ReplaceAll(base, "\x00", " ")
	base = rawMessageFilenameUnsafe.ReplaceAllString(base, "-")
	base = strings.Trim(base, ".-_")
	if base == "" {
		base = "message"
	}
	if !strings.HasSuffix(strings.ToLower(base), ".eml") {
		base += ".eml"
	}
	return base
}

func writeRawMessageResponse(w http.ResponseWriter, r *http.Request, raw []byte, filename string) {
	w.Header().Set("Content-Type", "message/rfc822")
	if len(raw) > 0 {
		w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	}
	if rawMessageDownloadRequested(r) {
		if disposition := mime.FormatMediaType("attachment", map[string]string{"filename": rawMessageFilename(filename, "message")}); disposition != "" {
			w.Header().Set("Content-Disposition", disposition)
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
