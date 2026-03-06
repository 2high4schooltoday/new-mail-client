package mail

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"html"
	"io"
	"regexp"
	"strings"

	gomail "github.com/emersion/go-message/mail"
)

const (
	DefaultPreviewMaxChars = 180
	previewMIMEReadBytes   = 4096
)

var (
	threadPrefixPattern   = regexp.MustCompile(`(?i)^(re|fw|fwd)\s*:\s*`)
	previewHTMLTagPattern = regexp.MustCompile(`<[^>]+>`)
)

// NormalizeThreadSubject strips repeated reply/forward prefixes and lowercases
// the remaining text for stable mailbox-scoped thread grouping.
func NormalizeThreadSubject(subject string) string {
	normalized := strings.TrimSpace(strings.ToLower(subject))
	for normalized != "" {
		next := threadPrefixPattern.ReplaceAllString(normalized, "")
		next = strings.TrimSpace(next)
		if next == normalized {
			break
		}
		normalized = next
	}
	return normalized
}

// DeriveThreadID builds a stable conversation-scoped thread ID from normalized
// subject (or sender fallback when subject is empty).
func DeriveThreadID(mailbox, subject, from string) string {
	normalized := NormalizeThreadSubject(subject)
	if normalized == "" {
		normalized = strings.ToLower(strings.TrimSpace(from))
	}
	if normalized == "" {
		normalized = "untitled"
	}
	sum := sha256.Sum256([]byte(normalized))
	return "conv:" + hex.EncodeToString(sum[:10])
}

// BuildPreviewFromBodySample creates a compact, plain-text snippet from sampled
// message body content.
func BuildPreviewFromBodySample(sample string, max int) string {
	if max <= 0 {
		max = DefaultPreviewMaxChars
	}
	clean := strings.ReplaceAll(sample, "\x00", " ")
	clean = html.UnescapeString(clean)
	if strings.Contains(clean, "<") && strings.Contains(clean, ">") {
		clean = previewHTMLTagPattern.ReplaceAllString(clean, " ")
	}
	compact := strings.Join(strings.Fields(clean), " ")
	if compact == "" {
		return ""
	}
	runes := []rune(compact)
	if len(runes) <= max {
		return compact
	}
	return strings.TrimSpace(string(runes[:max]))
}

// BuildPreviewFromMIMERawSample creates a robust snippet from a sampled RFC822
// payload by preferring decoded text/plain and then decoded text/html.
func BuildPreviewFromMIMERawSample(sample []byte, max int) string {
	if len(sample) == 0 {
		return ""
	}
	if max <= 0 {
		max = DefaultPreviewMaxChars
	}

	plain, htmlSnippet := extractPreviewFromMIMEParts(sample)
	if strings.TrimSpace(plain) != "" {
		return BuildPreviewFromBodySample(plain, max)
	}
	if strings.TrimSpace(htmlSnippet) != "" {
		return BuildPreviewFromBodySample(htmlSnippet, max)
	}

	bodySample := sample
	if idx := bytes.Index(sample, []byte("\r\n\r\n")); idx >= 0 {
		bodySample = sample[idx+4:]
	} else if idx := bytes.Index(sample, []byte("\n\n")); idx >= 0 {
		bodySample = sample[idx+2:]
	}
	return BuildPreviewFromBodySample(string(bodySample), max)
}

func extractPreviewFromMIMEParts(raw []byte) (string, string) {
	mr, err := gomail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		return "", ""
	}

	var plain string
	var htmlSnippet string
	for {
		part, nextErr := mr.NextPart()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			break
		}
		desc := classifyMIMEPart(part.Header)
		switch desc.kind {
		case mimePartTextPlain:
			if plain != "" {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(part.Body, previewMIMEReadBytes))
			plain = string(body)
		case mimePartTextHTML:
			if htmlSnippet != "" {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(part.Body, previewMIMEReadBytes))
			htmlSnippet = string(body)
		}
		if plain != "" && htmlSnippet != "" {
			break
		}
	}
	return plain, htmlSnippet
}
