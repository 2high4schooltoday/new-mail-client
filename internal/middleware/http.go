package middleware

import (
	"crypto/subtle"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"mailclient/internal/rate"
	"mailclient/internal/service"
	"mailclient/internal/util"
)

func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := uuid.NewString()
		r = r.WithContext(WithRequestID(r.Context(), rid))
		w.Header().Set("X-Request-ID", rid)
		next.ServeHTTP(w, r)
	})
}

func Authn(svc *service.Service, cookieName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(cookieName)
			if err != nil || c.Value == "" {
				util.WriteError(w, http.StatusUnauthorized, "unauthorized", "authentication required", RequestID(r.Context()))
				return
			}
			u, sess, err := svc.ValidateSession(r.Context(), c.Value)
			if err != nil {
				util.WriteError(w, http.StatusUnauthorized, "unauthorized", "invalid session", RequestID(r.Context()))
				return
			}
			r = r.WithContext(WithUser(r.Context(), u))
			r = r.WithContext(WithSession(r.Context(), sess))
			next.ServeHTTP(w, r)
		})
	}
}

func AdminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := User(r.Context())
		if !ok || u.Role != "admin" {
			util.WriteError(w, http.StatusForbidden, "forbidden", "admin role required", RequestID(r.Context()))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func CSRFFromCookie(cookieName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			h := r.Header.Get("X-CSRF-Token")
			c, err := r.Cookie(cookieName)
			if err != nil || c.Value == "" || h == "" {
				util.WriteError(w, http.StatusForbidden, "csrf_failed", "missing csrf token", RequestID(r.Context()))
				return
			}
			if subtle.ConstantTimeCompare([]byte(h), []byte(c.Value)) != 1 {
				util.WriteError(w, http.StatusForbidden, "csrf_failed", "invalid csrf token", RequestID(r.Context()))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RateLimit(l *rate.Limiter, route string, limit int, window time.Duration, trustProxy bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := route + ":" + ClientIP(r, trustProxy)
			if !l.Allow(key, limit, window) {
				util.WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many requests", RequestID(r.Context()))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sr, r)
		rid := RequestID(r.Context())
		log.Printf("request method=%s path=%s status=%d duration_ms=%d request_id=%s remote_ip=%s",
			r.Method, r.URL.Path, sr.status, time.Since(start).Milliseconds(), rid, ClientIP(r, false))
	})
}

func LegacyRemoteIP(r *http.Request) string {
	// Deprecated compatibility helper.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
