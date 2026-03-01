package middleware

import (
	"context"
	"net/http"

	"mailclient/internal/models"
)

type ctxKey string

const (
	ctxRequestID ctxKey = "request_id"
	ctxUser      ctxKey = "user"
	ctxSession   ctxKey = "session"
)

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxRequestID, id)
}

func RequestID(ctx context.Context) string {
	v, _ := ctx.Value(ctxRequestID).(string)
	return v
}

func WithUser(ctx context.Context, u models.User) context.Context {
	return context.WithValue(ctx, ctxUser, u)
}

func User(ctx context.Context) (models.User, bool) {
	u, ok := ctx.Value(ctxUser).(models.User)
	return u, ok
}

func WithSession(ctx context.Context, s models.Session) context.Context {
	return context.WithValue(ctx, ctxSession, s)
}

func Session(ctx context.Context) (models.Session, bool) {
	s, ok := ctx.Value(ctxSession).(models.Session)
	return s, ok
}

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set(
			"Content-Security-Policy",
			"default-src 'self'; "+
				"img-src 'self' data:; "+
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
				"style-src-elem 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
				"font-src 'self' data: https://fonts.gstatic.com; "+
				"connect-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://cdn.jsdelivr.net; "+
				"script-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'",
		)
		next.ServeHTTP(w, r)
	})
}
