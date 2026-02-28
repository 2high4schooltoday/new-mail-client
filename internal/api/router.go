package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"mailclient/internal/captcha"
	"mailclient/internal/config"
	"mailclient/internal/mail"
	"mailclient/internal/middleware"
	"mailclient/internal/models"
	"mailclient/internal/rate"
	"mailclient/internal/service"
	"mailclient/internal/store"
	"mailclient/internal/util"
)

type Handlers struct {
	cfg             config.Config
	svc             *service.Service
	limiter         *rate.Limiter
	captchaVerifier captcha.Verifier
}

const (
	maxUploadAttachmentBytes = 25 << 20
	maxUploadTotalBytes      = 35 << 20
)

func NewRouter(cfg config.Config, svc *service.Service) http.Handler {
	h := &Handlers{
		cfg:             cfg,
		svc:             svc,
		limiter:         rate.NewLimiter(),
		captchaVerifier: captcha.NewVerifier(cfg),
	}
	r := chi.NewRouter()
	r.Use(chimw.Recoverer)
	r.Use(middleware.RequestIDMiddleware)
	r.Use(middleware.RequestLogger)
	r.Use(middleware.SecurityHeaders)
	if len(cfg.CORSAllowedOrigins) > 0 {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   cfg.CORSAllowedOrigins,
			AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders:   []string{"Content-Type", "X-CSRF-Token"},
			AllowCredentials: true,
		}))
	}

	r.Get("/health/live", func(w http.ResponseWriter, r *http.Request) {
		util.WriteJSON(w, 200, map[string]string{"status": "ok"})
	})
	r.Get("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		ready := map[string]any{
			"checked_at": time.Now().UTC().Format(time.RFC3339),
			"components": map[string]any{},
		}
		comps := ready["components"].(map[string]any)

		sqliteOK := true
		if _, err := h.svc.SetupStatus(r.Context()); err != nil {
			sqliteOK = false
			comps["sqlite"] = map[string]any{"ok": false, "error": err.Error()}
		} else {
			comps["sqlite"] = map[string]any{"ok": true}
		}

		if err := mail.ProbeIMAP(r.Context(), cfg); err != nil {
			comps["imap"] = map[string]any{"ok": false, "error": err.Error()}
			sqliteOK = false
		} else {
			comps["imap"] = map[string]any{"ok": true}
		}

		if err := mail.ProbeSMTP(r.Context(), cfg); err != nil {
			comps["smtp"] = map[string]any{"ok": false, "error": err.Error()}
			sqliteOK = false
		} else {
			comps["smtp"] = map[string]any{"ok": true}
		}

		if sqliteOK {
			ready["status"] = "ready"
			util.WriteJSON(w, 200, ready)
			return
		}
		ready["status"] = "degraded"
		util.WriteJSON(w, 503, ready)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/setup/status", h.SetupStatus)
		r.With(middleware.RateLimit(h.limiter, "setup_complete", 20, time.Minute, h.cfg.TrustProxy)).Post("/setup/complete", h.SetupComplete)
		r.With(middleware.RateLimit(h.limiter, "register", 10, time.Minute, h.cfg.TrustProxy)).Post("/register", h.Register)
		r.With(middleware.RateLimit(h.limiter, "login", 20, time.Minute, h.cfg.TrustProxy)).Post("/login", h.Login)
		r.Post("/logout", h.Logout)
		r.With(middleware.RateLimit(h.limiter, "reset_request", 10, time.Minute, h.cfg.TrustProxy)).Post("/password/reset/request", h.PasswordResetRequest)
		r.Post("/password/reset/confirm", h.PasswordResetConfirm)

		r.Group(func(r chi.Router) {
			r.Use(middleware.Authn(h.svc, h.cfg.SessionCookieName, h.cfg.TrustProxy))
			r.Get("/me", h.Me)
			r.Get("/mailboxes", h.ListMailboxes)
			r.Get("/messages", h.ListMessages)
			r.Get("/messages/{id}", h.GetMessage)
			r.Get("/search", h.Search)
			r.Get("/attachments/{id}", h.GetAttachment)

			r.Group(func(r chi.Router) {
				r.Use(middleware.CSRFFromCookie(h.cfg.CSRFCookieName))
				r.With(middleware.RateLimit(h.limiter, "send", 30, time.Minute, h.cfg.TrustProxy)).Post("/messages/send", h.SendMessage)
				r.With(middleware.RateLimit(h.limiter, "send", 30, time.Minute, h.cfg.TrustProxy)).Post("/messages/{id}/reply", h.ReplyMessage)
				r.With(middleware.RateLimit(h.limiter, "send", 30, time.Minute, h.cfg.TrustProxy)).Post("/messages/{id}/forward", h.ForwardMessage)
				r.Post("/messages/{id}/flags", h.SetMessageFlags)
				r.Post("/messages/{id}/move", h.MoveMessage)
			})

			r.Route("/admin", func(r chi.Router) {
				r.Use(middleware.AdminOnly)
				r.Get("/registrations", h.AdminListRegistrations)
				r.Get("/users", h.AdminListUsers)
				r.Get("/audit-log", h.AdminAuditLog)
				r.Get("/system/mail-health", h.AdminMailHealth)
				r.Group(func(r chi.Router) {
					r.Use(middleware.CSRFFromCookie(h.cfg.CSRFCookieName))
					r.Post("/registrations/{id}/approve", h.AdminApproveRegistration)
					r.Post("/registrations/{id}/reject", h.AdminRejectRegistration)
					r.Post("/users/{id}/suspend", h.AdminSuspendUser)
					r.Post("/users/{id}/unsuspend", h.AdminUnsuspendUser)
					r.Post("/users/{id}/reset-password", h.AdminResetPassword)
					r.Post("/users/{id}/retry-provision", h.AdminRetryProvisionUser)
				})
			})
		})
	})

	fs := http.FileServer(http.Dir("web"))
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/health/") {
			http.NotFound(w, r)
			return
		}
		if p == "/" {
			http.ServeFile(w, r, filepath.Join("web", "index.html"))
			return
		}
		fs.ServeHTTP(w, r)
	})

	return r
}

type registerRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	CaptchaToken string `json:"captcha_token"`
}

func (h *Handlers) SetupStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.svc.SetupStatus(r.Context())
	if err != nil {
		util.WriteError(w, 500, "internal_error", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, status)
}

func (h *Handlers) SetupComplete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BaseDomain        string `json:"base_domain"`
		AdminEmail        string `json:"admin_email"`
		AdminMailboxLogin string `json:"admin_mailbox_login"`
		AdminPassword     string `json:"admin_password"`
		Region            string `json:"region"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteError(w, 400, "bad_request", "invalid json", middleware.RequestID(r.Context()))
		return
	}
	token, user, err := h.svc.CompleteSetup(r.Context(), service.SetupCompleteRequest{
		BaseDomain:        req.BaseDomain,
		AdminEmail:        req.AdminEmail,
		AdminMailboxLogin: req.AdminMailboxLogin,
		AdminPassword:     req.AdminPassword,
		Region:            req.Region,
	}, r.RemoteAddr, r.UserAgent())
	if err != nil {
		msg := err.Error()
		status := http.StatusBadRequest
		code := "setup_failed"
		failureClass := "setup_failed"
		pamAttempts := ""
		pamAttemptCount := 0
		var pamCredErr *service.PAMCredentialsInvalidError
		switch {
		case strings.EqualFold(strings.TrimSpace(msg), "setup already completed"):
			status = http.StatusConflict
			code = "setup_already_complete"
			failureClass = "setup_already_complete"
		case errors.Is(err, service.ErrPAMVerifierDown):
			status = http.StatusBadGateway
			code = "pam_verifier_unavailable"
			failureClass = "verifier_unavailable"
			msg = "cannot validate PAM credentials because IMAP connectivity failed; check IMAP_HOST/IMAP_PORT/IMAP_TLS/IMAP_STARTTLS"
			lowerErr := strings.ToLower(err.Error())
			if strings.Contains(lowerErr, "x509") || strings.Contains(lowerErr, "certificate") || strings.Contains(lowerErr, "tls") {
				msg = "IMAP TLS verification failed while validating PAM credentials. If using IMAP_HOST=127.0.0.1, set IMAP_INSECURE_SKIP_VERIFY=true or set IMAP_HOST to your mail FQDN."
			}
		case strings.Contains(strings.ToLower(msg), "invalid domain"):
			code = "invalid_domain"
		case strings.Contains(strings.ToLower(msg), "invalid admin email"):
			code = "invalid_admin_email"
		case strings.Contains(strings.ToLower(msg), "must use @"):
			code = "admin_email_domain_mismatch"
		case strings.Contains(strings.ToLower(msg), "password"):
			code = "invalid_password"
		case errors.As(err, &pamCredErr):
			code = "pam_credentials_invalid"
			failureClass = "invalid_identity_or_password"
			msg = "PAM auth mode is enabled. The password or mailbox login identity is invalid."
			if pamCredErr != nil && len(pamCredErr.Attempts) > 0 {
				pamAttemptCount = len(pamCredErr.Attempts)
				pamAttempts = strings.Join(pamCredErr.Attempts, ",")
				msg = fmt.Sprintf("%s Attempted logins: %s.", msg, strings.Join(pamCredErr.Attempts, ", "))
			}
		case strings.Contains(strings.ToLower(msg), "dovecot/pam"):
			code = "pam_credentials_invalid"
			failureClass = "invalid_identity_or_password"
			msg = "PAM auth mode is enabled. The password or mailbox login identity is invalid."
		}
		log.Printf("setup_complete_failed code=%s class=%s status=%d admin_email=%s base_domain=%s request_id=%s pam_attempt_count=%d pam_attempts=%q err=%q",
			code,
			failureClass,
			status,
			strings.ToLower(strings.TrimSpace(req.AdminEmail)),
			strings.ToLower(strings.TrimSpace(req.BaseDomain)),
			middleware.RequestID(r.Context()),
			pamAttemptCount,
			pamAttempts,
			err.Error(),
		)
		util.WriteError(w, status, code, msg, middleware.RequestID(r.Context()))
		return
	}
	csrfToken := randomToken()
	h.setAuthCookies(w, r, token, csrfToken)
	util.WriteJSON(w, 200, map[string]string{"status": "ok", "user_id": user.ID, "email": user.Email, "role": user.Role, "csrf_token": csrfToken})
}

func (h *Handlers) Register(w http.ResponseWriter, r *http.Request) {
	if !h.ensureSetupComplete(w, r) {
		return
	}
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteError(w, 400, "bad_request", "invalid json", middleware.RequestID(r.Context()))
		return
	}
	captchaOK := true
	if h.cfg.CaptchaEnabled {
		ip := middleware.ClientIP(r, h.cfg.TrustProxy)
		if err := h.captchaVerifier.Verify(r.Context(), req.CaptchaToken, ip); err != nil {
			util.WriteError(w, 400, "captcha_required", "captcha validation failed", middleware.RequestID(r.Context()))
			return
		}
	}
	if err := h.svc.Register(r.Context(), req.Email, req.Password, r.RemoteAddr, r.UserAgent(), captchaOK); err != nil {
		util.WriteError(w, 400, "register_failed", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 201, map[string]string{"status": "pending_approval"})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	if !h.ensureSetupComplete(w, r) {
		return
	}
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteError(w, 400, "bad_request", "invalid json", middleware.RequestID(r.Context()))
		return
	}
	token, user, err := h.svc.Login(r.Context(), req.Email, req.Password, r.RemoteAddr, r.UserAgent())
	if err != nil {
		normalizedEmail := strings.ToLower(strings.TrimSpace(req.Email))
		ip := middleware.ClientIP(r, h.cfg.TrustProxy)
		key := ip + "|" + normalizedEmail
		windowStart := time.Now().UTC().Truncate(15 * time.Minute)
		failCount, _ := h.svc.Store().IncrementRateEvent(r.Context(), key, "login_failed", windowStart)
		_ = h.svc.Store().CleanupRateEventsBefore(r.Context(), time.Now().UTC().Add(-24*time.Hour))
		if failCount > 3 {
			backoff := time.Duration(1<<(minInt(failCount-3, 5))) * time.Second
			select {
			case <-time.After(backoff):
			case <-r.Context().Done():
			}
		}

		status := 401
		code := "invalid_credentials"
		if failCount > 6 {
			status, code = 429, "rate_limited"
		}
		if err == service.ErrPendingApproval {
			status, code = 403, "pending_approval"
		}
		if err == service.ErrSuspended {
			status, code = 403, "suspended"
		}
		util.WriteError(w, status, code, err.Error(), middleware.RequestID(r.Context()))
		return
	}
	normalizedEmail := strings.ToLower(strings.TrimSpace(req.Email))
	ip := middleware.ClientIP(r, h.cfg.TrustProxy)
	_ = h.svc.Store().DeleteRateEvents(r.Context(), ip+"|"+normalizedEmail, "login_failed")

	csrfToken := randomToken()
	h.setAuthCookies(w, r, token, csrfToken)
	util.WriteJSON(w, 200, map[string]string{"user_id": user.ID, "email": user.Email, "role": user.Role, "csrf_token": csrfToken})
}

func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie(h.cfg.SessionCookieName)
	if c != nil && c.Value != "" {
		_ = h.svc.Logout(r.Context(), c.Value)
	}
	h.clearAuthCookies(w, r)
	util.WriteJSON(w, 200, map[string]string{"status": "ok"})
}

func (h *Handlers) PasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	if !h.ensureSetupComplete(w, r) {
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteError(w, 400, "bad_request", "invalid json", middleware.RequestID(r.Context()))
		return
	}
	if err := h.svc.RequestPasswordReset(r.Context(), req.Email); err != nil {
		if errors.Is(err, service.ErrPAMPasswordManaged) {
			util.WriteError(w, 400, "unsupported_auth_backend", err.Error(), middleware.RequestID(r.Context()))
			return
		}
		util.WriteError(w, 500, "internal_error", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, map[string]string{"status": "accepted"})
}

func (h *Handlers) PasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	if !h.ensureSetupComplete(w, r) {
		return
	}
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteError(w, 400, "bad_request", "invalid json", middleware.RequestID(r.Context()))
		return
	}
	if err := h.svc.ConfirmPasswordReset(r.Context(), req.Token, req.NewPassword); err != nil {
		if errors.Is(err, service.ErrPAMPasswordManaged) {
			util.WriteError(w, 400, "unsupported_auth_backend", err.Error(), middleware.RequestID(r.Context()))
			return
		}
		util.WriteError(w, 400, "reset_failed", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, map[string]string{"status": "updated"})
}

func (h *Handlers) Me(w http.ResponseWriter, r *http.Request) {
	u, _ := middleware.User(r.Context())
	util.WriteJSON(w, 200, map[string]any{"id": u.ID, "email": u.Email, "role": u.Role, "status": u.Status})
}

func (h *Handlers) ListMailboxes(w http.ResponseWriter, r *http.Request) {
	u, _ := middleware.User(r.Context())
	pass, err := h.sessionMailPassword(r)
	if err != nil {
		util.WriteError(w, 401, "mail_auth_missing", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	mailLogin := service.MailIdentity(u)
	items, err := h.svc.Mail().ListMailboxes(r.Context(), mailLogin, pass)
	if err != nil {
		util.WriteError(w, 502, "imap_error", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, items)
}

func (h *Handlers) ListMessages(w http.ResponseWriter, r *http.Request) {
	u, _ := middleware.User(r.Context())
	pass, err := h.sessionMailPassword(r)
	if err != nil {
		util.WriteError(w, 401, "mail_auth_missing", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	mbox := r.URL.Query().Get("mailbox")
	if mbox == "" {
		mbox = "INBOX"
	}
	page, pageSize := parsePagination(r)
	mailLogin := service.MailIdentity(u)
	items, err := h.svc.Mail().ListMessages(r.Context(), mailLogin, pass, mbox, page, pageSize)
	if err != nil {
		util.WriteError(w, 502, "imap_error", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, map[string]any{"page": page, "page_size": pageSize, "items": items})
}

func (h *Handlers) GetMessage(w http.ResponseWriter, r *http.Request) {
	u, _ := middleware.User(r.Context())
	pass, err := h.sessionMailPassword(r)
	if err != nil {
		util.WriteError(w, 401, "mail_auth_missing", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	id := chi.URLParam(r, "id")
	mailLogin := service.MailIdentity(u)
	msg, err := h.svc.Mail().GetMessage(r.Context(), mailLogin, pass, id)
	if err != nil {
		util.WriteError(w, 404, "not_found", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, msg)
}

func (h *Handlers) SendMessage(w http.ResponseWriter, r *http.Request) {
	h.handleSend(w, r, "")
}

func (h *Handlers) ReplyMessage(w http.ResponseWriter, r *http.Request) {
	h.handleSend(w, r, chi.URLParam(r, "id"))
}

func (h *Handlers) ForwardMessage(w http.ResponseWriter, r *http.Request) {
	h.handleSend(w, r, chi.URLParam(r, "id"))
}

func (h *Handlers) handleSend(w http.ResponseWriter, r *http.Request, inReply string) {
	u, _ := middleware.User(r.Context())
	pass, err := h.sessionMailPassword(r)
	if err != nil {
		util.WriteError(w, 401, "mail_auth_missing", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	req, err := decodeSendRequest(r)
	if err != nil {
		util.WriteError(w, 400, "bad_request", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	req.From = u.Email
	req.InReplyToID = inReply
	mailLogin := service.MailIdentity(u)
	if err := h.svc.Mail().Send(r.Context(), mailLogin, pass, req); err != nil {
		util.WriteError(w, 502, "smtp_error", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, map[string]string{"status": "sent"})
}

func (h *Handlers) SetMessageFlags(w http.ResponseWriter, r *http.Request) {
	u, _ := middleware.User(r.Context())
	pass, err := h.sessionMailPassword(r)
	if err != nil {
		util.WriteError(w, 401, "mail_auth_missing", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	id := chi.URLParam(r, "id")
	var req struct {
		Flags []string `json:"flags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteError(w, 400, "bad_request", "invalid json", middleware.RequestID(r.Context()))
		return
	}
	mailLogin := service.MailIdentity(u)
	if err := h.svc.Mail().SetFlags(r.Context(), mailLogin, pass, id, req.Flags); err != nil {
		util.WriteError(w, 502, "imap_error", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, map[string]string{"status": "ok"})
}

func (h *Handlers) MoveMessage(w http.ResponseWriter, r *http.Request) {
	u, _ := middleware.User(r.Context())
	pass, err := h.sessionMailPassword(r)
	if err != nil {
		util.WriteError(w, 401, "mail_auth_missing", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	id := chi.URLParam(r, "id")
	var req struct {
		Mailbox string `json:"mailbox"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteError(w, 400, "bad_request", "invalid json", middleware.RequestID(r.Context()))
		return
	}
	mailLogin := service.MailIdentity(u)
	if err := h.svc.Mail().Move(r.Context(), mailLogin, pass, id, req.Mailbox); err != nil {
		util.WriteError(w, 502, "imap_error", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, map[string]string{"status": "ok"})
}

func (h *Handlers) Search(w http.ResponseWriter, r *http.Request) {
	u, _ := middleware.User(r.Context())
	pass, err := h.sessionMailPassword(r)
	if err != nil {
		util.WriteError(w, 401, "mail_auth_missing", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	q := r.URL.Query().Get("q")
	mailbox := strings.TrimSpace(r.URL.Query().Get("mailbox"))
	if mailbox == "" {
		mailbox = "INBOX"
	}
	page, pageSize := parsePagination(r)
	mailLogin := service.MailIdentity(u)
	items, err := h.svc.Mail().Search(r.Context(), mailLogin, pass, mailbox, q, page, pageSize)
	if err != nil {
		util.WriteError(w, 502, "imap_error", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, map[string]any{"page": page, "page_size": pageSize, "items": items})
}

func (h *Handlers) GetAttachment(w http.ResponseWriter, r *http.Request) {
	u, _ := middleware.User(r.Context())
	pass, err := h.sessionMailPassword(r)
	if err != nil {
		util.WriteError(w, 401, "mail_auth_missing", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	id := chi.URLParam(r, "id")
	mailLogin := service.MailIdentity(u)
	meta, stream, err := h.svc.Mail().GetAttachmentStream(r.Context(), mailLogin, pass, id)
	if err != nil {
		util.WriteError(w, 404, "not_found", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	defer stream.Close()
	w.Header().Set("Content-Type", meta.ContentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+meta.Filename+`"`)
	if meta.Size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(meta.Size, 10))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, stream)
}

func (h *Handlers) AdminListRegistrations(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "pending"
	}
	page, pageSize := parsePagination(r)
	items, err := h.svc.ListRegistrations(r.Context(), status, pageSize, (page-1)*pageSize)
	if err != nil {
		util.WriteError(w, 500, "internal_error", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, map[string]any{"items": items, "page": page, "page_size": pageSize})
}

func (h *Handlers) AdminApproveRegistration(w http.ResponseWriter, r *http.Request) {
	admin, _ := middleware.User(r.Context())
	id := chi.URLParam(r, "id")
	if err := h.svc.ApproveRegistration(r.Context(), admin.ID, id); err != nil {
		if errors.Is(err, store.ErrConflict) {
			util.WriteError(w, 409, "already_decided", "registration has already been decided", middleware.RequestID(r.Context()))
			return
		}
		util.WriteError(w, 400, "approve_failed", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, map[string]string{"status": "approved"})
}

func (h *Handlers) AdminRejectRegistration(w http.ResponseWriter, r *http.Request) {
	admin, _ := middleware.User(r.Context())
	id := chi.URLParam(r, "id")
	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteError(w, 400, "bad_request", "invalid json", middleware.RequestID(r.Context()))
		return
	}
	if err := h.svc.RejectRegistration(r.Context(), admin.ID, id, req.Reason); err != nil {
		if errors.Is(err, store.ErrConflict) {
			util.WriteError(w, 409, "already_decided", "registration has already been decided", middleware.RequestID(r.Context()))
			return
		}
		util.WriteError(w, 400, "reject_failed", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, map[string]string{"status": "rejected"})
}

func (h *Handlers) AdminListUsers(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePagination(r)
	users, err := h.svc.ListUsers(r.Context(), pageSize, (page-1)*pageSize)
	if err != nil {
		util.WriteError(w, 500, "internal_error", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	type dto struct {
		ID             string            `json:"id"`
		Email          string            `json:"email"`
		Role           string            `json:"role"`
		Status         models.UserStatus `json:"status"`
		ProvisionState string            `json:"provision_state"`
		ProvisionError *string           `json:"provision_error,omitempty"`
	}
	out := make([]dto, 0, len(users))
	for _, u := range users {
		out = append(out, dto{
			ID:             u.ID,
			Email:          u.Email,
			Role:           u.Role,
			Status:         u.Status,
			ProvisionState: u.ProvisionState,
			ProvisionError: u.ProvisionError,
		})
	}
	util.WriteJSON(w, 200, map[string]any{"items": out, "page": page, "page_size": pageSize})
}

func (h *Handlers) AdminSuspendUser(w http.ResponseWriter, r *http.Request) {
	admin, _ := middleware.User(r.Context())
	id := chi.URLParam(r, "id")
	if err := h.svc.SuspendUser(r.Context(), admin.ID, id); err != nil {
		util.WriteError(w, 400, "suspend_failed", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, map[string]string{"status": "suspended"})
}

func (h *Handlers) AdminUnsuspendUser(w http.ResponseWriter, r *http.Request) {
	admin, _ := middleware.User(r.Context())
	id := chi.URLParam(r, "id")
	if err := h.svc.UnsuspendUser(r.Context(), admin.ID, id); err != nil {
		util.WriteError(w, 400, "unsuspend_failed", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, map[string]string{"status": "active"})
}

func (h *Handlers) AdminResetPassword(w http.ResponseWriter, r *http.Request) {
	admin, _ := middleware.User(r.Context())
	id := chi.URLParam(r, "id")
	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		util.WriteError(w, 400, "bad_request", "invalid json", middleware.RequestID(r.Context()))
		return
	}
	if req.NewPassword == "" {
		util.WriteError(w, 400, "bad_request", "new_password is required", middleware.RequestID(r.Context()))
		return
	}
	if err := h.svc.AdminResetPassword(r.Context(), admin.ID, id, req.NewPassword); err != nil {
		if errors.Is(err, service.ErrPAMPasswordManaged) {
			util.WriteError(w, 400, "unsupported_auth_backend", err.Error(), middleware.RequestID(r.Context()))
			return
		}
		util.WriteError(w, 400, "reset_failed", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, map[string]string{"status": "updated"})
}

func (h *Handlers) AdminRetryProvisionUser(w http.ResponseWriter, r *http.Request) {
	admin, _ := middleware.User(r.Context())
	id := chi.URLParam(r, "id")
	if err := h.svc.RetryProvisionUser(r.Context(), admin.ID, id); err != nil {
		util.WriteError(w, 400, "retry_provision_failed", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, map[string]string{"status": "provisioned"})
}

func (h *Handlers) AdminAuditLog(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePagination(r)
	items, err := h.svc.ListAudit(r.Context(), pageSize, (page-1)*pageSize)
	if err != nil {
		util.WriteError(w, 500, "internal_error", err.Error(), middleware.RequestID(r.Context()))
		return
	}
	util.WriteJSON(w, 200, map[string]any{"items": items, "page": page, "page_size": pageSize})
}

func (h *Handlers) AdminMailHealth(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"checked_at": time.Now().UTC().Format(time.RFC3339),
		"imap":       map[string]any{"ok": true},
		"smtp":       map[string]any{"ok": true},
	}
	if err := mail.ProbeIMAP(r.Context(), h.cfg); err != nil {
		out["imap"] = map[string]any{"ok": false, "error": err.Error()}
	}
	if err := mail.ProbeSMTP(r.Context(), h.cfg); err != nil {
		out["smtp"] = map[string]any{"ok": false, "error": err.Error()}
	}
	util.WriteJSON(w, 200, out)
}

func parsePagination(r *http.Request) (int, int) {
	page := 1
	pageSize := 25
	if v := r.URL.Query().Get("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}
	if v := r.URL.Query().Get("page_size"); v != "" {
		if ps, err := strconv.Atoi(v); err == nil {
			if ps < 1 {
				ps = 1
			}
			if ps > 100 {
				ps = 100
			}
			pageSize = ps
		}
	}
	return page, pageSize
}

func randomToken() string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func (h *Handlers) setAuthCookies(w http.ResponseWriter, r *http.Request, sessionToken, csrfToken string) {
	secure := h.cfg.ResolveCookieSecure(r)
	maxAge := int(h.cfg.SessionAbsoluteDuration().Seconds())
	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.SessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.CSRFCookieName,
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func (h *Handlers) clearAuthCookies(w http.ResponseWriter, r *http.Request) {
	secure := h.cfg.ResolveCookieSecure(r)
	expiredAt := time.Unix(1, 0).UTC()
	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  expiredAt,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.CSRFCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  expiredAt,
	})
}

func decodeSendRequest(r *http.Request) (mail.SendRequest, error) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/form-data") {
		if err := r.ParseMultipartForm(maxUploadAttachmentBytes); err != nil {
			return mail.SendRequest{}, err
		}
		to := splitCSV(r.FormValue("to"))
		req := mail.SendRequest{
			To:      to,
			Subject: r.FormValue("subject"),
			Body:    r.FormValue("body"),
		}
		files := r.MultipartForm.File["attachments"]
		var totalBytes int64
		for _, fh := range files {
			if fh.Size > maxUploadAttachmentBytes {
				return mail.SendRequest{}, errors.New("attachment exceeds per-file size limit")
			}
			f, err := fh.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(io.LimitReader(f, maxUploadAttachmentBytes))
			_ = f.Close()
			if err != nil {
				continue
			}
			totalBytes += int64(len(data))
			if totalBytes > maxUploadTotalBytes {
				return mail.SendRequest{}, errors.New("attachments exceed total size limit")
			}
			req.Attachments = append(req.Attachments, mail.SendAttachment{Filename: fh.Filename, ContentType: fh.Header.Get("Content-Type"), Data: data})
		}
		return req, nil
	}
	var req struct {
		To      []string `json:"to"`
		Subject string   `json:"subject"`
		Body    string   `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return mail.SendRequest{}, err
	}
	return mail.SendRequest{To: req.To, Subject: req.Subject, Body: req.Body}, nil
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (h *Handlers) sessionMailPassword(r *http.Request) (string, error) {
	sess, ok := middleware.Session(r.Context())
	if !ok {
		return "", service.ErrInvalidCredentials
	}
	return h.svc.SessionMailPassword(sess)
}

func (h *Handlers) ensureSetupComplete(w http.ResponseWriter, r *http.Request) bool {
	status, err := h.svc.SetupStatus(r.Context())
	if err != nil {
		util.WriteError(w, 500, "internal_error", err.Error(), middleware.RequestID(r.Context()))
		return false
	}
	if status.Required {
		util.WriteError(w, 423, "setup_required", "first-run setup is required", middleware.RequestID(r.Context()))
		return false
	}
	return true
}
