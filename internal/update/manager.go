package update

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"mailclient/internal/config"
	"mailclient/internal/store"
	"mailclient/internal/version"
)

const (
	settingLastCheckAt     = "update_last_check_at"
	settingETag            = "update_etag"
	settingLatestTag       = "update_latest_tag"
	settingLatestPublished = "update_latest_published_at"
	settingLatestURL       = "update_latest_html_url"
	settingLastCheckError  = "update_last_check_error"
	settingLastSuccessVer  = "update_last_success_version"
	settingLastSuccessAt   = "update_last_success_at"
)

var targetVersionRx = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type Manager struct {
	cfg config.Config
	gh  *githubClient
	now func() time.Time
}

func NewManager(cfg config.Config) *Manager {
	return &Manager{
		cfg: cfg,
		gh:  newGitHubClient(cfg),
		now: func() time.Time { return time.Now().UTC() },
	}
}

func (m *Manager) Status(ctx context.Context, st *store.Store, forceCheck bool) (StatusResponse, error) {
	status := StatusResponse{
		Enabled:    m.cfg.UpdateEnabled,
		Configured: m.isConfigured(),
		Current:    version.Current(),
		Apply:      ApplyStatus{State: ApplyStateIdle},
	}
	var checkErr error
	if m.cfg.UpdateEnabled && (forceCheck || m.shouldRefresh(ctx, st)) {
		checkErr = m.refreshLatest(ctx, st)
		if forceCheck && checkErr != nil {
			return status, checkErr
		}
	}

	latestTag, _ := m.getSetting(ctx, st, settingLatestTag)
	if latestTag != "" {
		latestPublishedRaw, _ := m.getSetting(ctx, st, settingLatestPublished)
		latestURL, _ := m.getSetting(ctx, st, settingLatestURL)
		rel := &ReleaseInfo{TagName: latestTag, HTMLURL: latestURL}
		if latestPublishedRaw != "" {
			if parsed, err := time.Parse(time.RFC3339, latestPublishedRaw); err == nil {
				rel.PublishedAt = parsed
			}
		}
		status.Latest = rel
		status.UpdateAvailable = compareVersions(status.Current.Version, rel.TagName)
	}
	status.LastCheckedAt, _ = m.getSetting(ctx, st, settingLastCheckAt)
	status.LastCheckError, _ = m.getSetting(ctx, st, settingLastCheckError)
	if checkErr != nil && status.LastCheckError == "" {
		status.LastCheckError = checkErr.Error()
	}
	apply, err := readApplyStatusTolerant(statusPath(m.cfg))
	if err != nil {
		return StatusResponse{}, err
	}
	status.Apply = apply
	if status.Apply.State == ApplyStateIdle {
		if _, err := os.Stat(lockPath(m.cfg)); err == nil {
			status.Apply.State = ApplyStateInProgress
		}
	}
	return status, nil
}

func (m *Manager) QueueApply(ctx context.Context, st *store.Store, requestedBy, targetVersion, requestID string) (ApplyRequest, error) {
	if !m.cfg.UpdateEnabled || !m.isConfigured() {
		return ApplyRequest{}, ErrUpdaterNotConfigured
	}
	target := strings.TrimSpace(targetVersion)
	if target != "" && !targetVersionRx.MatchString(target) {
		return ApplyRequest{}, ErrInvalidTargetVersion
	}
	if requestID = strings.TrimSpace(requestID); requestID == "" {
		requestID = uuid.NewString()
	}
	current, err := readApplyStatusTolerant(statusPath(m.cfg))
	if err != nil {
		return ApplyRequest{}, fmt.Errorf("%w: %v", ErrUpdateRequestFailed, err)
	}
	if current.State == ApplyStateQueued || current.State == ApplyStateInProgress {
		return ApplyRequest{}, ErrUpdateInProgress
	}
	if _, err := os.Stat(lockPath(m.cfg)); err == nil {
		return ApplyRequest{}, ErrUpdateInProgress
	}
	req := ApplyRequest{
		RequestID:     requestID,
		RequestedAt:   m.now(),
		RequestedBy:   strings.TrimSpace(requestedBy),
		TargetVersion: target,
	}
	if err := ensureDirs([]string{requestDir(m.cfg), statusDir(m.cfg)}, 0o750); err != nil {
		return ApplyRequest{}, fmt.Errorf("%w: %v", ErrUpdateRequestFailed, err)
	}
	if err := writeJSONAtomic(requestPath(m.cfg), req, 0o640); err != nil {
		return ApplyRequest{}, fmt.Errorf("%w: %v", ErrUpdateRequestFailed, err)
	}
	if err := writeJSONAtomic(statusPath(m.cfg), ApplyStatus{
		State:         ApplyStateQueued,
		RequestID:     req.RequestID,
		RequestedAt:   req.RequestedAt,
		TargetVersion: req.TargetVersion,
	}, 0o640); err != nil {
		return ApplyRequest{}, fmt.Errorf("%w: %v", ErrUpdateRequestFailed, err)
	}
	return req, nil
}

func (m *Manager) isConfigured() bool {
	if !m.cfg.UpdateEnabled {
		return false
	}
	if _, err := os.Stat(updaterPathUnitPath(m.cfg)); err != nil {
		return false
	}
	if err := os.MkdirAll(requestDir(m.cfg), 0o750); err != nil {
		return false
	}
	probe := requestDir(m.cfg) + "/.write-check"
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return false
	}
	_ = os.Remove(probe)
	return true
}

func (m *Manager) shouldRefresh(ctx context.Context, st *store.Store) bool {
	lastCheckRaw, _ := m.getSetting(ctx, st, settingLastCheckAt)
	if strings.TrimSpace(lastCheckRaw) == "" {
		return true
	}
	lastCheck, err := time.Parse(time.RFC3339, lastCheckRaw)
	if err != nil {
		return true
	}
	interval := time.Duration(m.cfg.UpdateCheckIntervalMin) * time.Minute
	return m.now().After(lastCheck.Add(interval))
}

func (m *Manager) refreshLatest(ctx context.Context, st *store.Store) error {
	etag, _ := m.getSetting(ctx, st, settingETag)
	latest, newETag, notModified, err := m.gh.latestRelease(ctx, etag)
	now := m.now().Format(time.RFC3339)
	_ = st.UpsertSetting(ctx, settingLastCheckAt, now)
	if err != nil {
		_ = st.UpsertSetting(ctx, settingLastCheckError, err.Error())
		return err
	}
	_ = st.UpsertSetting(ctx, settingLastCheckError, "")
	if newETag != "" {
		_ = st.UpsertSetting(ctx, settingETag, newETag)
	}
	if notModified {
		return nil
	}
	_ = st.UpsertSetting(ctx, settingLatestTag, strings.TrimSpace(latest.TagName))
	_ = st.UpsertSetting(ctx, settingLatestURL, strings.TrimSpace(latest.HTMLURL))
	if !latest.PublishedAt.IsZero() {
		_ = st.UpsertSetting(ctx, settingLatestPublished, latest.PublishedAt.UTC().Format(time.RFC3339))
	}
	return nil
}

func (m *Manager) MarkSuccess(ctx context.Context, st *store.Store, targetVersion string) {
	_ = st.UpsertSetting(ctx, settingLastSuccessVer, strings.TrimSpace(targetVersion))
	_ = st.UpsertSetting(ctx, settingLastSuccessAt, m.now().Format(time.RFC3339))
}

func (m *Manager) getSetting(ctx context.Context, st *store.Store, key string) (string, bool) {
	v, ok, err := st.GetSetting(ctx, key)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(v), ok
}

func compareVersions(current, latest string) bool {
	c := strings.TrimSpace(current)
	l := strings.TrimSpace(latest)
	if c == "" || l == "" {
		return false
	}
	if strings.EqualFold(c, l) {
		return false
	}
	trim := func(v string) string {
		return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "v")
	}
	return trim(c) != trim(l)
}

func ApplyErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrUpdaterNotConfigured):
		return "updater_not_configured"
	case errors.Is(err, ErrUpdateInProgress):
		return "update_in_progress"
	case errors.Is(err, ErrInvalidTargetVersion):
		return "invalid_target_version"
	default:
		return "update_request_failed"
	}
}

func readApplyStatusTolerant(path string) (ApplyStatus, error) {
	st, err := readApplyStatus(path)
	if err == nil {
		return st, nil
	}
	if os.IsPermission(err) {
		// Treat unreadable status files as unknown/idle and allow queueing a new request.
		return ApplyStatus{State: ApplyStateIdle}, nil
	}
	return ApplyStatus{}, err
}
