package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mailclient/internal/config"
	"mailclient/internal/db"
	"mailclient/internal/store"
)

func newUpdateTestStore(t *testing.T) *store.Store {
	t.Helper()
	sqdb, err := db.OpenSQLite(filepath.Join(t.TempDir(), "app.db"), 1, 1, time.Minute)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sqdb.Close() })
	for _, migration := range []string{
		filepath.Join("..", "..", "migrations", "001_init.sql"),
		filepath.Join("..", "..", "migrations", "002_users_mail_login.sql"),
	} {
		if err := db.ApplyMigrationFile(sqdb, migration); err != nil {
			t.Fatalf("apply migration %s: %v", migration, err)
		}
	}
	return store.New(sqdb)
}

func TestCompareVersions(t *testing.T) {
	t.Parallel()
	if compareVersions("v1.2.3", "v1.2.3") {
		t.Fatalf("expected same version to not be an update")
	}
	if !compareVersions("v1.2.3", "v1.2.4") {
		t.Fatalf("expected newer version to be detected")
	}
	if compareVersions("", "v1.2.4") {
		t.Fatalf("expected empty current version to not claim update")
	}
}

func TestQueueApplyValidationAndInProgress(t *testing.T) {
	st := newUpdateTestStore(t)
	base := t.TempDir()
	unitDir := filepath.Join(base, "units")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatalf("mkdir unit dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(unitDir, "mailclient-updater.path"), []byte("ok"), 0o644); err != nil {
		t.Fatalf("write unit file: %v", err)
	}
	cfg := config.Config{
		UpdateEnabled:          true,
		UpdateRepoOwner:        "2high4schooltoday",
		UpdateRepoName:         "new-mail-client",
		UpdateCheckIntervalMin: 60,
		UpdateHTTPTimeoutSec:   10,
		UpdateBackupKeep:       3,
		UpdateBaseDir:          filepath.Join(base, "update"),
		UpdateInstallDir:       filepath.Join(base, "install"),
		UpdateServiceName:      "mailclient",
		UpdateSystemdUnitDir:   unitDir,
	}
	mgr := NewManager(cfg)

	if _, err := mgr.QueueApply(context.Background(), st, "admin@example.com", "bad version!", ""); err == nil {
		t.Fatalf("expected invalid target version error")
	}
	req, err := mgr.QueueApply(context.Background(), st, "admin@example.com", "v1.2.3", "req-1")
	if err != nil {
		t.Fatalf("queue apply: %v", err)
	}
	if req.RequestID != "req-1" {
		t.Fatalf("unexpected request id: %q", req.RequestID)
	}
	if _, err := mgr.QueueApply(context.Background(), st, "admin@example.com", "v1.2.4", "req-2"); err == nil {
		t.Fatalf("expected in-progress protection on second request")
	}
}

func TestGitHubLatestReleaseWithETag(t *testing.T) {
	t.Parallel()
	serverETag := `"abc123"`
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/2high4schooltoday/new-mail-client/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == serverETag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", serverETag)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.3","name":"v1.2.3","published_at":"2026-01-01T00:00:00Z","html_url":"https://example.test/release","assets":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := config.Config{
		UpdateRepoOwner:      "2high4schooltoday",
		UpdateRepoName:       "new-mail-client",
		UpdateHTTPTimeoutSec: 5,
	}
	gh := newGitHubClient(cfg)
	gh.baseURL = srv.URL

	first, etag, notModified, err := gh.latestRelease(context.Background(), "")
	if err != nil {
		t.Fatalf("first latest release call: %v", err)
	}
	if notModified {
		t.Fatalf("did not expect not-modified on first request")
	}
	if first.TagName != "v1.2.3" {
		t.Fatalf("unexpected tag: %q", first.TagName)
	}
	second, _, notModified, err := gh.latestRelease(context.Background(), etag)
	if err != nil {
		t.Fatalf("second latest release call: %v", err)
	}
	if !notModified {
		t.Fatalf("expected not-modified on second request")
	}
	if second.TagName != "" {
		t.Fatalf("expected empty release payload on 304, got %q", second.TagName)
	}
}
