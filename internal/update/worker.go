package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"mailclient/internal/config"
	"mailclient/internal/db"
	"mailclient/internal/store"
	"mailclient/internal/version"
)

func RunWorker(ctx context.Context, cfg config.Config) error {
	mgr := NewManager(cfg)
	return mgr.runWorker(ctx)
}

func (m *Manager) runWorker(ctx context.Context) error {
	if !m.cfg.UpdateEnabled {
		return nil
	}
	if err := ensureDirs([]string{
		requestDir(m.cfg),
		statusDir(m.cfg),
		lockDir(m.cfg),
		workDir(m.cfg),
		backupsDir(m.cfg),
	}, 0o750); err != nil {
		return err
	}
	lockFD, err := os.OpenFile(lockPath(m.cfg), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return err
	}
	_, _ = lockFD.WriteString(fmt.Sprintf("pid=%d started_at=%s\n", os.Getpid(), m.now().Format(time.RFC3339)))
	_ = lockFD.Close()
	defer os.Remove(lockPath(m.cfg))

	var req ApplyRequest
	if err := readJSONFile(requestPath(m.cfg), &req); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if strings.TrimSpace(req.RequestID) == "" {
		req.RequestID = fmt.Sprintf("update-%d", m.now().Unix())
	}
	if req.RequestedAt.IsZero() {
		req.RequestedAt = m.now()
	}

	started := m.now()
	_ = writeJSONAtomic(statusPath(m.cfg), ApplyStatus{
		State:         ApplyStateInProgress,
		RequestID:     req.RequestID,
		RequestedAt:   req.RequestedAt,
		StartedAt:     started,
		TargetVersion: strings.TrimSpace(req.TargetVersion),
		FromVersion:   version.Current().Version,
	}, 0o640)

	finalStatus := ApplyStatus{
		State:         ApplyStateFailed,
		RequestID:     req.RequestID,
		RequestedAt:   req.RequestedAt,
		StartedAt:     started,
		FinishedAt:    m.now(),
		TargetVersion: strings.TrimSpace(req.TargetVersion),
		FromVersion:   version.Current().Version,
	}
	defer func() {
		finalStatus.FinishedAt = m.now()
		_ = writeJSONAtomic(statusPath(m.cfg), finalStatus, 0o640)
		_ = os.Remove(requestPath(m.cfg))
	}()

	target := strings.TrimSpace(req.TargetVersion)
	if target != "" && !targetVersionRx.MatchString(target) {
		finalStatus.Error = ErrInvalidTargetVersion.Error()
		return ErrInvalidTargetVersion
	}
	toVersion, rollback, err := m.applyRelease(ctx, req)
	if err != nil {
		finalStatus.Error = err.Error()
		finalStatus.ToVersion = toVersion
		finalStatus.RolledBack = rollback
		if rollback {
			finalStatus.State = ApplyStateRolledBack
		}
		return err
	}
	finalStatus.State = ApplyStateCompleted
	finalStatus.ToVersion = toVersion

	if sqdb, err := db.OpenSQLite(m.cfg.DBPath, 1, 1, time.Minute); err == nil {
		st := store.New(sqdb)
		m.MarkSuccess(context.Background(), st, toVersion)
		_ = sqdb.Close()
	}
	return nil
}

func (m *Manager) applyRelease(ctx context.Context, req ApplyRequest) (string, bool, error) {
	release, err := m.resolveRelease(ctx, strings.TrimSpace(req.TargetVersion))
	if err != nil {
		return "", false, err
	}
	arch := runtime.GOARCH
	archiveName := fmt.Sprintf("mailclient-linux-%s.tar.gz", arch)
	checksumName := "checksums.txt"
	archiveURL, ok := findAssetURL(release, archiveName)
	if !ok {
		return "", false, fmt.Errorf("release asset %s not found", archiveName)
	}
	checksumURL, ok := findAssetURL(release, checksumName)
	if !ok {
		return "", false, fmt.Errorf("release asset %s not found", checksumName)
	}

	runID := req.RequestID
	if strings.TrimSpace(runID) == "" {
		runID = fmt.Sprintf("run-%d", m.now().Unix())
	}
	runWork := filepath.Join(workDir(m.cfg), sanitizePathToken(runID))
	_ = os.RemoveAll(runWork)
	if err := os.MkdirAll(runWork, 0o750); err != nil {
		return "", false, err
	}
	defer os.RemoveAll(runWork)

	archivePath := filepath.Join(runWork, archiveName)
	checksumPath := filepath.Join(runWork, checksumName)
	if err := m.downloadAsset(ctx, archiveURL, archivePath); err != nil {
		return "", false, err
	}
	if err := m.downloadAsset(ctx, checksumURL, checksumPath); err != nil {
		return "", false, err
	}
	if err := verifyChecksumFile(checksumPath, archivePath, archiveName); err != nil {
		return "", false, err
	}

	extracted := filepath.Join(runWork, "extract")
	if err := extractTarGz(archivePath, extracted); err != nil {
		return "", false, err
	}
	payloadRoot, err := findPayloadRoot(extracted)
	if err != nil {
		return "", false, err
	}

	stageDir := filepath.Join(m.cfg.UpdateInstallDir, ".update-stage-"+sanitizePathToken(runID))
	if err := os.RemoveAll(stageDir); err != nil {
		return "", false, err
	}
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		return "", false, err
	}
	defer os.RemoveAll(stageDir)

	if err := copyFile(filepath.Join(payloadRoot, "mailclient"), filepath.Join(stageDir, "mailclient"), 0o755); err != nil {
		return "", false, err
	}
	if err := copyDir(filepath.Join(payloadRoot, "web"), filepath.Join(stageDir, "web")); err != nil {
		return "", false, err
	}
	if err := copyDir(filepath.Join(payloadRoot, "migrations"), filepath.Join(stageDir, "migrations")); err != nil {
		return "", false, err
	}

	prevBin := filepath.Join(m.cfg.UpdateInstallDir, ".prev-mailclient-"+sanitizePathToken(runID))
	prevWeb := filepath.Join(m.cfg.UpdateInstallDir, ".prev-web-"+sanitizePathToken(runID))
	prevMig := filepath.Join(m.cfg.UpdateInstallDir, ".prev-migrations-"+sanitizePathToken(runID))

	currentBin := filepath.Join(m.cfg.UpdateInstallDir, "mailclient")
	currentWeb := filepath.Join(m.cfg.UpdateInstallDir, "web")
	currentMig := filepath.Join(m.cfg.UpdateInstallDir, "migrations")
	stageBin := filepath.Join(stageDir, "mailclient")
	stageWeb := filepath.Join(stageDir, "web")
	stageMig := filepath.Join(stageDir, "migrations")

	for _, p := range []string{prevBin, prevWeb, prevMig} {
		_ = os.RemoveAll(p)
	}

	swapped := false
	rollback := func() error {
		_ = os.RemoveAll(currentWeb)
		_ = os.RemoveAll(currentMig)
		_ = os.Remove(currentBin)
		if _, err := os.Stat(prevWeb); err == nil {
			if err := os.Rename(prevWeb, currentWeb); err != nil {
				return err
			}
		}
		if _, err := os.Stat(prevMig); err == nil {
			if err := os.Rename(prevMig, currentMig); err != nil {
				return err
			}
		}
		if _, err := os.Stat(prevBin); err == nil {
			if err := os.Rename(prevBin, currentBin); err != nil {
				return err
			}
		}
		return nil
	}

	if err := swapPath(currentBin, stageBin, prevBin); err != nil {
		return "", false, err
	}
	if err := swapPath(currentWeb, stageWeb, prevWeb); err != nil {
		_ = rollback()
		return "", false, err
	}
	if err := swapPath(currentMig, stageMig, prevMig); err != nil {
		_ = rollback()
		return "", false, err
	}
	swapped = true

	if err := chownRuntimeArtifacts(m.cfg.UpdateInstallDir); err != nil {
		if rbErr := rollback(); rbErr != nil {
			return "", false, fmt.Errorf("chown failed: %v; rollback failed: %v", err, rbErr)
		}
		return "", true, err
	}
	if err := runCmd(ctx, "systemctl", "restart", m.cfg.UpdateServiceName); err != nil {
		if rbErr := rollback(); rbErr != nil {
			return "", false, fmt.Errorf("service restart failed: %v; rollback failed: %v", err, rbErr)
		}
		_ = runCmd(context.Background(), "systemctl", "restart", m.cfg.UpdateServiceName)
		return "", true, err
	}
	if err := checkServiceHealth(ctx, m.cfg.ListenAddr); err != nil {
		if swapped {
			if rbErr := rollback(); rbErr != nil {
				return release.TagName, false, fmt.Errorf("health check failed: %v; rollback failed: %v", err, rbErr)
			}
			_ = runCmd(context.Background(), "systemctl", "restart", m.cfg.UpdateServiceName)
			return release.TagName, true, err
		}
		return release.TagName, false, err
	}

	backupDest := filepath.Join(backupsDir(m.cfg), time.Now().UTC().Format("20060102T150405")+"-"+sanitizePathToken(runID))
	if err := os.MkdirAll(backupDest, 0o750); err != nil {
		return release.TagName, false, err
	}
	_ = os.Rename(prevBin, filepath.Join(backupDest, "mailclient"))
	_ = os.Rename(prevWeb, filepath.Join(backupDest, "web"))
	_ = os.Rename(prevMig, filepath.Join(backupDest, "migrations"))
	trimBackups(backupsDir(m.cfg), m.cfg.UpdateBackupKeep)

	return release.TagName, false, nil
}

func (m *Manager) resolveRelease(ctx context.Context, targetVersion string) (githubRelease, error) {
	if targetVersion != "" {
		return m.gh.releaseByTag(ctx, targetVersion)
	}
	rel, _, _, err := m.gh.latestReleaseRaw(ctx, "")
	return rel, err
}

func (m *Manager) downloadAsset(ctx context.Context, rawURL, destPath string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return fmt.Errorf("refusing non-https asset url")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "mailclient-updater/1")
	if token := strings.TrimSpace(m.cfg.UpdateGitHubToken); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: time.Duration(m.cfg.UpdateHTTPTimeoutSec) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("asset download failed with status %d", resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o750); err != nil {
		return err
	}
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func verifyChecksumFile(checksumPath, archivePath, archiveName string) error {
	raw, err := os.ReadFile(checksumPath)
	if err != nil {
		return err
	}
	expected := ""
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		if fields[1] == archiveName || strings.TrimPrefix(fields[1], "*") == archiveName {
			expected = fields[0]
			break
		}
	}
	if expected == "" {
		return fmt.Errorf("checksum for %s not found", archiveName)
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(strings.TrimSpace(expected), got) {
		return fmt.Errorf("checksum mismatch for %s", archiveName)
	}
	return nil
}

func extractTarGz(src, dest string) error {
	if err := os.MkdirAll(dest, 0o750); err != nil {
		return err
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(strings.TrimPrefix(hdr.Name, "/"))
		if name == "." || strings.HasPrefix(name, "..") {
			return fmt.Errorf("invalid archive path: %q", hdr.Name)
		}
		target := filepath.Join(dest, name)
		if !strings.HasPrefix(target, dest+string(os.PathSeparator)) && target != dest {
			return fmt.Errorf("invalid archive path: %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				_ = out.Close()
				return err
			}
			_ = out.Close()
		}
	}
	return nil
}

func findPayloadRoot(extractDir string) (string, error) {
	required := []string{"mailclient", "web", "migrations"}
	if hasRequiredPaths(extractDir, required) {
		return extractDir, nil
	}
	entries, err := os.ReadDir(extractDir)
	if err != nil {
		return "", err
	}
	if len(entries) == 1 && entries[0].IsDir() {
		root := filepath.Join(extractDir, entries[0].Name())
		if hasRequiredPaths(root, required) {
			return root, nil
		}
	}
	return "", fmt.Errorf("release payload missing required files (mailclient, web, migrations)")
}

func hasRequiredPaths(root string, required []string) bool {
	for _, rel := range required {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			return false
		}
	}
	return true
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		return copyFile(path, target, info.Mode())
	})
}

func swapPath(current, staged, previous string) error {
	if err := os.Rename(current, previous); err != nil {
		return err
	}
	if err := os.Rename(staged, current); err != nil {
		_ = os.Rename(previous, current)
		return err
	}
	return nil
}

func runCmd(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %v (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func checkServiceHealth(ctx context.Context, listenAddr string) error {
	base := localBaseURL(listenAddr)
	client := &http.Client{Timeout: 5 * time.Second}
	endpoints := []string{"/health/live", "/api/v1/setup/status"}
	deadline := time.Now().Add(40 * time.Second)
	for {
		allOK := true
		for _, ep := range endpoints {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+ep, nil)
			resp, err := client.Do(req)
			if err != nil {
				allOK = false
				break
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				allOK = false
				break
			}
		}
		if allOK {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("health checks failed after restart")
		}
		time.Sleep(1200 * time.Millisecond)
	}
}

func localBaseURL(listenAddr string) string {
	addr := strings.TrimSpace(listenAddr)
	if addr == "" {
		return "http://127.0.0.1:8080"
	}
	if strings.HasPrefix(addr, ":") {
		return "http://127.0.0.1" + addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://127.0.0.1:8080"
	}
	host = strings.TrimSpace(host)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

func chownRuntimeArtifacts(installDir string) error {
	u, err := user.Lookup("mailclient")
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	paths := []string{
		filepath.Join(installDir, "mailclient"),
		filepath.Join(installDir, "web"),
		filepath.Join(installDir, "migrations"),
	}
	for _, p := range paths {
		if err := chownRecursive(p, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func chownRecursive(path string, uid, gid int) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return os.Chown(path, uid, gid)
	}
	return filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(p, uid, gid)
	})
}

func trimBackups(base string, keep int) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	type item struct {
		name string
		time time.Time
	}
	all := make([]item, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		all = append(all, item{name: e.Name(), time: info.ModTime()})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].time.After(all[j].time) })
	for i := keep; i < len(all); i++ {
		_ = os.RemoveAll(filepath.Join(base, all[i].name))
	}
}

func sanitizePathToken(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
}
