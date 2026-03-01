package update

import (
	"path/filepath"

	"mailclient/internal/config"
)

func requestDir(cfg config.Config) string {
	return filepath.Join(cfg.UpdateBaseDir, "request")
}

func statusDir(cfg config.Config) string {
	return filepath.Join(cfg.UpdateBaseDir, "status")
}

func lockDir(cfg config.Config) string {
	return filepath.Join(cfg.UpdateBaseDir, "lock")
}

func workDir(cfg config.Config) string {
	return filepath.Join(cfg.UpdateBaseDir, "work")
}

func backupsDir(cfg config.Config) string {
	return filepath.Join(cfg.UpdateBaseDir, "backups")
}

func requestPath(cfg config.Config) string {
	return filepath.Join(requestDir(cfg), "update-request.json")
}

func statusPath(cfg config.Config) string {
	return filepath.Join(statusDir(cfg), "update-status.json")
}

func lockPath(cfg config.Config) string {
	return filepath.Join(lockDir(cfg), "update.lock")
}

func updaterPathUnitPath(cfg config.Config) string {
	return filepath.Join(cfg.UpdateSystemdUnitDir, "mailclient-updater.path")
}
