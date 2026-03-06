package update

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"despatch/internal/config"
)

type updaterDirGroup int

const (
	updaterDirGroupRoot updaterDirGroup = iota
	updaterDirGroupDespatch
)

type updaterDirSpec struct {
	path  string
	mode  os.FileMode
	group updaterDirGroup
}

type updaterDirEnsureOptions struct {
	strictPerms      bool
	enforceOwnership bool
}

func updaterDirContract(cfg config.Config) []updaterDirSpec {
	base := filepath.Clean(cfg.UpdateBaseDir)
	return []updaterDirSpec{
		{path: base, mode: 0o750, group: updaterDirGroupDespatch},
		{path: filepath.Clean(requestDir(cfg)), mode: 0o770, group: updaterDirGroupDespatch},
		{path: filepath.Clean(statusDir(cfg)), mode: 0o770, group: updaterDirGroupDespatch},
		{path: filepath.Clean(lockDir(cfg)), mode: 0o750, group: updaterDirGroupRoot},
		{path: filepath.Clean(workDir(cfg)), mode: 0o750, group: updaterDirGroupRoot},
		{path: filepath.Clean(backupsDir(cfg)), mode: 0o750, group: updaterDirGroupRoot},
	}
}

func updaterRequestStatusContract(cfg config.Config) []updaterDirSpec {
	base := filepath.Clean(cfg.UpdateBaseDir)
	return []updaterDirSpec{
		{path: base, mode: 0o750, group: updaterDirGroupDespatch},
		{path: filepath.Clean(requestDir(cfg)), mode: 0o770, group: updaterDirGroupDespatch},
		{path: filepath.Clean(statusDir(cfg)), mode: 0o770, group: updaterDirGroupDespatch},
	}
}

func updaterDirModeForPath(cfg config.Config, dirPath string, fallback os.FileMode) os.FileMode {
	target := filepath.Clean(dirPath)
	for _, spec := range updaterDirContract(cfg) {
		if spec.path == target {
			return spec.mode
		}
	}
	return fallback
}

func ensureUpdaterRuntimeDirectories(cfg config.Config) error {
	opts := updaterDirEnsureOptions{
		strictPerms:      true,
		enforceOwnership: os.Geteuid() == 0,
	}
	return ensureUpdaterDirSpecs(updaterDirContract(cfg), opts)
}

func ensureUpdaterRequestStatusDirectories(cfg config.Config) error {
	return ensureUpdaterDirSpecs(updaterRequestStatusContract(cfg), updaterDirEnsureOptions{
		strictPerms: false,
	})
}

func ensureUpdaterWritableDirectory(cfg config.Config, dirPath string) error {
	mode := updaterDirModeForPath(cfg, dirPath, 0o750)
	if err := os.MkdirAll(dirPath, mode); err != nil {
		return err
	}
	if err := os.Chmod(dirPath, mode); err != nil && !isUpdaterPermissionError(err) {
		return err
	}
	return nil
}

func ensureUpdaterDirSpecs(specs []updaterDirSpec, opts updaterDirEnsureOptions) error {
	despatchGID := 0
	if opts.enforceOwnership {
		gid, err := lookupDespatchGroupID()
		if err != nil {
			return err
		}
		despatchGID = gid
	}
	for _, spec := range specs {
		if err := os.MkdirAll(spec.path, spec.mode); err != nil {
			return err
		}
		if err := os.Chmod(spec.path, spec.mode); err != nil {
			if opts.strictPerms || !isUpdaterPermissionError(err) {
				return err
			}
		}
		if opts.enforceOwnership {
			gid := 0
			if spec.group == updaterDirGroupDespatch {
				gid = despatchGID
			}
			if err := os.Chown(spec.path, 0, gid); err != nil {
				return err
			}
		}
	}
	return nil
}

func lookupDespatchGroupID() (int, error) {
	u, err := user.Lookup("despatch")
	if err != nil {
		return 0, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, err
	}
	return gid, nil
}

func isUpdaterPermissionError(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM)
}
