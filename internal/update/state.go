package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func ensureDirs(cfgPath []string, mode os.FileMode) error {
	for _, p := range cfgPath {
		if err := os.MkdirAll(p, mode); err != nil {
			return err
		}
	}
	return nil
}

func readJSONFile(path string, out any) error {
	if err := rejectSymlink(path); err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func writeJSONAtomic(path string, payload any, mode os.FileMode) error {
	if err := rejectSymlink(path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink path: %s", path)
	}
	return nil
}

func readApplyStatus(cfgPath string) (ApplyStatus, error) {
	var st ApplyStatus
	if err := readJSONFile(cfgPath, &st); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ApplyStatus{State: ApplyStateIdle}, nil
		}
		return ApplyStatus{}, err
	}
	if st.State == "" {
		st.State = ApplyStateIdle
	}
	return st, nil
}
