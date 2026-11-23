package disk

import (
	"io/fs"
	"os"
	"path/filepath"
)

// writeFile fills a temporary file in the same directory as path and renames it
// over path. A process reading path sees either the previous contents or the new
// ones rather than a truncated file, and mode is applied on every write instead
// of only when the file is created. Readers that already have the old file open
// can finish reading it; the old file is reclaimed after the last reader closes.
func writeFile(path string, data []byte, mode fs.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp")
	if err != nil {
		return err
	}
	tmpPath := file.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}

	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}

	// Chmod rather than passing the mode to CreateTemp, so that the configured
	// mode is not reduced by the process umask.
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}

	if err := file.Close(); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}
