package disk

import (
	"io/fs"
	"os"
	"path/filepath"
)

// writeFile fills a temporary file in the same directory as path and renames it
// over path. A process reading path sees either the previous contents or the new
// ones rather than a truncated file, and mode is applied on every write instead
// of only when the file is created.
func writeFile(path string, data []byte, mode fs.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp")
	if err != nil {
		return err
	}
	tmpPath := file.Name()

	if err := writeAndClose(file, data, mode); err != nil {
		file.Close()
		os.Remove(tmpPath)
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}

	return nil
}

func writeAndClose(file *os.File, data []byte, mode fs.FileMode) error {
	if _, err := file.Write(data); err != nil {
		return err
	}

	if err := file.Sync(); err != nil {
		return err
	}

	// Chmod rather than passing the mode to CreateTemp, so that the configured
	// mode is not reduced by the process umask.
	if err := file.Chmod(mode); err != nil {
		return err
	}

	return file.Close()
}
