package disk

import (
	"io/fs"
	"os"
	"path/filepath"
)

// writeFile writes beside path and renames the completed file over it. Readers
// therefore see either the old contents or the new contents, never a partial
// write. Chmod is applied to each replacement so the configured mode is not
// lost on renewal.
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

	// CreateTemp uses a restrictive default mode, so apply the configured mode
	// explicitly rather than relying on the process umask.
	if err := file.Chmod(mode); err != nil {
		return err
	}

	return file.Close()
}
