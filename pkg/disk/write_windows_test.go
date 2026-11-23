//go:build windows

package disk

import (
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func assertFileMode(t *testing.T, file string, expected fs.FileMode) {
	t.Helper()

	// Windows does not expose the configured POSIX permission bits through
	// os.FileMode. The common tests still verify that the file was written.
	_ = expected
	_, err := os.Stat(file)
	require.NoError(t, err)
}
