//go:build !windows

package disk

import (
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func assertFileMode(t *testing.T, file string, expected fs.FileMode) {
	t.Helper()

	info, err := os.Stat(file)
	require.NoError(t, err)
	require.Equal(t, expected, info.Mode().Perm(), file)
}
