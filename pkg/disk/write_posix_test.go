//go:build !windows

package disk

import (
	"io/fs"
	"os"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spiffe-helper/test/spiffetest"
	"github.com/stretchr/testify/require"
)

// The configuration example in README.md sets every file mode to 0444, so a
// renewal has to be able to replace a file it cannot open for writing.
func TestWriteX509ContextWithReadOnlyFileMode(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("Skipping test that relies on file permissions, which root ignores")
	}

	readOnly := fs.FileMode(0444)

	rootCA := spiffetest.NewCA(t)
	spiffeID := spiffeid.RequireFromString(testWorkloadID)
	certs, key := rootCA.CreateX509SVID(spiffeID.String())

	x509Context := &workloadapi.X509Context{
		Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(spiffeID.TrustDomain(), rootCA.Roots())),
		SVIDs: []*x509svid.SVID{
			{
				ID:           spiffeID,
				Certificates: certs,
				PrivateKey:   key,
			},
		},
	}

	tempDir := t.TempDir()
	disk := NewX509(X509Config{
		Dir:                tempDir,
		SVIDFileName:       svidFileName,
		SVIDKeyFileName:    svidKeyFileName,
		SVIDBundleFileName: svidBundleFileName,
		CertFileMode:       readOnly,
		KeyFileMode:        readOnly,
	})

	require.NoError(t, disk.WriteX509Context(x509Context))
	require.NoError(t, disk.WriteX509Context(x509Context))

	for _, file := range []string{disk.SVIDPath(), disk.SVIDKeyPath(), disk.SVIDBundlePath()} {
		info, err := os.Stat(file)
		require.NoError(t, err)
		require.Equal(t, readOnly, info.Mode().Perm(), file)
	}

	entries, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	require.ElementsMatch(t, []string{svidFileName, svidKeyFileName, svidBundleFileName}, names)
}
