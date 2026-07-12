package spire

import (
	"crypto/sha1" //nolint:gosec // SPIRE's X509-SVID agent ID uses the certificate SHA-1 fingerprint.
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/spiffe-helper/test/integration/internal/dockercompose"
	"github.com/spiffe/spiffe-helper/test/util"
	"github.com/stretchr/testify/require"
)

const (
	moduleRoot  = "../.."
	trustDomain = "example.org"
	spireWait   = 60 * time.Second
)

type Environment struct {
	dockerCompose *dockercompose.Project
	AgentParentID string
	bundleDir     string
}

type Entry struct {
	SPIFFEID  string
	Selectors []string
	DNSNames  []string
	TTL       time.Duration
}

func Start(tb testing.TB, dockerCompose *dockercompose.Project) *Environment {
	tb.Helper()
	require.NotNil(tb, dockerCompose, "Docker Compose project is required")

	bundleDir := spireBundleDir(tb)

	dockerCompose.Load(tb, "spire/compose.yaml", map[string]string{
		"SPIRE_BUNDLE_DIR": bundleDir,
		"GO_VERSION":       readGoVersion(tb, moduleRoot),
	})

	startServer(tb, dockerCompose)
	publishBundle(tb, dockerCompose, bundleDir)

	startAgent(tb, dockerCompose)

	return &Environment{
		dockerCompose: dockerCompose,
		AgentParentID: agentParentID(tb),
		bundleDir:     bundleDir,
	}
}

func (e *Environment) Cleanup(logf func(string, ...any)) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if e.bundleDir == "" {
		return
	}
	if err := os.RemoveAll(e.bundleDir); err != nil {
		logf("remove SPIRE bundle directory: %v", err)
	}
}

func (e *Environment) RegisterEntry(tb testing.TB, entry Entry) {
	tb.Helper()

	require.NotEmpty(tb, entry.SPIFFEID, "entry SPIFFE ID is required")
	require.NotEmpty(tb, entry.Selectors, "at least one entry selector is required")

	args := []string{
		"./bin/spire-server", "entry", "create",
		"-parentID", e.AgentParentID,
		"-spiffeID", entry.SPIFFEID,
	}
	for _, selector := range entry.Selectors {
		args = append(args, "-selector", selector)
	}
	for _, dnsName := range entry.DNSNames {
		args = append(args, "-dns", dnsName)
	}
	if entry.TTL > 0 {
		args = append(args, "-x509SVIDTTL", strconv.FormatInt(int64(entry.TTL.Seconds()), 10))
	}

	e.dockerCompose.Exec(tb, "spire-server", args...)
}

func (e *Environment) UpdateEntry(tb testing.TB, entry Entry) {
	tb.Helper()

	require.NotEmpty(tb, entry.SPIFFEID, "entry SPIFFE ID is required")
	require.NotEmpty(tb, entry.Selectors, "at least one entry selector is required")

	args := []string{
		"./bin/spire-server", "entry", "update",
		"-entryID", e.entryID(tb, entry.SPIFFEID),
		"-parentID", e.AgentParentID,
		"-spiffeID", entry.SPIFFEID,
	}
	for _, selector := range entry.Selectors {
		args = append(args, "-selector", selector)
	}
	for _, dnsName := range entry.DNSNames {
		args = append(args, "-dns", dnsName)
	}
	if entry.TTL > 0 {
		args = append(args, "-x509SVIDTTL", strconv.FormatInt(int64(entry.TTL.Seconds()), 10))
	}

	e.dockerCompose.Exec(tb, "spire-server", args...)
}

func (e *Environment) ShowEntry(tb testing.TB, spiffeID string) string {
	tb.Helper()

	require.NotEmpty(tb, spiffeID, "entry SPIFFE ID is required")

	return e.dockerCompose.Exec(
		tb,
		"spire-server",
		"./bin/spire-server", "entry", "show",
		"-spiffeID", spiffeID,
	)
}

func (e *Environment) entryID(tb testing.TB, spiffeID string) string {
	tb.Helper()

	entry := e.ShowEntry(tb, spiffeID)
	for _, line := range strings.Split(entry, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(key) == "Entry ID" {
			entryID := strings.TrimSpace(value)
			require.NotEmpty(tb, entryID, "entry ID is required")
			return entryID
		}
	}

	require.FailNow(tb, "entry ID not found", "SPIFFE ID %q entry:\n%s", spiffeID, entry)
	return ""
}

func readGoVersion(tb testing.TB, moduleRoot string) string {
	tb.Helper()

	goMod, err := os.ReadFile(filepath.Join(moduleRoot, "go.mod"))
	require.NoError(tb, err, "read go.mod")

	for _, line := range strings.Split(string(goMod), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "go" {
			return fields[1]
		}
	}

	require.FailNow(tb, "go version not found in go.mod")
	return ""
}

func spireBundleDir(tb testing.TB) string {
	tb.Helper()

	buildDir := filepath.Join(moduleRoot, ".build", "integration")
	require.NoError(tb, os.MkdirAll(buildDir, 0750), "create integration build directory")

	bundleDir, err := os.MkdirTemp(buildDir, "spire-bundle-")
	require.NoError(tb, err, "create SPIRE bundle directory")

	bundleDir, err = filepath.Abs(bundleDir)
	require.NoError(tb, err, "resolve SPIRE bundle directory")

	return bundleDir
}

func startServer(tb testing.TB, dockerCompose *dockercompose.Project) {
	tb.Helper()

	dockerCompose.Up(tb, "spire-server")
	dockerCompose.WaitForExec(
		tb,
		"spire-server",
		spireWait,
		"./bin/spire-server", "healthcheck",
	)
}

func publishBundle(tb testing.TB, dockerCompose *dockercompose.Project, bundleDir string) {
	tb.Helper()

	bundle := dockerCompose.Exec(tb, "spire-server", "./bin/spire-server", "bundle", "show")
	bootstrapPath := filepath.Join(bundleDir, "bootstrap.crt")
	require.NoError(tb, os.WriteFile(bootstrapPath, []byte(bundle), 0600), "write SPIRE agent bootstrap bundle")
}

func startAgent(tb testing.TB, dockerCompose *dockercompose.Project) {
	tb.Helper()

	dockerCompose.Up(tb, "spire-agent")
	dockerCompose.WaitForExec(
		tb,
		"spire-agent",
		spireWait,
		"./bin/spire-agent", "healthcheck",
		"-socketPath", "/run/spire/api.sock",
	)
}

func agentParentID(tb testing.TB) string {
	tb.Helper()

	agentCertPath := filepath.Join("spire", "conf", "agent", "agent.crt.pem")
	return x509POPAgentID(tb, agentCertPath)
}

func x509POPAgentID(tb testing.TB, path string) string {
	tb.Helper()

	certPEM, err := os.ReadFile(path)
	require.NoError(tb, err, "read agent certificate")

	cert, err := util.ParseCertificate(certPEM)
	require.NoError(tb, err, "parse agent certificate %q", path)

	fingerprint := sha1.Sum(cert.Raw) //nolint:gosec // SPIRE's X509-SVID agent ID uses the certificate SHA-1 fingerprint.
	return "spiffe://" + trustDomain + "/spire/agent/x509pop/" + hex.EncodeToString(fingerprint[:])
}
