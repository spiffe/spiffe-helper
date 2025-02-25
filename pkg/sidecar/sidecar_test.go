package sidecar

/*
 * Test suite for common sidecar functionality
 */

import (
	"context"
	"crypto"
	"crypto/x509"
	"os"
	"path"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spiffe-helper/test/spiffetest"
	"github.com/spiffe/spiffe-helper/test/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Validate basic sidecar command behaviour, simulating daemon-mode execution with
// workload api server responses. These exercise behaviour after receiving the
//
// Further tests should be added for restarting short-lived commands each time
// a cert is delivered, signalling long-running commands, commands exiting on a
// signal, command stdio handling, etc.
func TestSidecar_TestCmdRuns(t *testing.T) {
	if runtime.GOOS == "windows" {
		// If someone wants to write these to only invoke go helpers that
		// are bundled with this test suite, so it can run on Windows, that
		// would be fine. Or find Windows equivalents for the commands,
		// like in TestSidecar_TestCmdRunsRelaunchShortlived.
		t.Skip("Skipping tests that invoke unix shell commands on Windows")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tmpdir := t.TempDir()
	touchTestFile := path.Join(tmpdir, "testfile")

	testcases := []struct {
		// A command to invoke
		cmd     string
		cmdArgs string
		// Should stdio be redirected? nil means the test's stdio
		// will be passed through.
		stdin  *os.File
		stdout *os.File
		stderr *os.File
		// How long to run 'cmd' before checking results. If a timeout
		// is set and expectTerminated is false, the command must NOT have
		// exited before the timeout, so ensure it runs for long enough.
		timeout time.Duration
		// Is this command expected to exit before the timeout (or at all?)
		// If false, ensure that the command runtime is long enough for it
		// to still be running while the test checks run.
		expectTerminated bool
		// exit code expected if 'cmd' is expected to terminate. This
		// is the raw OS exit code. These tests don't currently define
		// a way to test for signal exits.
		expectExitStatus int
		expectSignalExit syscall.Signal
		// Is this command expected to create a file? If so, the path
		// to check for the file's existence.
		expectFileExists string
	}{
		{
			// Check that the command runs and exits, and
			// we can observe a side effect to prove it ran
			cmd:              "touch",
			cmdArgs:          touchTestFile,
			expectTerminated: true,
			expectExitStatus: 0,
			expectFileExists: touchTestFile,
		},
		{
			// check nonzero exit code handling
			cmd:              "false",
			expectTerminated: true,
			expectExitStatus: 1,
		},
		{
			// run a sleep and wait for it to finish, ensuring that
			// we actually wait for the exit of a process that takes
			// a moment to run.
			cmd:              "sleep",
			cmdArgs:          "0.1",
			expectTerminated: true,
		},
		{
			// run a sleep and inspect state before it finishes
			cmd:              "sleep",
			cmdArgs:          "1",
			expectTerminated: false,
			timeout:          400 * time.Millisecond,
		},
		{
			// signal exit handling - if a process exits with a signal
			// we handle it gracefully
			cmd:     "sh",
			cmdArgs: "-c \"kill -TERM $$\"",
			// Suppress the "signal: hangup" from the shell
			stdout:           nil,
			stderr:           nil,
			expectTerminated: true,
			expectSignalExit: syscall.SIGTERM,
		},
		{
			// show that argument splitting is confusing - it will not handle single-quoted
			// arguments how you might expect. This will fail with an unterminated string
			// error (exit code 2) because the argument gets split into the vector
			// ["-c", "'kill", "-TERM", "$$'"]. This shows that we
			// should really be using an argument vector to accept
			// commands, not a string.
			cmd:     "sh",
			cmdArgs: "-c 'kill -TERM $$'",
			// Suppress the "TERM: 1: Syntax error: Unterminated
			// quoted string" error message from the shell
			stdout:           nil,
			stderr:           nil,
			expectTerminated: true,
			expectExitStatus: 2,
		},
	}
	for _, tc := range testcases {
		tc := tc
		t.Run(tc.cmd, func(t *testing.T) {
			if runtime.GOOS == "windows" && tc.expectSignalExit != 0 {
				t.Skip("Signal handling is not supported on Windows")
			}

			// Set up the harness for this sidecar command run
			s := newSidecarTest(t)
			s.NewConfig(t)
			config := s.Config()
			config.Cmd = tc.cmd
			config.CmdArgs = tc.cmdArgs

			s.NewSidecar(t)
			// deliberately does not defer s.Close() since we might be abandoning
			// the sidecar when it is still running a command, and don't want panics
			// writing to unclosed channels.
			sidecar := s.Sidecar()

			if tc.stdin != nil {
				sidecar.stdin = tc.stdin
			}
			if tc.stdout != nil {
				sidecar.stdout = tc.stdout
			}
			if tc.stderr != nil {
				sidecar.stderr = tc.stderr
			}

			// There must be no testfile before the command runs when we're checking
			// for command side-effects (test-file creation)
			if tc.expectFileExists != "" {
				testfile := path.Join(config.CertDir, "testfile")
				_, err := os.Stat(testfile)
				require.True(t, os.IsNotExist(err))
			}

			t.Logf("invoking cert update for sidecar with cmd %s %s", tc.cmd, tc.cmdArgs)

			// Fake the workload api server issuing a new SVID. This will also
			// check that the cert was round-tripped, but it doesn't check that
			// the on-disk cert is correct. See TestSidecar_RunDaemon for that.
			// This doesn't need to respect the command timeout, since we're not
			// waiting for the command here.
			svid := newTestX509SVID(t, s.rootCA)
			s.MockUpdateX509Certificate(ctx, t, svid)

			// Wait for 'cmd' to run and terminate, the overall test timeout to expire
			// or the per-command timeout to expire.
			var commandDeadline <-chan time.Time
			if tc.timeout != 0 {
				commandDeadline = time.After(tc.timeout)
			}
			exited := false
			var processState os.ProcessState
			select {
			case <-commandDeadline:
				// timeout has expired, check that the state observed at
				// this moment matches what we're expecting. This isn't
				// usually an error, we're just checking that the command's
				// state is consistent with what we expect.
			case <-ctx.Done():
				// overall context has expired; this will fail the test.
				// The sidecar channels are not closed to prevent a race
				// where the sidecar might try to write to the channels
				// and panic before the test as a whole aborts.
				require.NoError(t, ctx.Err())
				return
			case processState = <-sidecar.cmdExitChan:
				exited = true
				t.Logf("Command exited with %s", processState.String())
			}

			// If we expect the process to exit, ensure it has
			require.Equal(t, tc.expectTerminated, exited)

			// We only check the exit status if the process is
			// supposed to exit; some tests will leave the process
			// running.
			if tc.expectTerminated {
				// Sidecar monitor must agree it has exited
				require.Equal(t, false, sidecar.processRunning)
				if tc.expectSignalExit > 0 {
					// Does this need to be in a separate
					// abstraction with a build guard for
					// windows, or is it sufficient that it
					// is unreachable on Windows?
					require.Equal(t, tc.expectSignalExit, processState.Sys().(syscall.WaitStatus).Signal())
				} else {
					require.True(t, processState.Exited())
					require.Equal(t, tc.expectExitStatus, processState.ExitCode())
				}
			} else {
				// The tests require that the process is still
				// running. Make sure you allow enough time for
				// the launched process to keep running before
				// the test ends.
				require.Equal(t, true, sidecar.processRunning)
			}

			// The test file must have been created if expected
			if tc.expectFileExists != "" {
				_, err := os.Stat(tc.expectFileExists)
				require.NoError(t, err)
			}

			// If a process was left running the sidecar will still
			// be waiting for it to exit. When it does, it will
			// write to the cmdExitChan. We don't really want to
			// wait for the process to finish so we'll orphan
			// channels in this case. We could start goroutines to
			// read from them then close them but why bother, the
			// whole test will be terminated soon and the GC will
			// take care of it once the Sidecar is done anyway.
			if exited {
				s.Close(t)
			}
		})
	}
}

// A short-lived process gets re-launched whenever the certs are rotated. The
// pid must change in each iteration.
//
// This test should probably also assert that the pid doesn't change between
// cert rotations, but that's a bit more complex to test.
func TestSidecar_TestCmdRunsRelaunchShortlived(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s := newSidecarTest(t)
	s.NewConfig(t)
	config := s.Config()
	if runtime.GOOS == "windows" {
		config.Cmd = "cmd"
		config.CmdArgs = "/c echo hello"
	} else {
		config.Cmd = "echo"
		config.CmdArgs = "hello"
	}

	s.NewSidecar(t)
	sidecar := s.Sidecar()
	defer s.Close(t)

	var pid int
	for range 3 {
		if sidecar.process != nil {
			pid = sidecar.process.Pid
		}

		svid := newTestX509SVID(t, s.rootCA)
		s.MockUpdateX509Certificate(ctx, t, svid)

		select {
		case <-ctx.Done():
			require.NoError(t, ctx.Err())
			return
		case <-sidecar.cmdExitChan:
		}

		require.Equal(t, false, sidecar.processRunning)
		require.NotEqual(t, pid, sidecar.process.Pid)
	}
}

// Assorted tests for sidecar certificate update logic.
//
// Creates a Sidecar with a Mocked WorkloadAPIClient and tests that
// running the Sidecar Daemon, when a SVID Response is sent to the
// UpdateChan on the WorkloadAPI client, the PEM files are stored on disk
//
// These tests don't focus on daemon mode and command execution.
func TestSidecar_RunDaemon(t *testing.T) {
	// Create root CA
	domain1CA := spiffetest.NewCA(t)
	// Create an intermediate certificate
	domain1Inter := domain1CA.CreateCA()
	domain1Bundle := domain1CA.Roots()

	// Used for testing federated trust domains
	domain2CA := spiffetest.NewCA(t)
	domain2Bundle := domain2CA.Roots()

	// SVID with intermediate
	spiffeIDWithIntermediate, err := spiffeid.FromString("spiffe://example.test/workloadWithIntermediate")
	require.NoError(t, err)
	svidChainWithIntermediate, svidKeyWithIntermediate := domain1Inter.CreateX509SVID(spiffeIDWithIntermediate.String())
	require.Len(t, svidChainWithIntermediate, 2)

	// Add cert with intermediate into a svid
	svidWithIntermediate := []*x509svid.SVID{
		{
			ID:           spiffeIDWithIntermediate,
			Certificates: svidChainWithIntermediate,
			PrivateKey:   svidKeyWithIntermediate,
		},
	}

	// Concat bundles with intermediate certificate
	bundleWithIntermediate := domain1CA.Roots()
	bundleWithIntermediate = append(bundleWithIntermediate, svidChainWithIntermediate[1:]...)

	// Create a single svid without intermediate
	spiffeID, err := spiffeid.FromString("spiffe://example.test/workload")
	require.NoError(t, err)
	svidChain, svidKey := domain1CA.CreateX509SVID(spiffeID.String())
	require.Len(t, svidChain, 1)
	svid := []*x509svid.SVID{
		{
			ID:           spiffeID,
			Certificates: svidChain,
			PrivateKey:   svidKey,
		},
	}

	bundleWithFederatedDomains := domain1CA.Roots()
	bundleWithFederatedDomains = append(bundleWithFederatedDomains, domain2Bundle[0:]...)
	// Used to create an additional bundle when testing federated trust domains
	federatedSpiffeID, err := spiffeid.FromString("spiffe://foo.test/server")
	require.NoError(t, err)

	tmpdir := t.TempDir()

	log, _ := test.NewNullLogger()

	config := &Config{
		Cmd:                "echo",
		CertDir:            tmpdir,
		SVIDFileName:       "svid.pem",
		SVIDKeyFileName:    "svid_key.pem",
		SVIDBundleFileName: "svid_bundle.pem",
		Log:                log,
		CertFileMode:       os.FileMode(0644),
		KeyFileMode:        os.FileMode(0600),
		JWTBundleFileMode:  os.FileMode(0600),
		JWTSVIDFileMode:    os.FileMode(0600),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	sidecar := Sidecar{
		config:        config,
		certReadyChan: make(chan *workloadapi.X509Context, 1),
		health: Health{
			FileWriteStatuses: FileWriteStatuses{
				X509WriteStatus: writeStatusUnwritten,
				JWTWriteStatus:  make(map[string]string),
			},
		},
	}
	defer close(sidecar.certReadyChan)

	testCases := []struct {
		name                 string
		response             *workloadapi.X509Context
		certs                []*x509.Certificate
		key                  crypto.Signer
		bundle               []*x509.Certificate
		renewSignal          string
		intermediateInBundle bool
		federatedDomains     bool
	}{
		{
			name: "svid with intermediate",
			response: &workloadapi.X509Context{
				Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(spiffeIDWithIntermediate.TrustDomain(), domain1Bundle)),
				SVIDs:   svidWithIntermediate,
			},
			certs:  svidChainWithIntermediate,
			key:    svidKeyWithIntermediate,
			bundle: domain1Bundle,
		},
		{
			name: "intermediate in bundle",
			response: &workloadapi.X509Context{
				Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(spiffeIDWithIntermediate.TrustDomain(), domain1Bundle)),
				SVIDs:   svidWithIntermediate,
			},
			// Only first certificate is expected
			certs: []*x509.Certificate{svidChainWithIntermediate[0]},
			key:   svidKeyWithIntermediate,
			// A concatenation between bundle and intermediate is expected
			bundle: bundleWithIntermediate,

			intermediateInBundle: true,
		},
		{
			name: "single svid with intermediate in bundle",
			response: &workloadapi.X509Context{
				Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(spiffeID.TrustDomain(), domain1CA.Roots())),
				SVIDs:   svid,
			},
			certs:                svidChain,
			key:                  svidKey,
			bundle:               domain1Bundle,
			intermediateInBundle: true,
		},
		{
			name: "single svid",
			response: &workloadapi.X509Context{
				Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(spiffeID.TrustDomain(), domain1CA.Roots())),
				SVIDs:   svid,
			},
			certs:  svidChain,
			key:    svidKey,
			bundle: domain1Bundle,
		},
		{
			name: "single svid with RenewSignal",
			response: &workloadapi.X509Context{
				Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(spiffeID.TrustDomain(), domain1CA.Roots())),
				SVIDs:   svid,
			},
			certs:       svidChain,
			key:         svidKey,
			bundle:      domain1Bundle,
			renewSignal: "SIGHUP",
		},
		{
			name: "svid with federated trust domains",
			response: &workloadapi.X509Context{
				Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(spiffeID.TrustDomain(), domain1CA.Roots()), x509bundle.FromX509Authorities(federatedSpiffeID.TrustDomain(), domain2CA.Roots())),
				SVIDs:   svid,
			},
			certs:            svidChain,
			key:              svidKey,
			bundle:           bundleWithFederatedDomains,
			federatedDomains: true,
		},
	}

	svidFile := path.Join(tmpdir, config.SVIDFileName)
	svidKeyFile := path.Join(tmpdir, config.SVIDKeyFileName)
	svidBundleFile := path.Join(tmpdir, config.SVIDBundleFileName)

	w := x509Watcher{&sidecar}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			sidecar.config.AddIntermediatesToBundle = testCase.intermediateInBundle
			sidecar.config.RenewSignal = testCase.renewSignal
			sidecar.config.IncludeFederatedDomains = testCase.federatedDomains
			// Push response to start updating process
			// updateMockChan <- testCase.response.ToProto(t)
			w.OnX509ContextUpdate(testCase.response)

			// Wait until response is processed
			select {
			case <-sidecar.CertReadyChan():
			// continue
			case <-ctx.Done():
				require.NoError(t, ctx.Err())
			}

			// Load certificates from disk and validate it is expected
			certs, err := util.LoadCertificates(svidFile)
			require.NoError(t, err)
			require.Equal(t, testCase.certs, certs)

			// Load key from disk and validate it is expected
			key, err := util.LoadPrivateKey(svidKeyFile)
			require.NoError(t, err)
			require.Equal(t, testCase.key, key)

			// Load bundle from disk and validate it is expected
			bundles, err := util.LoadCertificates(svidBundleFile)
			require.NoError(t, err)
			require.Equal(t, testCase.bundle, bundles)
		})
	}

	cancel()
}

func TestGetCmdArgs(t *testing.T) {
	cases := []struct {
		name         string
		in           string
		expectedArgs []string
		expectedErr  string
	}{
		{
			name:         "Empty input arguments",
			in:           "",
			expectedArgs: []string{},
		},
		{
			name:         "Arguments without double quoted spaces",
			in:           "-flag1 value1 -flag2 value2",
			expectedArgs: []string{"-flag1", "value1", "-flag2", "value2"},
		},
		{
			name:         "Arguments with double quoted spaces",
			in:           `-flag1 "value 1" -flag2 "value 2"`,
			expectedArgs: []string{"-flag1", "value 1", "-flag2", "value 2"},
		},
		{
			name:        "Missing quote",
			in:          `-flag1 "value 1`,
			expectedErr: `missing " in quoted-field`,
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			args, err := getCmdArgs(c.in)
			if c.expectedErr != "" {
				require.NotNil(t, err)
				require.Nil(t, args)
				require.Contains(t, err.Error(), c.expectedErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.expectedArgs, args)
		})
	}
}

// TestSignalProcess makes sure only one copy of the process is started. It uses a small script that creates a file
// where the name is the process ID of the script. If more then one file exists, then multiple processes were started
func TestSignalProcess(t *testing.T) {
	tempDir := t.TempDir()
	config := &Config{
		Cmd:         "./sidecar_test.sh",
		CmdArgs:     tempDir,
		RenewSignal: "SIGWINCH",
	}
	sidecar := New(config)
	require.NotNil(t, sidecar)

	// Run signalProcess() twice. The second should only signal the process with SIGWINCH which is basically a no op.
	err := sidecar.signalProcess()
	require.NoError(t, err)
	err = sidecar.signalProcess()
	require.NoError(t, err)

	// Give the script some time to run
	time.Sleep(1 * time.Second)

	files, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	require.Equal(t, 1, len(files))
}
