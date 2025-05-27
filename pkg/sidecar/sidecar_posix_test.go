//go:build !windows
// +build !windows

package sidecar

/*
 * Tests for the sidecar that exercise signal handling and pid file signalling.
 * These tests are not run on Windows because they rely on signal handling.
 */

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	SignalHelperArg = "signal"
	defaultTimeout  = 10 * time.Second
)

// We need a command we can run from the sidecar that will report on signals delivered.
// Rather than rely on a shell script, we'll use a simple golang program that will
// report to stdout when it receives a signal. We reuse the test executable for this
// if given the 'signal' argument.
//
// This will compile on Windows but panic at runtime.
func SignalListenerHelperMain(_ *testing.M) int {
	if len(os.Args) < 3 || len(os.Args) > 4 {
		fmt.Fprintf(os.Stderr, "signal helper: Usage: %s "+SignalHelperArg+" <signal> [<forward_to_pid>]\n", os.Args[0])
		return 1
	}
	signame := os.Args[2]
	wantsig := SignalNum(signame)
	if wantsig == 0 {
		fmt.Fprintf(os.Stderr, "signal helper: Unknown signal %s\n", signame)
		return 1
	}

	// Should the test helper forward signals to the test process where
	// it can trap them?
	var forwardToPid int
	var forwardToProc *os.Process
	if len(os.Args) >= 4 {
		var err error
		// Prepare to forward the signal to the specified pid
		forwardToPid, err = strconv.Atoi(os.Args[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "signal helper: Invalid pid %s\n", os.Args[3])
			return 1
		}
		forwardToProc, err = os.FindProcess(forwardToPid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "signal helper: Failed to find process %d: %v\n", forwardToPid, err)
			return 1
		}
	}

	// Ensure the helper doesn't run forever if orphaned
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// listen for the signal requested
	c := make(chan os.Signal, 1)
	signal.Notify(c, wantsig)
	// and wait for signal delivery, reporting each one on stdout
	fmt.Fprintf(os.Stderr,
		"signal helper: pid %d for %s (%v) listening\n",
		os.Getpid(), signame, wantsig)
	for {
		select {
		case gotsig := <-c:
			received := time.Now()
			fmt.Fprintf(os.Stdout, "%d\t%s\n", received.UnixNano(), SignalName(gotsig.(syscall.Signal)))
			// Signal received, report it and forward it to the specified pid
			if forwardToProc != nil {
				if err := forwardToProc.Signal(gotsig); err != nil {
					fmt.Fprintf(os.Stderr, "signal helper: Failed to forward signal %s to %d: %v\n", gotsig, forwardToPid, err)
				} else {
					fmt.Fprintf(os.Stderr, "signal helper: forwarded %s to %d\n", gotsig, forwardToPid)
				}
			}
		case <-ctx.Done():
			// Test harness should send a SIGTERM to this process when it has finished with it, so
			// this suggests a process leak bug.
			os.Stderr.WriteString("signal helper: BUG: signal listener helper timed out without being explicitly terminated\n")
			return 0
		}
	}
}

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == SignalHelperArg {
		// We're the signal handler test program
		os.Exit(SignalListenerHelperMain(m))
	}
	os.Exit(m.Run())
}

// Validate pid_file_name signalling behaviour, simulating daemon-mode execution with
// workload api server responses. A signal is sent to the test case process itself.
func TestSidecar_TestPidFilenameSignalling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	tmpdir := t.TempDir()

	testcases := []struct {
		name           string
		signal         syscall.Signal
		missingPidfile bool
	}{
		{
			// pid_file_name signalling - we expect the sidecar to send
			// a signal to the pid pointed to in the pid file.
			name:   "pid_file_name signalling",
			signal: syscall.SIGUSR1,
		},
		{
			// Repeat the test with the pid file missing the first time around
			name:           "pid_file_name signalling",
			signal:         syscall.SIGUSR1,
			missingPidfile: true,
		},
	}
	for tcIndex, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// install a signal handler and record when we receive the signal
			sigListener := make(chan os.Signal, 1)
			signal.Notify(sigListener, tc.signal)
			defer signal.Stop(sigListener)

			// prepare a pid file for this test process.
			pid := os.Getpid()
			pidfile := path.Join(tmpdir, fmt.Sprintf("pidfile.%d.%d", tcIndex, pid))
			writePidFile := func() {
				// Write the pid file with the current process pid
				pidFileContent := []byte(fmt.Sprintf("%d\n", pid))
				err := os.WriteFile(pidfile, pidFileContent, 0600)
				require.NoError(t, err)
			}
			if !tc.missingPidfile {
				writePidFile()
			}

			// Set up the harness for this sidecar with the pid file
			// Deliberately does not defer s.Close() since we might be abandoning
			// the sidecar when it is still running a command
			s := newSidecarTest(t)

			config := s.sidecar.config
			config.PIDFilename = pidfile
			config.RenewSignal = SignalName(tc.signal)

			// Fake the workload api server issuing a new SVID. This will also
			// check that the cert was round-tripped, but it doesn't check that
			// the on-disk cert is correct. See TestSidecar_RunDaemon for that.
			// This doesn't need to respect the command timeout, since we're not
			// waiting for the command here.
			svid := newTestX509SVID(t, s.rootCA)
			s.MockUpdateX509Certificate(ctx, t, svid)

			// Wait for notification that the pid_file_name was signalled
			var pidFileResult pidFileSignalledResult
			select {
			case pidFileResult = <-s.pidFileSignalledChan:
				break
			case <-ctx.Done():
				// overall context has expired; this will fail the test.
				require.NoError(t, ctx.Err())
				return
			}

			if tc.missingPidfile {
				// The pid file was missing so signalling will fail.
				require.Equal(t, 0, pidFileResult.pid)
				require.ErrorContains(t, pidFileResult.err, "failed to read pid file")

				// Creating the pid file won't help now, so we're done
				// until the next renew.
				writePidFile()
				select {
				case <-time.After(200 * time.Millisecond):
					// A signal retry would've arried by now if there was going to be one,
					// but signals aren't retried.
					break
				case <-s.pidFileSignalledChan:
					require.Fail(t, "should not have signalled, since we don't retry signals")
				case <-ctx.Done():
					// overall context has expired; this will fail the test.
					require.NoError(t, ctx.Err())
					return
				}

				// A cert renewal will trigger another attempt to signal, which should succeed
				s.MockUpdateX509Certificate(ctx, t, svid)
				select {
				case pidFileResult = <-s.pidFileSignalledChan:
					require.NoError(t, pidFileResult.err)
				case <-ctx.Done():
					require.NoError(t, ctx.Err())
					return
				}
			}

			// Since a valid pid file was supplied, signalling must succeed
			// on the first attempt
			require.Equal(t, pid, pidFileResult.pid)
			require.NoError(t, pidFileResult.err)

			// Did we actually receive the signal?
			select {
			case sig := <-sigListener:
				require.Equal(t, tc.signal, sig)
			case <-ctx.Done():
				// overall context has expired; this will fail the test.
				require.NoError(t, ctx.Err())
				return
			}
		})
	}
}

// A long-running command should not be re-launched when the certs are rotated,
// and must be signalled to reload the certs.
//
// This test could be amended to remove the signal handling part on Windows and
// exercise a long running process by checking pids and chatting with it over
// stdio but that's a task for another day.
func TestSidecar_TestCmdRunsLongRunning(t *testing.T) {
	const testsig = syscall.SIGUSR1

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	s := newSidecarTest(t)
	defer s.Close(t)

	// Run a helper command that sleeps until signalled with SIGUSR1 then forwards
	// the signal to the specified pid (this test process). It runs as an alternate
	// mode of this test executable; see TestMain
	config := s.sidecar.config
	config.Cmd = os.Args[0]
	config.CmdArgs = fmt.Sprintf("%s %s %d", SignalHelperArg, SignalName(testsig), os.Getpid())
	config.RenewSignal = SignalName(testsig)

	// Listen for the signal we're going to send to the test helper, so we know when
	// it gets forwarded to us
	sigListener := make(chan os.Signal, 1)
	signal.Notify(sigListener, testsig)
	defer signal.Stop(sigListener)

	// Fake the cert issue, which will start the process
	svid := newTestX509SVID(t, s.rootCA)
	s.MockUpdateX509Certificate(ctx, t, svid)

	// It takes a moment for the test process to start up. We don't currently
	// send a channel event for this, so we'll just busy-wait for the process
	for {
		s.sidecar.mu.Lock()
		running := s.sidecar.processRunning
		s.sidecar.mu.Unlock()
		if running {
			break
		}
		if ctx.Err() != nil {
			require.NoError(t, ctx.Err())
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.True(t, s.sidecar.processRunning)
	firstPid := s.sidecar.process.Pid

	// There should be no signal sent to the test helper on the first iteration
	select {
	case <-time.After(100 * time.Millisecond):
		// We didn't get a signal within a reasonable period. None was expected,
		// so this indicates success, and we can proceed.
	case <-s.cmdExitChan:
		require.Fail(t, "command should not have exited")
	case forwardedSignal := <-sigListener:
		// No signal should be delivered on the first iteration, since the
		// helper was just launched.
		require.Fail(t, "Test failed", "unexpected signal %s", SignalName(forwardedSignal.(syscall.Signal)))
	case <-ctx.Done():
		require.NoError(t, ctx.Err())
	}

	// Now we'll rotate the certs a few times and check that the process is still
	// running and that we receive the signal we sent to the test helper when it
	// forwards it.
	for range 3 {
		// Fake the cert renewal
		svid := newTestX509SVID(t, s.rootCA)
		s.MockUpdateX509Certificate(ctx, t, svid)

		// Command is still running
		require.True(t, s.sidecar.processRunning)

		// On the second or later iteration, we should have received a signal
		// from the test helper. No signal is delivered on the first iteration
		// since the process is launched.
		// Wait for the signal to be forwarded to the test helper
		select {
		case forwardedSignal := <-sigListener:
			// We should receive the signal we sent to the test helper
			require.Equal(t, testsig, forwardedSignal)
		case <-s.cmdExitChan:
			// we should never get an exit status report, since the
			// proc should still be running
			require.Fail(t, "command should not have exited")
		case <-time.After(1 * time.Second):
			// We should have received a signal by now
			require.Fail(t, "timed out waiting for signal")
		case <-ctx.Done():
			require.NoError(t, ctx.Err())
		}

		// Command started and is still running
		require.True(t, s.sidecar.processRunning)

		if firstPid == -1 {
			firstPid = s.sidecar.process.Pid
		} else {
			// Pid does not change between iterations
			require.Equal(t, firstPid, s.sidecar.process.Pid)
		}

		// Ensure there's enough time between cert updates to be sure we don't
		// overlap file touching with the next update.
		time.Sleep(500 * time.Millisecond)
	}

	// Terminate the signal helper so the goroutine monitoring it doesn't wait
	// for it to time out. There's no need to wait here, the test is done.
	require.NoError(t, s.sidecar.process.Signal(syscall.SIGTERM))
}
