package dockercompose

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	commandTimeout = 5 * time.Minute
	cleanupTimeout = 2 * time.Minute
	projectDir     = "."
)

var projectSequence atomic.Uint64

// Project manages docker compose files for an integration test run.
type Project struct {
	projectName string
	files       []string
	env         []string
}

// Result contains the output and error from a docker compose command.
type Result struct {
	Stdout string
	Stderr string
	Err    error
}

// New creates a docker compose project for an integration test run.
func New() *Project {
	return &Project{
		projectName: "spiffe-helper-it-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatUint(projectSequence.Add(1), 10),
		env:         os.Environ(),
	}
}

// AddFile adds a docker compose file along with its environment to be managed together.
func (c *Project) AddFile(tb testing.TB, file string, environment map[string]string) {
	tb.Helper()

	require.NotEmpty(tb, file, "Compose file is required")
	c.files = append(c.files, file)
	for key, value := range environment {
		require.NotEmpty(tb, key, "environment variable key is required")
		c.env = append(c.env, key+"="+value)
	}
}

// Up is the equivalent of "docker compose up".
func (c *Project) Up(tb testing.TB, services ...string) {
	tb.Helper()

	upArgs := []string{"up", "--build", "-d"}
	args := make([]string, 0, len(upArgs)+len(services))
	args = append(args, upArgs...)
	args = append(args, services...)
	c.mustRun(tb, args...)
}

// Exec runs a command in a docker compose service and fails the test on error.
func (c *Project) Exec(tb testing.TB, service string, command ...string) string {
	tb.Helper()

	return c.mustRun(tb, execArgs(service, command)...)
}

// TryExec runs a command in a docker compose service and returns the result.
func (c *Project) TryExec(service string, command ...string) Result {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	stdout, stderr, err := c.run(ctx, execArgs(service, command)...)
	return Result{
		Stdout: stdout,
		Stderr: stderr,
		Err:    err,
	}
}

// WaitForExec waits for a command in a docker compose service to succeed.
func (c *Project) WaitForExec(tb testing.TB, service string, timeout time.Duration, command ...string) {
	tb.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := execArgs(service, command)

	var lastError error
	var lastStderr string
	for ctx.Err() == nil {
		attemptCtx, attemptCancel := context.WithTimeout(ctx, 5*time.Second)
		_, lastStderr, lastError = c.run(attemptCtx, args...)
		attemptCancel()
		if lastError == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}

	require.FailNow(tb, "timed out waiting for "+service, "%v\n%s", lastError, lastStderr)
}

// Cleanup tears down the docker compose project for a test.
func (c *Project) Cleanup(tb testing.TB) {
	tb.Helper()
	c.close(tb.Failed(), tb.Logf)
}

// Close tears down the docker compose project outside of a test helper.
func (c *Project) Close(failed bool, logf func(string, ...any)) {
	c.close(failed, logf)
}

func (c *Project) close(failed bool, logf func(string, ...any)) {
	if logf == nil {
		logf = func(string, ...any) {}
	}

	if failed {
		c.logDiagnostics(logf)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()

	_, stderr, err := c.run(ctx, "down", "--volumes", "--remove-orphans")
	if err != nil {
		logf("docker compose cleanup failed: %v\n%s", err, stderr)
	}
}

func (c *Project) mustRun(tb testing.TB, args ...string) string {
	tb.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	stdout, stderr, err := c.run(ctx, args...)
	require.NoError(tb, err, "docker compose %s failed:\n%s", strings.Join(args, " "), stderr)
	return stdout
}

func execArgs(service string, command []string) []string {
	execPrefix := []string{"exec", "-T", service}
	args := make([]string, 0, len(execPrefix)+len(command))
	args = append(args, execPrefix...)
	args = append(args, command...)
	return args
}

func (c *Project) run(ctx context.Context, args ...string) (string, string, error) {
	projectArgs := []string{"compose", "--project-name", c.projectName}
	fileArgsCount := 2 * len(c.files)
	fullArgs := make([]string, 0, len(projectArgs)+fileArgsCount+len(args))
	fullArgs = append(fullArgs, projectArgs...)
	for _, file := range c.files {
		fullArgs = append(fullArgs, "--file", file)
	}
	fullArgs = append(fullArgs, args...)

	command := exec.CommandContext(ctx, "docker", fullArgs...)
	command.Dir = projectDir
	command.Env = c.env

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	err := command.Run()
	if ctx.Err() != nil {
		err = fmt.Errorf("%w: %w", err, ctx.Err())
	}
	return stdout.String(), stderr.String(), err
}

func (c *Project) logDiagnostics(logf func(string, ...any)) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()

	if stdout, stderr, err := c.run(ctx, "ps", "--all"); err == nil {
		logf("docker compose ps:\n%s", stdout)
	} else {
		logf("docker compose ps failed: %v\n%s", err, stderr)
	}

	if stdout, stderr, err := c.run(ctx, "logs", "--no-color", "--tail", "200"); err == nil {
		logf("docker compose logs:\n%s", stdout)
	} else {
		logf("docker compose logs failed: %v\n%s", err, stderr)
	}
}
