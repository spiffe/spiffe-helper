package util

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	errPanic = errors.New("panic")
)

func TestRunTasksWithNoTasks(t *testing.T) {
	require.NoError(t, RunTasks(context.Background()))
}

func TestRunTaskReturnsWhenAllTasksAreComplete(t *testing.T) {
	in1, out1, t1 := newFakeTask()
	in2, out2, t2 := newFakeTask()

	wait := testRunTasks(context.Background(), t1, t2)

	// complete both tasks with no errors
	in1 <- nil
	in2 <- nil

	// assert RunTasks() returns no error and that both tasks completed with
	// no error
	require.NoError(t, receiveError(t, wait))
	require.NoError(t, receiveError(t, out1))
	require.NoError(t, receiveError(t, out2))
}

func TestRunTaskReturnsFirstFailure(t *testing.T) {
	_, out1, t1 := newFakeTask()
	in2, out2, t2 := newFakeTask()

	wait := testRunTasks(context.Background(), t1, t2)

	// complete task2 with an error
	expected := errors.New("WHOOPSIE")
	in2 <- expected

	// assert RunTasks() returns the error, that task1 was canceled, and that
	// task2 returned the error.
	require.ErrorIs(t, receiveError(t, wait), expected)
	require.ErrorIs(t, receiveError(t, out1), context.Canceled)
	require.ErrorIs(t, receiveError(t, out2), expected)
}

func TestRunTaskHandlesPanic(t *testing.T) {
	_, out1, t1 := newFakeTask()
	in2, out2, t2 := newFakeTask()

	wait := testRunTasks(context.Background(), t1, t2)

	// send down a special error to trigger a panic in task2
	in2 <- errPanic

	// assert RunTasks() returns the panic error, that task1 was canceled, and
	// that task2 returned the panic error.
	require.ErrorContains(t, receiveError(t, wait), errPanic.Error())
	require.ErrorIs(t, receiveError(t, out1), context.Canceled)
	require.ErrorContains(t, receiveError(t, out2), errPanic.Error())
}

func TestRunTaskCancelsTasksIfContextCanceled(t *testing.T) {
	_, out1, t1 := newFakeTask()
	_, out2, t2 := newFakeTask()

	ctx, cancel := context.WithCancel(context.Background())
	wait := testRunTasks(ctx, t1, t2)

	// cancel the parent context
	cancel()

	// assert that RunTasks() and both tasks were canceled
	require.ErrorIs(t, receiveError(t, wait), context.Canceled)
	require.ErrorIs(t, receiveError(t, out1), context.Canceled)
	require.ErrorIs(t, receiveError(t, out2), context.Canceled)
}

func TestRunTasksWithAlreadyCanceledContext(t *testing.T) {
	_, _, t1 := newFakeTask()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.ErrorIs(t, RunTasks(ctx, t1), context.Canceled)
}

func TestRunTasksConcurrency(t *testing.T) {
	in1, _, t1 := newFakeTask()
	in2, _, t2 := newFakeTask()

	wait := testRunTasks(context.Background(), t1, t2)

	// complete task 2 first. if tasks were serial, this would block
	// since task 1 is still waiting.
	in2 <- nil
	in1 <- nil

	require.NoError(t, receiveError(t, wait))
}

func TestRunTasksWait(t *testing.T) {
	in1, out1, t1 := newFakeTask()
	_, out2, t2 := newFakeTask()

	wait := testRunTasks(context.Background(), t1, t2)

	// fail task 1
	expected := errors.New("fail")
	in1 <- expected

	// RunTasks should return the error immediately
	require.ErrorIs(t, receiveError(t, wait), expected)

	// verify that task 1 actually completed
	require.ErrorIs(t, receiveError(t, out1), expected)

	// task 2 should have been canceled by now
	require.ErrorIs(t, receiveError(t, out2), context.Canceled)

	// Since we're using newFakeTask, in2 is still there.
	// The task function returns context.Canceled because ctx.Done() was selected.
}

func newFakeTask() (chan error, chan error, func(context.Context) error) {
	in := make(chan error)
	out := make(chan error, 1)
	return in, out, func(ctx context.Context) (err error) {
		defer func() {
			out <- err
		}()
		select {
		case err = <-in:
			if errors.Is(err, errPanic) {
				panic(err)
			}
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func testRunTasks(ctx context.Context, tasks ...func(context.Context) error) chan error {
	ch := make(chan error)
	go func() {
		ch <- RunTasks(ctx, tasks...)
	}()
	return ch
}

func receiveError(t *testing.T, ch chan error) error {
	t.Helper()

	timer := time.NewTimer(time.Second)
	defer timer.Stop()

	select {
	case <-timer.C:
		require.FailNow(t, "timed out waiting for result")
		return nil
	case actual := <-ch:
		return actual
	}
}
