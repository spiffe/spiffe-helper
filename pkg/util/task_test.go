package util

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	ctx = context.Background()

	errPanic = errors.New("panic")
)

func TestRunTasksWithNoTasks(t *testing.T) {
	if err := RunTasks(ctx); err != nil {
		t.Fatalf("expected no error; got %v", err)
	}
}

func TestRunTaskReturnsWhenAllTasksAreComplete(t *testing.T) {
	in1, out1, t1 := newFakeTask()
	in2, out2, t2 := newFakeTask()

	wait := testRunTasks(ctx, t1, t2)

	// complete both tasks with no errors
	in1 <- nil
	in2 <- nil

	// assert RunTasks() returns no error and that both tasks completed with
	// no error
	assertErrorChan(t, wait, nil)
	assertErrorChan(t, out1, nil)
	assertErrorChan(t, out2, nil)
}

func TestRunTaskReturnsFirstFailure(t *testing.T) {
	_, out1, t1 := newFakeTask()
	in2, out2, t2 := newFakeTask()

	wait := testRunTasks(ctx, t1, t2)

	// complete task2 with an error
	expected := errors.New("WHOOPSIE")
	in2 <- expected

	// assert RunTasks() returns the error, that task1 was canceled, and that
	// task2 returned the error.
	assertErrorChan(t, wait, expected)
	assertErrorChan(t, out1, context.Canceled)
	assertErrorChan(t, out2, expected)
}

func TestRunTaskHandlesPanic(t *testing.T) {
	_, out1, t1 := newFakeTask()
	in2, out2, t2 := newFakeTask()

	wait := testRunTasks(ctx, t1, t2)

	// send down a special error to trigger a panic in task2
	in2 <- errPanic

	// assert RunTasks() returns the panic error, that task1 was canceled, and
	// that task2 returned the panic error.
	assertErrorChanContains(t, wait, errPanic.Error())
	assertErrorChan(t, out1, context.Canceled)
	assertErrorChanContains(t, out2, errPanic.Error())
}

func TestRunTaskCancelsTasksIfContextCanceled(t *testing.T) {
	_, out1, t1 := newFakeTask()
	_, out2, t2 := newFakeTask()

	ctx, cancel := context.WithCancel(ctx)
	wait := testRunTasks(ctx, t1, t2)

	// cancel the parent context
	cancel()

	// assert that RunTasks() and both tasks were canceled
	assertErrorChan(t, wait, context.Canceled)
	assertErrorChan(t, out1, context.Canceled)
	assertErrorChan(t, out2, context.Canceled)
}

func TestRunTasksWithAlreadyCanceledContext(t *testing.T) {
	_, _, t1 := newFakeTask()

	ctx, cancel := context.WithCancel(ctx)
	cancel()

	if err := RunTasks(ctx, t1); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled; got %v", err)
	}
}

func TestRunTasksConcurrency(t *testing.T) {
	in1, _, t1 := newFakeTask()
	in2, _, t2 := newFakeTask()

	wait := testRunTasks(ctx, t1, t2)

	// complete task 2 first. if tasks were serial, this would block
	// since task 1 is still waiting.
	in2 <- nil
	in1 <- nil

	assertErrorChan(t, wait, nil)
}

func TestRunTasksWait(t *testing.T) {
	in1, out1, t1 := newFakeTask()
	_, out2, t2 := newFakeTask()

	wait := testRunTasks(ctx, t1, t2)

	// fail task 1
	expected := errors.New("fail")
	in1 <- expected

	// RunTasks should return the error immediately
	assertErrorChan(t, wait, expected)

	// verify that task 1 actually completed
	assertErrorChan(t, out1, expected)

	// task 2 should have been canceled by now
	assertErrorChan(t, out2, context.Canceled)

	// Since we're using newFakeTask, in2 is still there.
	// The task function returns context.Canceled because ctx.Done() was selected.
}

func TestSerialRun(t *testing.T) {
	t.Run("no tasks", func(t *testing.T) {
		if err := SerialRun()(ctx); err != nil {
			t.Fatalf("expected no error; got %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		in1, out1, t1 := newFakeTask()
		in2, out2, t2 := newFakeTask()

		errch := make(chan error, 1)
		go func() {
			errch <- SerialRun(t1, t2)(ctx)
		}()

		in1 <- nil
		assertErrorChan(t, out1, nil)
		in2 <- nil
		assertErrorChan(t, out2, nil)
		assertErrorChan(t, errch, nil)
	})

	t.Run("failure", func(t *testing.T) {
		in1, out1, t1 := newFakeTask()
		_, out2, t2 := newFakeTask()

		errch := make(chan error, 1)
		go func() {
			errch <- SerialRun(t1, t2)(ctx)
		}()

		expected := errors.New("fail")
		in1 <- expected
		assertErrorChan(t, out1, expected)
		assertErrorChan(t, errch, expected)

		// t2 should not have been called
		select {
		case err := <-out2:
			t.Fatalf("task 2 should not have been called; got %v", err)
		default:
		}
	})

	t.Run("panic", func(t *testing.T) {
		in1, out1, t1 := newFakeTask()
		_, out2, t2 := newFakeTask()

		errch := make(chan error, 1)
		go func() {
			errch <- SerialRun(t1, t2)(ctx)
		}()

		in1 <- errPanic
		assertErrorChanContains(t, out1, errPanic.Error())
		assertErrorChanContains(t, errch, errPanic.Error())

		// t2 should not have been called
		select {
		case err := <-out2:
			t.Fatalf("task 2 should not have been called; got %v", err)
		default:
		}
	})

	t.Run("context canceled", func(t *testing.T) {
		_, out1, t1 := newFakeTask()

		ctx, cancel := context.WithCancel(ctx)
		errch := make(chan error, 1)
		go func() {
			errch <- SerialRun(t1)(ctx)
		}()

		cancel()
		assertErrorChan(t, out1, context.Canceled)
		assertErrorChan(t, errch, context.Canceled)
	})
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

func assertErrorChan(t *testing.T, ch chan error, expected error) {
	t.Helper()

	timer := time.NewTimer(time.Second)
	select {
	case <-timer.C:
		t.Fatalf("timed out waiting for result")
	case actual := <-ch:
		if !errors.Is(actual, expected) {
			t.Fatalf("expected %v; got %v", expected, actual)
		}
	}
}

func assertErrorChanContains(t *testing.T, ch chan error, contains string) {
	t.Helper()

	timer := time.NewTimer(time.Second)
	select {
	case <-timer.C:
		t.Fatalf("timed out waiting for result")
	case actual := <-ch:
		if !strings.Contains(actual.Error(), contains) {
			t.Fatalf("expected error contains %s; got %v", contains, actual)
		}
	}
}
