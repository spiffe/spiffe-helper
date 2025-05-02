//go:build windows
// +build windows

package sidecar

import "syscall"

// Signal based tests should never run on Windows so we should not
// actually need this signal name remapping, but this way there
// will be a better error.
func SignalName(sig syscall.Signal) string {
	panic("signal handling is not supported on windows")
}

func SignalNum(sig string) syscall.Signal {
	panic("signal handling is not supported on windows")
}
