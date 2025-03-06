//go:build !windows
// +build !windows

package sidecar

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// Used by tests to map syscall.Signal constants to the signal names
// used in the Sidecar struct
func SignalName(sig syscall.Signal) string {
	return unix.SignalName(sig)
}

func SignalNum(sig string) syscall.Signal {
	return unix.SignalNum(sig)
}
