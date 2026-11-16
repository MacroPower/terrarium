//go:build !linux && !darwin

package main

import (
	"errors"
	"syscall"
)

// processEnded reports whether the process pid has exited and its
// parent has reaped it. A process that has exited still answers signal
// 0 until its parent reaps it. Outside Linux and macOS, the tests do
// not read the state of that process. For a child of the test process
// that the test has not yet waited for, processEnded therefore reports
// false after the child exits. TestEnvoyGuardIgnoredSignals then
// detects a guard that a signal ended only through the wait status
// that it checks after it closes the pipe.
func processEnded(pid int) bool {
	return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}
