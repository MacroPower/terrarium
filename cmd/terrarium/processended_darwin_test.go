package main

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

// processStateZombie is the state SZOMB of the XNU kernel, which the
// kernel gives a process that has exited but that its parent has not
// reaped.
const processStateZombie = 5

// processEnded reports whether the process pid has exited. A process
// that has exited but that its parent has not reaped still answers
// signal 0, so processEnded also reports true for that process.
func processEnded(pid int) bool {
	err := syscall.Kill(pid, 0)
	if errors.Is(err, syscall.ESRCH) {
		return true
	}

	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		// The kernel returns no process when the parent reaped it
		// after the signal 0.
		return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
	}

	return info.Proc.P_stat == processStateZombie
}
