package main

import (
	"bytes"
	"errors"
	"os"
	"strconv"
	"syscall"
)

// processEnded reports whether the process pid has exited. A process
// that has exited but that its parent has not reaped still answers
// signal 0, so processEnded also reports true for that process.
func processEnded(pid int) bool {
	err := syscall.Kill(pid, 0)
	if errors.Is(err, syscall.ESRCH) {
		return true
	}

	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if errors.Is(err, os.ErrNotExist) {
		return true
	}

	// The state follows the command name, which ends at the last
	// closing parenthesis.
	i := bytes.LastIndexByte(data, ')')
	if err != nil || i < 0 || len(data) <= i+2 {
		return false
	}

	return data[i+2] == 'Z'
}
