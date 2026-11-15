//go:build !linux

package main

import (
	"os"
	"os/exec"
)

// execOpenFile leaves cmd unchanged, so cmd executes the file at its
// path. Only Linux can execute an open file through a path.
//
// A process that can write to the directory of the binary can therefore
// replace the binary between the hash check and the start of cmd. Keep
// that directory out of reach of such a process, for example with the
// write rules of a sandbox.
func execOpenFile(_ *exec.Cmd, _ *os.File) {}

// execOpenFileError returns err, the error of a command that did not
// start, unchanged. [execOpenFile] leaves the command unchanged, so it
// adds no cause of its own to the start.
func execOpenFileError(_ *os.File, err error) error {
	return err
}
