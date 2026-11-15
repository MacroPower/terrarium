package main

import (
	"os"
	"os/exec"
	"strconv"
)

// execOpenFile makes cmd execute the open file f in place of the file
// at the path of cmd. The first argument of cmd keeps the path.
//
// The caller checked the content of f. A process that puts another file
// at the path after that check therefore does not change the program
// that cmd runs. A process that can write to the checked file itself
// can still change it before cmd starts.
//
// The child process receives f as a descriptor and executes the
// /proc/self/fd entry of that descriptor, so the host must mount /proc.
// The kernel takes the name of the process from the last element of the
// executed path. The name of the process is therefore the descriptor
// number, and only its command line holds the path of the binary. The
// process keeps the descriptor open.
func execOpenFile(cmd *exec.Cmd, f *os.File) {
	cmd.ExtraFiles = append(cmd.ExtraFiles, f)

	// The child receives the entries of ExtraFiles after its standard
	// streams, so entry i has the descriptor number 3+i.
	cmd.Path = "/proc/self/fd/" + strconv.Itoa(2+len(cmd.ExtraFiles))
}
