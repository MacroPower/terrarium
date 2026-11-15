package main

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

var (
	// ErrProcNotMounted means that the host does not mount /proc, so
	// the proxy cannot execute the managed Envoy binary. See
	// [execOpenFile].
	ErrProcNotMounted = errors.New("host does not mount /proc")

	// ErrLoaderNotFound means that the host holds no file at the path
	// of the dynamic loader that the managed Envoy binary names as its
	// interpreter. NixOS without nix-ld and without its stub loader is
	// such a host.
	ErrLoaderNotFound = errors.New("dynamic loader not found")
)

const (
	// The directory in which /proc names each open descriptor of the
	// process that reads it.
	procFDDir = "/proc/self/fd"

	// The length of the longest interpreter path that the kernel
	// accepts in an ELF file, which is PATH_MAX.
	maxInterpreterLen = 4096
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
//
// See [execOpenFileError] for the error of a cmd that does not start.
func execOpenFile(cmd *exec.Cmd, f *os.File) {
	execDescriptor(cmd, f, procFDDir)
}

// execDescriptor makes cmd execute the open file f through its entry in
// fdDir, the directory that names each open descriptor of a process.
// See [execOpenFile].
func execDescriptor(cmd *exec.Cmd, f *os.File, fdDir string) {
	cmd.ExtraFiles = append(cmd.ExtraFiles, f)

	// The child receives the entries of ExtraFiles after its standard
	// streams, so entry i has the descriptor number 3+i.
	cmd.Path = filepath.Join(fdDir, strconv.Itoa(2+len(cmd.ExtraFiles)))
}

// execOpenFileError adds the cause to err where it finds the cause.
// Err is the error of a command that [execOpenFile] changed to execute
// f and that did not start.
//
// The kernel reports two faults of the host as a missing file, and
// neither fault is a missing binary. The returned error wraps
// [ErrProcNotMounted] when the host does not mount /proc. It wraps
// [ErrLoaderNotFound] and names the loader when f is an ELF file whose
// interpreter the host does not hold. Every other err comes back
// unchanged.
func execOpenFileError(f *os.File, err error) error {
	return explainExecError(f, err, procFDDir)
}

// explainExecError is [execOpenFileError] for a command that
// [execDescriptor] changed to execute f through fdDir.
func explainExecError(f *os.File, err error, fdDir string) error {
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	_, statErr := os.Stat(fdDir)
	if errors.Is(statErr, fs.ErrNotExist) {
		return fmt.Errorf("%w: %w", ErrProcNotMounted, err)
	}

	loader := elfInterpreter(f)
	if loader == "" {
		return err
	}

	// Stat follows a symbolic link, as the kernel does, so a link
	// without a target also counts as a missing loader.
	_, statErr = os.Stat(loader)
	if errors.Is(statErr, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s: %w", ErrLoaderNotFound, loader, err)
	}

	return err
}

// elfInterpreter returns the path of the dynamic loader that the ELF
// file f names as its interpreter. It returns the empty string when f
// is not an ELF file, or when f does not name an interpreter. A
// statically linked program does not name one.
func elfInterpreter(f *os.File) string {
	// The ELF file reads f by offset and does not own a resource, so
	// the function does not close it.
	ef, err := elf.NewFile(f)
	if err != nil {
		return ""
	}

	for _, prog := range ef.Progs {
		if prog.Type != elf.PT_INTERP {
			continue
		}

		data, err := io.ReadAll(io.LimitReader(prog.Open(), maxInterpreterLen))
		if err != nil {
			return ""
		}

		// The segment holds the path and a NUL byte that ends it.
		path, _, _ := bytes.Cut(data, []byte{0})

		return string(path)
	}

	return ""
}
