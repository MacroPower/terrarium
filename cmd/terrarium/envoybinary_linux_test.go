package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// elfWithInterpreter returns an ELF program for the host that names
// interp as its dynamic loader. The program holds no code, so it runs
// only as far as the kernel's search for interp.
func elfWithInterpreter(t *testing.T, interp string) []byte {
	t.Helper()

	machines := map[string]elf.Machine{
		"amd64": elf.EM_X86_64,
		"arm64": elf.EM_AARCH64,
	}

	machine, ok := machines[runtime.GOARCH]
	if !ok {
		t.Skipf("no ELF machine for %s", runtime.GOARCH)
	}

	header := elf.Header64{
		Ident: [elf.EI_NIDENT]byte{
			0x7f, 'E', 'L', 'F',
			byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT),
		},
		Type:    uint16(elf.ET_EXEC),
		Machine: uint16(machine),
		Version: uint32(elf.EV_CURRENT),
		Phnum:   1,
	}
	header.Ehsize = uint16(binary.Size(header))
	header.Phoff = uint64(header.Ehsize)

	// The path ends with a NUL byte.
	name := append([]byte(interp), 0)

	prog := elf.Prog64{
		Type:   uint32(elf.PT_INTERP),
		Flags:  uint32(elf.PF_R),
		Filesz: uint64(len(name)),
		Memsz:  uint64(len(name)),
		Align:  1,
	}
	header.Phentsize = uint16(binary.Size(prog))
	prog.Off = header.Phoff + uint64(header.Phentsize)

	var buf bytes.Buffer

	require.NoError(t, binary.Write(&buf, binary.LittleEndian, header))
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, prog))
	buf.Write(name)

	return buf.Bytes()
}

// TestExplainExecError starts a command that executes an open file
// through a descriptor directory. It checks the cause that
// [explainExecError] adds to the error of that start.
func TestExplainExecError(t *testing.T) {
	t.Parallel()

	missingLoader := filepath.Join(t.TempDir(), "ld-missing.so.1")
	missingShell := filepath.Join(t.TempDir(), "sh")

	tests := map[string]struct {
		// program is the content of the executed file.
		program func(t *testing.T) []byte
		// fdDir is the descriptor directory of the command. An empty
		// value selects the one that /proc holds.
		fdDir string
		// startErr is the error of the start.
		startErr error
		// err is the cause that the explained error wraps. It is nil
		// for a start error that comes back unchanged.
		err error
		// msg is text that the explained error holds.
		msg string
	}{
		"descriptor directory is missing": {
			program:  func(*testing.T) []byte { return []byte("#!/bin/sh\n") },
			fdDir:    filepath.Join(t.TempDir(), "proc", "self", "fd"),
			startErr: fs.ErrNotExist,
			err:      ErrProcNotMounted,
		},
		"loader of an ELF file is missing": {
			program: func(t *testing.T) []byte {
				t.Helper()

				return elfWithInterpreter(t, missingLoader)
			},
			startErr: fs.ErrNotExist,
			err:      ErrLoaderNotFound,
			msg:      ": " + missingLoader + ": ",
		},
		// Only an ELF file names a loader.
		"interpreter of a script is missing": {
			program:  func(*testing.T) []byte { return []byte("#!" + missingShell + "\n") },
			startErr: fs.ErrNotExist,
		},
		"file is not a program": {
			program:  func(*testing.T) []byte { return []byte("not a program") },
			startErr: syscall.ENOEXEC,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "envoy")
			require.NoError(t, os.WriteFile(path, tt.program(t), 0o755))

			f, err := os.Open(path) //nolint:gosec // test fixture path.
			require.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, f.Close())
			})

			fdDir := tt.fdDir
			if fdDir == "" {
				fdDir = procFDDir
			}

			cmd := exec.CommandContext(t.Context(), path)
			execDescriptor(cmd, f, fdDir)

			startErr := cmd.Start()
			require.ErrorIs(t, startErr, tt.startErr)

			got := explainExecError(f, startErr, fdDir)

			if tt.err == nil {
				assert.Equal(t, startErr, got)

				return
			}

			require.ErrorIs(t, got, tt.err)
			require.ErrorIs(t, got, startErr)
			assert.Contains(t, got.Error(), tt.msg)
		})
	}
}

// TestProxyManagedEnvoyLoaderNotFound checks the error of a [Proxy]
// whose managed build names a dynamic loader that the host does not
// hold. The error names the loader and the ways to run another binary.
func TestProxyManagedEnvoyLoaderNotFound(t *testing.T) {
	t.Parallel()

	loader := filepath.Join(t.TempDir(), "ld-missing.so.1")
	inst, path, _ := managedEnvoyInstaller(t, elfWithInterpreter(t, loader))

	dir := t.TempDir()
	usr := stubProxyUser(t, dir, "egress: []\n")
	usr.ReadyFile = filepath.Join(dir, "ready")

	opts := proxyOptions{bindAddress: loopbackIPv4, httpPort: freePort(t)}

	err := Proxy(t.Context(), usr, inst, opts)
	require.ErrorIs(t, err, ErrLoaderNotFound)
	require.ErrorIs(t, err, fs.ErrNotExist)
	require.ErrorContains(t, err, "starting envoy "+path+": ")
	require.ErrorContains(t, err, ": "+loader+": ")
	require.ErrorContains(t, err, "set --envoy-path or the envoy.path config key")

	assert.NoFileExists(t, usr.ReadyFile)
}

// TestEnvoyBinaryCommandRunsCheckedFile checks that the command of a
// managed binary runs the file that [resolveEnvoy] hashed. Another file
// takes the install path between the hash check and the start of the
// command.
func TestEnvoyBinaryCommandRunsCheckedFile(t *testing.T) {
	t.Parallel()

	out := filepath.Join(t.TempDir(), "out")

	// script returns a program that writes word to the out file. It
	// runs only shell builtins, so it does not depend on PATH.
	script := func(word string) []byte {
		return []byte("#!/bin/sh\necho " + word + " > '" + out + "'\n")
	}

	inst, path, _ := managedEnvoyInstaller(t, script("checked"))

	bin, err := resolveEnvoy(t.Context(), inst, "")
	require.NoError(t, err)
	closeEnvoyBinary(t, bin)

	// A rename puts another file at the install path. A write to the
	// path changes the checked file itself.
	other := filepath.Join(filepath.Dir(path), "other")
	require.NoError(t, os.WriteFile(other, script("replaced"), 0o755))
	require.NoError(t, os.Rename(other, path))

	cmd := bin.command(t.Context())
	require.NoError(t, cmd.Run())

	data, err := os.ReadFile(out) //nolint:gosec // test fixture path.
	require.NoError(t, err)
	assert.Equal(t, "checked\n", string(data))

	// The command line of the process names the install path.
	assert.Equal(t, []string{path}, cmd.Args)
}
