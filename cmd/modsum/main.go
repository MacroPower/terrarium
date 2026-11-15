package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

// The names of the commands.
const (
	cmdCheck  = "check"
	cmdUpdate = "update"
)

const usage = `usage:
  modsum check    compare go.sum with go.mod in each Dagger module
  modsum update   write the hashes that go.mod requires into go.sum in each Dagger module`

// moduleDirs holds the directory of each Dagger module, relative to the
// root of the repository.
var moduleDirs = []string{"ci", "ci/tests"}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	err := run(ctx, os.Args[1:], ".", os.Environ(), os.Stdout)

	stop()

	if err != nil {
		fmt.Fprintln(os.Stderr, "modsum:", err)
		os.Exit(1)
	}
}

// run executes the command that args names for each module of
// [moduleDirs] and writes its report to out. It continues after a module
// fails and returns the errors of every module. The root argument is the
// root of the repository. The update command runs the go command with the
// environment in env.
func run(ctx context.Context, args []string, root string, env []string, out io.Writer) error {
	if len(args) != 1 {
		return ErrUsage
	}

	var errs []error

	switch args[0] {
	case cmdCheck:
		for _, dir := range moduleDirs {
			errs = append(errs, check(filepath.Join(root, filepath.FromSlash(dir)), out))
		}

	case cmdUpdate:
		for _, dir := range moduleDirs {
			errs = append(errs, update(ctx, filepath.Join(root, filepath.FromSlash(dir)), env, out))
		}

	default:
		return ErrUsage
	}

	return errors.Join(errs...)
}

// check compares go.sum with go.mod in the module in dir. It returns an
// [ErrStale] error that lists each of the [problems].
func check(dir string, out io.Writer) error {
	mod, err := readModule(dir)
	if err != nil {
		return err
	}

	err = mod.stale("go run ./cmd/modsum " + cmdUpdate)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "%s: holds each hash that %s requires\n", mod.sumPath, mod.modPath)
	if err != nil {
		return fmt.Errorf("print result: %w", err)
	}

	return nil
}

// update writes the hashes that go.mod requires into go.sum in the module
// in dir, with [download]. The go command can also change go.mod. When
// the update fails, it restores both files.
func update(ctx context.Context, dir string, env []string, out io.Writer) error {
	modPath, sumPath := modulePaths(dir)

	oldMod, err := readState(modPath)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrModFile, err)
	}

	oldSum, err := readState(sumPath)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSumFile, err)
	}

	err = download(ctx, dir, env)
	if err != nil {
		return errors.Join(err, oldMod.restore(), oldSum.restore())
	}

	newMod, err := readState(modPath)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrModFile, err)
	}

	newSum, err := readState(sumPath)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSumFile, err)
	}

	var report strings.Builder

	if !newMod.equal(oldMod) {
		fmt.Fprintf(&report, "%s: the go command changed the requirements\n", modPath)
	}

	if newSum.equal(oldSum) {
		fmt.Fprintf(&report, "%s: holds each hash that %s requires\n", sumPath, modPath)
	} else {
		fmt.Fprintf(&report, "%s: changed to the hashes that %s requires\n", sumPath, modPath)
	}

	_, err = io.WriteString(out, report.String())
	if err != nil {
		return fmt.Errorf("print result: %w", err)
	}

	return nil
}
