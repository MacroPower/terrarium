package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

// flakeSource is the path of the flake that holds the vendorHash, relative
// to the root of the repository.
const flakeSource = "lima/flake.nix"

// The names of the commands.
const (
	cmdCheck  = "check"
	cmdUpdate = "update"
)

const usage = `usage:
  vendorhash check    compare the vendorHash in lima/flake.nix with the vendor tree
  vendorhash update   write the hash of the vendor tree into lima/flake.nix`

var (
	// ErrUsage means that the arguments do not name a command.
	ErrUsage = errors.New(usage)

	// ErrStale means that the vendorHash in the flake is not the hash of
	// the vendor tree.
	ErrStale = errors.New("vendorHash is stale")
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	err := run(ctx, os.Args[1:], ".", os.Stdout)

	stop()

	if err != nil {
		fmt.Fprintln(os.Stderr, "vendorhash:", err)
		os.Exit(1)
	}
}

// run executes the command that args names and writes its report to out.
// The root argument is the root of the repository, which holds the root Go
// module and the flake.
func run(ctx context.Context, args []string, root string, out io.Writer) error {
	if len(args) != 1 {
		return ErrUsage
	}

	path := filepath.Join(root, filepath.FromSlash(flakeSource))

	switch args[0] {
	case cmdCheck:
		return check(ctx, root, path, out)

	case cmdUpdate:
		return update(ctx, root, path, out)

	default:
		return ErrUsage
	}
}

// check compares the vendorHash in the flake at path with the hash of the
// vendor tree of the Go module in dir. It returns an [ErrStale] error when
// the two hashes differ.
func check(ctx context.Context, dir, path string, out io.Writer) error {
	f, err := readFlake(path)
	if err != nil {
		return err
	}

	sum, err := vendorHash(ctx, dir)
	if err != nil {
		return err
	}

	if f.hash() != sum {
		return fmt.Errorf(
			"%w: %s holds %s, and the vendor tree hashes to %s (run `go run ./cmd/vendorhash %s`)",
			ErrStale, path, f.hash(), sum, cmdUpdate,
		)
	}

	_, err = fmt.Fprintf(out, "%s: vendorHash %s matches the vendor tree\n", path, sum)
	if err != nil {
		return fmt.Errorf("print result: %w", err)
	}

	return nil
}

// update writes the hash of the vendor tree of the Go module in dir into
// the flake at path, as its vendorHash. It leaves a flake that holds the
// hash unchanged.
func update(ctx context.Context, dir, path string, out io.Writer) error {
	f, err := readFlake(path)
	if err != nil {
		return err
	}

	sum, err := vendorHash(ctx, dir)
	if err != nil {
		return err
	}

	if f.hash() == sum {
		_, err = fmt.Fprintf(out, "%s: vendorHash %s matches the vendor tree\n", path, sum)
		if err != nil {
			return fmt.Errorf("print result: %w", err)
		}

		return nil
	}

	old := f.hash()

	err = f.write(sum)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "%s: vendorHash changed from %s to %s\n", path, old, sum)
	if err != nil {
		return fmt.Errorf("print result: %w", err)
	}

	return nil
}
