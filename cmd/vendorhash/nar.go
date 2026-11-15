package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// narAlign is the number of bytes that each string of a Nix archive is a
// multiple of.
const narAlign = 8

// ErrArchive means that a file tree has no Nix archive.
var ErrArchive = errors.New("nix archive")

// narHash returns the hash that Nix computes for the file tree at root,
// as `nix hash path` prints it. The hash is the SHA-256 of the Nix archive
// (NAR) of the tree, in the Subresource Integrity (SRI) form. That form is
// "sha256-" and the base64 of the digest.
//
// The archive holds the name of each file, its content, and whether its
// owner can execute it. It holds no other permission, no owner, and no
// timestamp.
func narHash(root string) (string, error) {
	digest := sha256.New()
	w := bufio.NewWriter(digest)
	n := narWriter{w: w}

	err := n.strings("nix-archive-1")
	if err != nil {
		return "", err
	}

	err = n.node(root)
	if err != nil {
		return "", err
	}

	err = w.Flush()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrArchive, err)
	}

	return "sha256-" + base64.StdEncoding.EncodeToString(digest.Sum(nil)), nil
}

// narWriter writes the Nix archive of a file tree to w.
type narWriter struct {
	w io.Writer
}

// node writes the file at path. A directory holds its entries in the byte
// order of their names, which is the order of [os.ReadDir].
func (n narWriter) node(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrArchive, err)
	}

	err = n.strings("(", "type")
	if err != nil {
		return err
	}

	switch mode := info.Mode(); {
	case mode.IsRegular():
		err = n.regular(path, mode)

	case mode&fs.ModeSymlink != 0:
		err = n.symlink(path)

	case mode.IsDir():
		err = n.directory(path)

	default:
		err = fmt.Errorf("%w: %s is not a regular file, a symlink, or a directory", ErrArchive, path)
	}

	if err != nil {
		return err
	}

	return n.strings(")")
}

// regular writes the fields of the regular file at path, which has mode.
func (n narWriter) regular(path string, mode fs.FileMode) error {
	err := n.strings("regular")
	if err != nil {
		return err
	}

	if mode&0o100 != 0 {
		err = n.strings("executable", "")
		if err != nil {
			return err
		}
	}

	err = n.strings("contents")
	if err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrArchive, err)
	}

	defer f.Close() //nolint:errcheck // The file is open for reading.

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrArchive, err)
	}

	size := info.Size()

	err = n.length(size)
	if err != nil {
		return err
	}

	copied, err := io.Copy(n.w, f)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrArchive, err)
	}

	if copied != size {
		return fmt.Errorf("%w: %s changed size from %d to %d bytes", ErrArchive, path, size, copied)
	}

	return n.pad(size)
}

// symlink writes the fields of the symlink at path.
func (n narWriter) symlink(path string) error {
	target, err := os.Readlink(path)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrArchive, err)
	}

	return n.strings("symlink", "target", target)
}

// directory writes the fields of the directory at path.
func (n narWriter) directory(path string) error {
	err := n.strings("directory")
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrArchive, err)
	}

	for _, entry := range entries {
		err = n.strings("entry", "(", "name", entry.Name(), "node")
		if err != nil {
			return err
		}

		err = n.node(filepath.Join(path, entry.Name()))
		if err != nil {
			return err
		}

		err = n.strings(")")
		if err != nil {
			return err
		}
	}

	return nil
}

// strings writes each string of ss as its length, its bytes, and the
// padding.
func (n narWriter) strings(ss ...string) error {
	for _, s := range ss {
		size := int64(len(s))

		err := n.length(size)
		if err != nil {
			return err
		}

		_, err = io.WriteString(n.w, s)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrArchive, err)
		}

		err = n.pad(size)
		if err != nil {
			return err
		}
	}

	return nil
}

// length writes size, the length of a string, as a 64-bit little-endian
// integer.
func (n narWriter) length(size int64) error {
	var buf [narAlign]byte

	//nolint:gosec // G115: the length of a string is never negative.
	binary.LittleEndian.PutUint64(buf[:], uint64(size))

	_, err := n.w.Write(buf[:])
	if err != nil {
		return fmt.Errorf("%w: %w", ErrArchive, err)
	}

	return nil
}

// pad writes the zero bytes that follow a string of size bytes, so that
// the string ends at a multiple of [narAlign].
func (n narWriter) pad(size int64) error {
	var zeros [narAlign]byte

	_, err := n.w.Write(zeros[:(narAlign-size%narAlign)%narAlign])
	if err != nil {
		return fmt.Errorf("%w: %w", ErrArchive, err)
	}

	return nil
}
