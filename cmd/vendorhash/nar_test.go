package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// node is one file of a test tree.
type node struct {
	// path is relative to the root of the tree. The empty path names the
	// root.
	path string
	// data is the content of a regular file.
	data string
	// link is the target of a symlink.
	link string
	// mode is [fs.ModeDir] for a directory, [fs.ModeSymlink] for a
	// symlink, and the permissions of a regular file.
	mode fs.FileMode
}

// writeTree creates the nodes below a new temporary directory and returns
// the path of the root node.
func writeTree(t *testing.T, nodes []node) string {
	t.Helper()

	root := filepath.Join(t.TempDir(), "root")

	for _, n := range nodes {
		path := filepath.Join(root, filepath.FromSlash(n.path))

		switch {
		case n.mode.IsDir():
			require.NoError(t, os.MkdirAll(path, 0o755))

		case n.mode&fs.ModeSymlink != 0:
			require.NoError(t, os.Symlink(n.link, path))

		default:
			require.NoError(t, os.WriteFile(path, []byte(n.data), n.mode))
			// The umask can remove permissions from a new file.
			require.NoError(t, os.Chmod(path, n.mode))
		}
	}

	return root
}

// TestNarHash checks each hash against the output of
// `nix-hash --type sha256 --sri` for the same tree.
func TestNarHash(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		want  string
		nodes []node
	}{
		"empty directory": {
			nodes: []node{{mode: fs.ModeDir}},
			want:  "sha256-pQpattmS9VmO3ZIQUFn66az8GSmB4IvYhTTCFn6SUmo=",
		},
		"empty file": {
			nodes: []node{{mode: 0o644}},
			want:  "sha256-d6xi4mKdjkX2JFicDIv5niSzpyI0m/Hnm8GGAIU04kY=",
		},
		"file": {
			nodes: []node{{data: "hello\n", mode: 0o644}},
			want:  "sha256-HDfQGvQL4ugGkd48w99EN3ppmvuxfGjwgJZLL9Bx/BM=",
		},
		// The archive holds no permission other than the execute
		// permission of the owner.
		"file that only its owner can read": {
			nodes: []node{{data: "hello\n", mode: 0o400}},
			want:  "sha256-HDfQGvQL4ugGkd48w99EN3ppmvuxfGjwgJZLL9Bx/BM=",
		},
		"executable file": {
			nodes: []node{{data: "#!/bin/sh\n", mode: 0o755}},
			want:  "sha256-YoPBZoJg+QPRqJXAzWuCL6S2h2K7CxfO3vLTnZfiZVQ=",
		},
		"symlink": {
			nodes: []node{{link: "target/of/link", mode: fs.ModeSymlink}},
			want:  "sha256-bBhbaXSs8xmNT1xdjr8B/kkmxo1wuUjLtWHoPWuREXQ=",
		},
		// The tree holds a file whose size is a multiple of the
		// alignment and an empty directory. The byte order of its
		// names differs from their order without case.
		"tree": {
			nodes: []node{
				{mode: fs.ModeDir},
				{path: "empty", mode: 0o644},
				{path: "eight", data: "12345678", mode: 0o644},
				{path: "text", data: "hello\n", mode: 0o644},
				{path: "run.sh", data: "#!/bin/sh\n", mode: 0o755},
				{path: "link", link: "text", mode: fs.ModeSymlink},
				{path: "sub/inner", mode: fs.ModeDir},
				{path: "sub/inner/deep.txt", data: "deep\n", mode: 0o644},
				{path: "sub/void", mode: fs.ModeDir},
				{path: "B", data: "B", mode: 0o644},
				{path: "_x", data: "_", mode: 0o644},
				{path: "a", data: "a", mode: 0o644},
			},
			want: "sha256-0Y9JfrWrFjJPP7+Y6lwWOTZpaR6aGplzIDrTrrqjLH0=",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := narHash(writeTree(t, tc.nodes))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestNarHashRejectsTree(t *testing.T) {
	t.Parallel()

	t.Run("missing root", func(t *testing.T) {
		t.Parallel()

		_, err := narHash(filepath.Join(t.TempDir(), "missing"))
		require.ErrorIs(t, err, ErrArchive)
		require.ErrorIs(t, err, fs.ErrNotExist)
	})

	t.Run("named pipe", func(t *testing.T) {
		t.Parallel()

		root := writeTree(t, []node{{mode: fs.ModeDir}})
		path := filepath.Join(root, "pipe")
		require.NoError(t, syscall.Mkfifo(path, 0o644))

		_, err := narHash(root)
		require.ErrorIs(t, err, ErrArchive)
		require.ErrorContains(t, err, path+" is not a regular file, a symlink, or a directory")
	})
}
