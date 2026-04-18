// Package lookpath resolves command names to executable paths without
// importing os/exec (which pulls in sync, context, and friends). Both
// [privdrop] and [jail] use it to locate argv[0] before handing the
// path to execve on the same OS thread.
package lookpath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Find searches for an executable in the directories listed in the
// PATH environment variable. If name contains a slash, it is returned
// directly after verifying it is executable. An empty name is
// rejected with a distinct error.
func Find(name string) (string, error) {
	if name == "" {
		return "", errors.New("empty command name")
	}

	if strings.Contains(name, "/") {
		err := isExecutable(name)
		if err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}

		return name, nil
	}

	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return "", fmt.Errorf("%s: PATH is empty", name)
	}

	for dir := range strings.SplitSeq(pathEnv, ":") {
		if dir == "" {
			dir = "."
		}

		p := filepath.Join(dir, name)

		err := isExecutable(p)
		if err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf("%s: not found in PATH", name)
}

func isExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	if info.IsDir() {
		return errors.New("is a directory")
	}

	if info.Mode()&0o111 == 0 {
		return errors.New("not executable")
	}

	return nil
}
