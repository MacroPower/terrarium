package privdrop

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// lookPath searches for an executable in the directories listed in the
// PATH environment variable. If name contains a slash, it is returned
// directly after verifying it is executable. This is a minimal
// reimplementation of exec.LookPath that avoids importing os/exec
// (which pulls in sync, context, etc.).
func lookPath(name string) (string, error) {
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

		path := filepath.Join(dir, name)

		err := isExecutable(path)
		if err == nil {
			return path, nil
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

	// Check if any execute bit is set.
	if info.Mode()&0o111 == 0 {
		return errors.New("not executable")
	}

	return nil
}
