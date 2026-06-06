package main

import "fmt"

// ExitError carries a child process exit code through the error
// return path so the CLI entrypoint can propagate it to [os.Exit].
type ExitError struct{ Code int }

// Error returns a human-readable representation of the exit status.
func (e *ExitError) Error() string {
	return fmt.Sprintf("exit status %d", e.Code)
}
