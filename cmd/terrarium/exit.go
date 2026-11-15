package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/charmbracelet/fang"
	"go.jacobcolvin.com/niceyaml/fangs"
)

// ExitError carries a nonzero exit code through the error return path
// to [run], which makes it the exit code of terrarium.
//
// Terrarium prints no error for an ExitError, so the command that
// returns one must make sure that the user can see the cause. Init
// returns the exit code of the user command, which reports its own
// failure. A user command that a signal ends cannot report the
// signal, so Init logs it and returns the code 128 plus the signal
// number. That code is 143 for SIGTERM. The status command returns 3
// after it renders a report that shows a daemon that is not running.
type ExitError struct{ Code int }

// Error returns a human-readable representation of the exit status.
func (e *ExitError) Error() string {
	return fmt.Sprintf("exit status %d", e.Code)
}

// errorHandler is the [fang.ErrorHandler] of terrarium. It prints
// nothing for an [*ExitError] and passes every other error to
// [fangs.ErrorHandler].
//
//nolint:gocritic // hugeParam: required by [fang.ErrorHandler] signature.
func errorHandler(w io.Writer, styles fang.Styles, err error) {
	var exitErr *ExitError

	if errors.As(err, &exitErr) {
		return
	}

	fangs.ErrorHandler(w, styles, err)
}

// exitCode returns the exit code of terrarium for the error of the
// executed command. The code is 0 for nil, the code of an
// [*ExitError], and 1 for every other error.
func exitCode(err error) int {
	if err == nil {
		return 0
	}

	var exitErr *ExitError

	if errors.As(err, &exitErr) {
		return exitErr.Code
	}

	return 1
}
