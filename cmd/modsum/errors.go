package main

import "errors"

var (
	// ErrUsage means that the arguments do not name a command.
	ErrUsage = errors.New(usage)

	// ErrStale means that a go.sum file does not hold the hashes that
	// its go.mod file requires.
	ErrStale = errors.New("go.sum is stale")

	// ErrDownload means that the go command cannot download the modules
	// that a go.mod file requires.
	ErrDownload = errors.New("download modules")
)
