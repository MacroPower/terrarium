//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
)

// The outcomes of a reload in a [reloadStatus].
const (
	// The daemon runs the new config.
	reloadCompleted = "completed"

	// The daemon runs the previous config unchanged.
	reloadRejected = "rejected"

	// The reload stopped between the previous config and the new
	// config, so the daemon shuts down.
	reloadFailed = "failed"
)

// reloadStatus is the content of the reload status file. The daemon
// writes the file, and [DaemonReload] reads it to learn when a reload
// finished and how.
//
// The daemon runs one reload at a time and numbers its reloads from 1.
// Started is therefore the number of the reload that started last, and
// Finished is the number of the reload that finished last. A reload
// runs when Started is greater than Finished.
type reloadStatus struct {
	// The outcome of the reload with the number Finished. It is empty
	// before the first reload finishes.
	Outcome string `json:"outcome,omitempty"`

	// The error text of the reload with the number Finished. It is
	// empty when that reload completed.
	Error string `json:"error,omitempty"`

	// The PID of the daemon that wrote the status.
	PID int `json:"pid"`

	// The number of reloads that the daemon started.
	Started uint64 `json:"started"`

	// The number of reloads that the daemon finished.
	Finished uint64 `json:"finished"`
}

// err returns the error that [DaemonReload] reports for the outcome of
// s. It returns nil for a reload that completed.
func (s *reloadStatus) err() error {
	switch s.Outcome {
	case reloadCompleted:
		return nil

	case reloadRejected:
		return fmt.Errorf("%w: %s", ErrDaemonKeptConfig, s.Error)

	case reloadFailed:
		return fmt.Errorf("%w: %s", ErrReloadEndedDaemon, s.Error)

	default:
		return fmt.Errorf("%w: unknown outcome %q", ErrReloadStatus, s.Outcome)
	}
}

// reloadStatusPath returns the path of the reload status file of the
// daemon that records its PID in pidFile. The daemon and
// [DaemonReload] derive the path from the same --pid-file flag, so
// both name the same file.
func reloadStatusPath(pidFile string) string {
	return pidFile + ".reload"
}

// readReloadStatus reads the reload status file at path. The error
// wraps [fs.ErrNotExist] when the file does not exist.
func readReloadStatus(path string) (*reloadStatus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading reload status: %w", err)
	}

	status := &reloadStatus{}

	err = json.Unmarshal(data, status)
	if err != nil {
		return nil, fmt.Errorf("parsing reload status %s: %w", path, err)
	}

	return status, nil
}

// reloadRecorder keeps the reload status file of the daemon up to
// date. It replaces the file in one rename for each change, so a
// reader never reads a partial status.
//
// Create instances with [newReloadRecorder].
type reloadRecorder struct {
	path   string
	status reloadStatus
}

// newReloadRecorder creates a new [reloadRecorder] and writes the
// status of a daemon that has started no reload to path. A status
// file that a previous daemon left at path does not survive the call.
func newReloadRecorder(path string) (*reloadRecorder, error) {
	r := &reloadRecorder{
		path:   path,
		status: reloadStatus{PID: os.Getpid()},
	}

	err := r.write()
	if err != nil {
		return nil, err
	}

	return r, nil
}

// record runs reload as the next reload of the daemon and returns the
// error of reload. It writes to the status file that the reload
// started, and then that the reload finished with its outcome:
//
//   - No error gives [reloadCompleted].
//   - An error that wraps [ErrReloadRejected] gives [reloadRejected].
//   - Every other error gives [reloadFailed].
//
// A status that record cannot write does not stop the reload. Record
// logs the error of the write.
func (r *reloadRecorder) record(ctx context.Context, reload func(ctx context.Context) error) error {
	r.status.Started++
	r.save(ctx)

	err := reload(ctx)

	r.status.Finished = r.status.Started
	r.status.Outcome = reloadCompleted
	r.status.Error = ""

	if err != nil {
		r.status.Outcome = reloadFailed
		r.status.Error = err.Error()

		if errors.Is(err, ErrReloadRejected) {
			r.status.Outcome = reloadRejected
		}
	}

	r.save(ctx)

	return err
}

// remove deletes the status file. It logs an error of the removal.
func (r *reloadRecorder) remove(ctx context.Context) {
	err := os.Remove(r.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.ErrorContext(ctx, "removing reload status", slog.Any("err", err))
	}
}

// save writes the status and logs an error of the write.
func (r *reloadRecorder) save(ctx context.Context) {
	err := r.write()
	if err != nil {
		slog.ErrorContext(ctx, "recording reload status", slog.Any("err", err))
	}
}

// write replaces the status file with the status of r.
func (r *reloadRecorder) write() error {
	data, err := json.Marshal(&r.status)
	if err != nil {
		return fmt.Errorf("encoding reload status: %w", err)
	}

	err = writeFileAtomic(r.path, append(data, '\n'))
	if err != nil {
		return fmt.Errorf("writing reload status: %w", err)
	}

	return nil
}
