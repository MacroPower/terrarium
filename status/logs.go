package status

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"go.jacobcolvin.com/terrarium/config"
)

// tailChunkSize is the window size for reverse reads in [TailN].
// 8 KiB is a round multiple of page size and holds tens of typical
// log lines per chunk without over-allocating for short files.
const tailChunkSize int64 = 8 << 10

// TailN returns the last n lines of the file at path. Lines are
// returned in file order (oldest first). A non-newline-terminated
// final line is included. CRLF line endings are stripped. When the
// file contains fewer than n lines, the whole file is returned.
// Returns an empty slice (no error) when the file exists but is
// empty.
func TailN(path string, n int) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}

	f, err := os.Open(path) //nolint:gosec // operator-supplied path.
	if err != nil {
		return nil, err
	}

	defer f.Close() //nolint:errcheck // read-only file.

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	size := info.Size()
	if size == 0 {
		return nil, nil
	}

	// Read backwards in chunks until we've collected n+1 newlines
	// (or exhausted the file). The extra newline lets us trim the
	// partial first line that starts before our window began.
	var (
		buffer    []byte
		offset    = size
		newlines  int
		needLines = n + 1
	)

	for offset > 0 && newlines < needLines {
		readLen := tailChunkSize
		if offset < readLen {
			readLen = offset
		}

		offset -= readLen

		chunk := make([]byte, readLen)

		_, err := f.ReadAt(chunk, offset)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}

		buffer = append(chunk, buffer...)
		newlines = countNewlines(buffer)
	}

	lines := splitTailLines(buffer)
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}

	return lines, nil
}

// countNewlines counts '\n' bytes in b. Used by [TailN] to decide
// whether enough of the file has been read in reverse to satisfy the
// requested line count.
func countNewlines(b []byte) int {
	return strings.Count(string(b), "\n")
}

// splitTailLines splits raw tail bytes on '\n' and strips trailing
// '\r'. An empty final element produced by a trailing newline is
// dropped; a non-empty final element (a line that was not
// newline-terminated, common when envoy rotates mid-line on SIGHUP)
// is preserved.
func splitTailLines(buffer []byte) []string {
	s := string(buffer)

	lines := strings.Split(s, "\n")

	// Drop a trailing empty element produced by a final '\n'.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	for i, line := range lines {
		lines[i] = strings.TrimRight(line, "\r")
	}

	return lines
}

// collectLogs tails the Envoy process and access log files. When cfg
// is non-nil, [Config.EnvoyLogPath] and [Config.EnvoyAccessLogPath]
// are consulted so a YAML override takes priority over the CLI
// fallback. When cfg is nil (config missing or unreadable), the CLI
// fallbacks from opts are used directly. A permission or parse error
// from the config load is preserved on the [LogsSection] so the
// renderer can annotate why it fell back.
func collectLogs(cfg *config.Config, cfgErr error, opts Options) LogsSection {
	s := LogsSection{Requested: opts.LogLines}

	if opts.NoLogs {
		s.Skipped = true
		return s
	}

	if s.Requested < 0 {
		s.Requested = 0
	}

	envoyLog := opts.EnvoyLogPath
	accessLog := opts.EnvoyAccessLogPath

	if cfg != nil {
		envoyLog = cfg.EnvoyLogPath(opts.EnvoyLogPath)
		accessLog = cfg.EnvoyAccessLogPath(opts.EnvoyAccessLogPath)
	}

	s.EnvoyLog = LogTail{Path: envoyLog}
	s.EnvoyAccessLog = LogTail{Path: accessLog}

	if cfgErr != nil {
		// Permission/parse errors from the config read surface as
		// annotations on both log tails so the renderer can explain
		// the fallback without a full-section Err.
		s.EnvoyLog.Err = fmt.Errorf("config: %w", cfgErr)
		s.EnvoyAccessLog.Err = fmt.Errorf("config: %w", cfgErr)
	}

	s.EnvoyLog.Lines, s.EnvoyLog.Err = tailOrKeepErr(envoyLog, s.Requested, s.EnvoyLog.Err)
	s.EnvoyAccessLog.Lines, s.EnvoyAccessLog.Err = tailOrKeepErr(accessLog, s.Requested, s.EnvoyAccessLog.Err)

	return s
}

// tailOrKeepErr tails n lines from path. When an existing Err is
// non-nil (from the config load), the result keeps that Err and
// appends no new error, so the renderer can explain both the config
// fallback and the tail outcome.
func tailOrKeepErr(path string, n int, existing error) ([]string, error) {
	lines, err := TailN(path, n)
	switch {
	case err == nil:
		return lines, existing
	case existing != nil && errors.Is(err, fs.ErrNotExist):
		return nil, existing
	default:
		return lines, err
	}
}
