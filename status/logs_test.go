package status_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/status"
)

func writeLog(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "log")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	return path
}

func TestTailNShorterThanN(t *testing.T) {
	t.Parallel()

	path := writeLog(t, "a\nb\nc\n")

	lines, err := status.TailN(path, 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, lines)
}

func TestTailNExactlyN(t *testing.T) {
	t.Parallel()

	path := writeLog(t, "a\nb\nc\n")

	lines, err := status.TailN(path, 3)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, lines)
}

func TestTailNLongerThanN(t *testing.T) {
	t.Parallel()

	var b strings.Builder

	for i := range 100 {
		_, _ = b.WriteString("line")
		_, _ = b.WriteRune(rune('0' + (i % 10)))
		_, _ = b.WriteString("\n")
	}

	path := writeLog(t, b.String())

	lines, err := status.TailN(path, 5)
	require.NoError(t, err)
	assert.Len(t, lines, 5)
	assert.Equal(t, "line5", lines[0])
	assert.Equal(t, "line9", lines[4])
}

func TestTailNLineSpansChunks(t *testing.T) {
	t.Parallel()

	// Build a file with one line that is > 8 KiB so it spans
	// multiple reverse-read chunks.
	long := strings.Repeat("x", 10_000)

	path := writeLog(t, "first\n"+long+"\nlast\n")

	lines, err := status.TailN(path, 2)
	require.NoError(t, err)
	require.Len(t, lines, 2)
	assert.Equal(t, long, lines[0])
	assert.Equal(t, "last", lines[1])
}

func TestTailNNonTerminatedFinalLine(t *testing.T) {
	t.Parallel()

	path := writeLog(t, "a\nb\nc")

	lines, err := status.TailN(path, 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, lines)
}

func TestTailNCRLF(t *testing.T) {
	t.Parallel()

	path := writeLog(t, "a\r\nb\r\nc\r\n")

	lines, err := status.TailN(path, 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, lines)
}

func TestTailNEmpty(t *testing.T) {
	t.Parallel()

	path := writeLog(t, "")

	lines, err := status.TailN(path, 10)
	require.NoError(t, err)
	assert.Empty(t, lines)
}

func TestTailNMissing(t *testing.T) {
	t.Parallel()

	_, err := status.TailN(filepath.Join(t.TempDir(), "nope"), 10)
	require.ErrorIs(t, err, fs.ErrNotExist)
}

func TestTailNUnreadable(t *testing.T) {
	t.Parallel()

	if os.Getuid() == 0 {
		t.Skip("chmod 000 is ignored by root")
	}

	path := writeLog(t, "a\nb\n")

	require.NoError(t, os.Chmod(path, 0o000))

	t.Cleanup(func() {
		os.Chmod(path, 0o644) //nolint:errcheck // best-effort perm restore for cleanup.
	})

	_, err := status.TailN(path, 10)
	require.ErrorIs(t, err, fs.ErrPermission)
}

func TestTailNZeroLines(t *testing.T) {
	t.Parallel()

	path := writeLog(t, "a\nb\nc\n")

	lines, err := status.TailN(path, 0)
	require.NoError(t, err)
	assert.Empty(t, lines)

	lines, err = status.TailN(path, -5)
	require.NoError(t, err)
	assert.Empty(t, lines)
}
