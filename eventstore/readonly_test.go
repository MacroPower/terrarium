package eventstore_test

import (
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/eventstore"
)

// stoppedStore writes to path the files of a store that stopped
// without a clean close. It returns the content of each file under the
// suffix of the file. The files are a copy of the files of an open
// store, so the `-wal` file holds frames that no checkpoint copied to
// the database file.
func stoppedStore(t *testing.T, path string) map[string][]byte {
	t.Helper()

	live := filepath.Join(t.TempDir(), "live.db")

	store, err := eventstore.Open(t.Context(), live)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	files := map[string][]byte{}

	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, err := os.ReadFile(live + suffix)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path+suffix, data, 0o600))

		files[suffix] = data
	}

	require.NotEmpty(t, files["-wal"])

	return files
}

// assertFilesEqual asserts that the database file at path and its
// `-wal` file hold the content in want. The map want holds the content
// of each file under the suffix of the file.
func assertFilesEqual(t *testing.T, want map[string][]byte, path string) {
	t.Helper()

	for _, suffix := range []string{"", "-wal"} {
		data, err := os.ReadFile(path + suffix)
		require.NoError(t, err)
		assert.Equal(t, want[suffix], data, "the reader changed the file %q", filepath.Base(path)+suffix)
	}
}

// assertNoWALFiles asserts that the database file at path has no
// `-wal` file and no `-shm` file.
func assertNoWALFiles(t *testing.T, path string) {
	t.Helper()

	assert.NoFileExists(t, path+"-wal")
	assert.NoFileExists(t, path+"-shm")
}

// A store that closes cleanly removes the `-wal` and `-shm` files. The
// next query of a reader that opened before the close creates both
// files again.
func TestOpenReadOnly_StoreClosesDuringRead(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")

	store, err := eventstore.Open(t.Context(), path)
	require.NoError(t, err)

	db, err := eventstore.OpenReadOnly(t.Context(), path)
	require.NoError(t, err)

	// The reader keeps no connection between its queries, so the store
	// is the last connection when it closes.
	db.SetMaxIdleConns(0)

	require.NoError(t, store.Close())
	assertNoWALFiles(t, path)

	want, err := os.ReadFile(path)
	require.NoError(t, err)

	assert.Equal(t, 1, countInstances(t, db))
	assert.FileExists(t, path+"-wal")

	require.NoError(t, db.Close())

	assertNoWALFiles(t, path)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, want, got, "the reader changed the database file")
}

// A store that opens after the reader and then stops without a clean
// close leaves a `-wal` file with frames. The reader is then the last
// connection to close the database.
func TestOpenReadOnly_StoreStopsDuringRead(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	closedStore(t, path)

	db, err := eventstore.OpenReadOnly(t.Context(), path)
	require.NoError(t, err)

	// The reader keeps no connection between its queries, so no
	// connection is open when the files change.
	db.SetMaxIdleConns(0)

	want := stoppedStore(t, path)

	assert.Equal(t, 1, countInstances(t, db))

	_, err = db.ExecContext(t.Context(), `DELETE FROM instances`)
	require.ErrorContains(t, err, "attempt to write a readonly database")

	require.NoError(t, db.Close())

	assertFilesEqual(t, want, path)
}

func TestOpenReadOnly_OverlappingReadersRemoveWALFiles(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		// firstClosesFirst reports whether the reader that opened
		// first also closes first.
		firstClosesFirst bool
	}{
		"first reader closes first": {firstClosesFirst: true},
		"first reader closes last":  {firstClosesFirst: false},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "stats.db")
			closedStore(t, path)

			want, err := os.ReadFile(path)
			require.NoError(t, err)

			first, err := eventstore.OpenReadOnly(t.Context(), path)
			require.NoError(t, err)

			second, err := eventstore.OpenReadOnly(t.Context(), path)
			require.NoError(t, err)

			assert.Equal(t, 1, countInstances(t, first))
			assert.Equal(t, 1, countInstances(t, second))

			if !tc.firstClosesFirst {
				first, second = second, first
			}

			// The reader that stays open still reads, and its
			// connection keeps both files.
			require.NoError(t, first.Close())
			assert.Equal(t, 1, countInstances(t, second))
			assert.FileExists(t, path+"-wal")

			require.NoError(t, second.Close())

			assertNoWALFiles(t, path)

			got, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, want, got, "the readers changed the database file")
		})
	}
}

// The close of a [*sql.DB] closes only its idle connections before the
// cleanup. The connection of an open [*sql.Rows] closes later for
// reads only, so both files stay.
func TestOpenReadOnly_OpenRowsKeepWALFiles(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	closedStore(t, path)

	db, err := eventstore.OpenReadOnly(t.Context(), path)
	require.NoError(t, err)

	rows, err := db.QueryContext(t.Context(), `SELECT id FROM instances`)
	require.NoError(t, err)

	require.NoError(t, db.Close())
	require.NoError(t, rows.Close())

	assert.FileExists(t, path+"-wal")
	assert.FileExists(t, path+"-shm")

	// The next reader that closes with no value open removes both files.
	reader, err := eventstore.OpenReadOnly(t.Context(), path)
	require.NoError(t, err)

	assert.Equal(t, 1, countInstances(t, reader))
	require.NoError(t, reader.Close())

	assertNoWALFiles(t, path)
}

func TestOpenReadOnly_ConcurrentReadersRemoveWALFiles(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	closedStore(t, path)

	want, err := os.ReadFile(path)
	require.NoError(t, err)

	const readers = 8

	var (
		wg   sync.WaitGroup
		errs [readers]error
	)

	for i := range readers {
		wg.Go(func() {
			for range 5 {
				db, err := eventstore.OpenReadOnly(t.Context(), path)
				if err != nil {
					errs[i] = errors.Join(errs[i], err)

					continue
				}

				var n int

				err = db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM instances`).Scan(&n)
				errs[i] = errors.Join(errs[i], err, db.Close())
			}
		})
	}

	wg.Wait()

	for i := range readers {
		require.NoError(t, errs[i])
	}

	assertNoWALFiles(t, path)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, want, got, "the readers changed the database file")
}

// A store can write its first frame between the check of the `-wal`
// file that the close of a reader runs first and the write lock of the
// cleanup. RemoveWALIfEmpty starts after that check.
func TestRemoveWALIfEmpty_KeepsWALWithFrames(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	want := stoppedStore(t, path)

	require.NoError(t, eventstore.RemoveWALIfEmpty(t.Context(), path))

	assertFilesEqual(t, want, path)
	assert.FileExists(t, path+"-shm")
}

func TestRemoveWALIfEmpty_RemovesEmptyWAL(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	closedStore(t, path)

	want, err := os.ReadFile(path)
	require.NoError(t, err)

	// The call creates both files and removes them.
	require.NoError(t, eventstore.RemoveWALIfEmpty(t.Context(), path))

	assertNoWALFiles(t, path)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, want, got, "the cleanup changed the database file")
}

// A connection that holds the write lock is in the middle of a write,
// so the cleanup leaves the files to that connection.
func TestRemoveWALIfEmpty_KeepsFilesOfWriter(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	closedStore(t, path)

	raw, err := sql.Open("sqlite", "file://"+(&url.URL{Path: path}).EscapedPath())
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, raw.Close()) })

	conn, err := raw.Conn(t.Context())
	require.NoError(t, err)

	_, err = conn.ExecContext(t.Context(), `BEGIN IMMEDIATE`)
	require.NoError(t, err)

	require.NoError(t, eventstore.RemoveWALIfEmpty(t.Context(), path))

	assert.FileExists(t, path+"-wal")
	assert.FileExists(t, path+"-shm")

	// The writer still holds its lock and commits its write.
	_, err = conn.ExecContext(t.Context(), `INSERT INTO instances (id, started_at, mode) VALUES ('x', 1, 'proxy')`)
	require.NoError(t, err)

	_, err = conn.ExecContext(t.Context(), `COMMIT`)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	db := openReadOnly(t, path)

	assert.Equal(t, 2, countInstances(t, db))
}

// A reader that runs as another user can keep the `-wal` and `-shm`
// files, which that user owns. SQLite then opens them for reads only
// for the owner of the database file, so its cleanup cannot take the
// write lock. The same holds for a database file that the caller
// cannot write. The close keeps the files and reports no error.
func TestOpenReadOnly_KeepsFilesItCannotWrite(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("root ignores the mode of a file")
	}

	tcs := map[string]struct {
		// readOnly lists the suffixes of the files that the caller
		// cannot write.
		readOnly []string
	}{
		"write-ahead log files": {readOnly: []string{"-wal", "-shm"}},
		"database file":         {readOnly: []string{""}},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "stats.db")
			closedStore(t, path)

			// A connection for reads only creates both files and keeps
			// them.
			raw, err := sql.Open("sqlite", "file://"+(&url.URL{Path: path}).EscapedPath()+"?mode=ro")
			require.NoError(t, err)

			_, err = raw.ExecContext(t.Context(), `SELECT COUNT(*) FROM instances`)
			require.NoError(t, err)
			require.NoError(t, raw.Close())

			for _, suffix := range tc.readOnly {
				require.NoError(t, os.Chmod(path+suffix, 0o444))
			}

			want, err := os.ReadFile(path)
			require.NoError(t, err)

			for range 2 {
				db, err := eventstore.OpenReadOnly(t.Context(), path)
				require.NoError(t, err)

				assert.Equal(t, 1, countInstances(t, db))
				require.NoError(t, db.Close())

				assert.FileExists(t, path+"-wal")
				assert.FileExists(t, path+"-shm")
			}

			got, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, want, got, "the reader changed the database file")
		})
	}
}
