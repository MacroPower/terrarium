package eventstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// readOnlyDSNQuery is the query string of each connection that
// [OpenReadOnly] opens. SQLite reads `mode=ro`, so it opens the
// database file for reads only and does not create a missing one.
// Each statement that changes a table, an index, or the schema fails
// with `attempt to write a readonly database`.
//
// The last connection to close a database checkpoints the frames of
// the `-wal` file into the database file and removes the `-wal` and
// `-shm` files. SQLite grants the lock of that step only on a file
// that is open for writes. A connection with `mode=ro` therefore
// leaves the three files as it found them, also when it closes last.
//
// A query creates the `-wal` file and the `-shm` file that are
// missing, and the connection cannot remove them for the same reason.
// [removeEmptyWAL] removes them.
const readOnlyDSNQuery = "?mode=ro&_pragma=busy_timeout(2000)"

// walCleanupDSNQuery is the query string of the connection that
// [removeWALIfEmpty] opens to remove the `-wal` and `-shm` files.
// SQLite reads `mode=rw`, so it opens an existing file for reads and
// writes and does not create a missing one. SQLite opens a file that
// the caller cannot write for reads only, and that connection removes
// no file.
const walCleanupDSNQuery = "?mode=rw&_pragma=busy_timeout(2000)"

// walCleanupMu lets one [removeWALIfEmpty] run at a time in this
// process. SQLite removes the `-wal` file only at the close of the
// last connection, so two calls that overlap each keep the file for
// the other.
var walCleanupMu sync.Mutex

// OpenReadOnly opens the SQLite event store at path for reads only.
// No writer goroutine, no schema apply, no instance row. It gives raw
// SQL access to a database written by a separate [*Store] in the
// daemon. Use [OpenReader] for the typed queries. The caller owns
// closing the returned [*sql.DB].
//
// A path that holds no file returns an error that wraps
// [io/fs.ErrNotExist], and OpenReadOnly does not create the file.
// SQLite opens the database file for reads only on each connection.
// A statement that changes a table, an index, or the schema through
// the returned [*sql.DB] therefore fails. An `ATTACH` statement still
// creates the file that it names.
//
// The connections never checkpoint the `-wal` file into the database
// file. The queries therefore leave the database file and the frames
// of its `-wal` file as they found them, whenever a [Store] opens,
// closes, or stops without a clean close.
//
// A query creates the `-wal` file and the `-shm` file that are
// missing, for example after a [Store] closed cleanly. Files that
// another user owns can stop a later [Open], so the close of the
// returned [*sql.DB] removes them:
//
//   - The close removes both files when the `-wal` file holds no
//     frame and no other connection to the database is open.
//   - The close keeps a `-wal` file that holds a frame, because the
//     frame is a write of a [Store]. That store can open both files
//     again.
//   - The close keeps both files while another connection is open.
//     When that connection belongs to another reader, the close of
//     that reader removes them.
//
// The close does not remove the files in these cases:
//
//   - The caller cannot write the database file. SQLite removes the
//     files only through a connection that can write that file.
//   - The caller cannot write the `-wal` file or the `-shm` file, for
//     example when a reader of another user created them. The close
//     cannot take the write lock, so it keeps both files.
//   - Readers of two processes close at the same moment. Each of them
//     can keep the files for the other. The next close of a reader
//     removes them.
//   - A [*sql.Rows], a [*sql.Tx], or a [*sql.Conn] of the returned
//     [*sql.DB] is still open. The close of the [*sql.DB] closes only
//     its idle connections before the cleanup, so the connection of
//     that value keeps both files. That connection closes later for
//     reads only, so it does not remove them either. Callers must
//     close those values before they close the [*sql.DB].
//
// SQLite removes the files in the close of the last connection, and
// that close checkpoints the frames that it finds. The close of the
// returned [*sql.DB] holds the write lock of the database from its
// check of the `-wal` file until that last close starts. A [Store]
// that commits and closes inside that last close, before SQLite locks
// the database file, leaves frames that the close checkpoints.
//
// SQLite follows the symbolic links in path and keeps the `-wal` and
// `-shm` files beside their target, so the close looks for them there.
func OpenReadOnly(ctx context.Context, path string) (*sql.DB, error) {
	// SQLite reports a missing file as SQLITE_CANTOPEN, which does not
	// say that the file is missing, so the check runs first.
	_, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}

	// SQLite follows symbolic links in the path and keeps the `-wal`
	// file beside the target, so the open and the close use the
	// target. The stat runs first because EvalSymlinks resolves the
	// empty path to the current directory.
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}

	connector, err := newReadOnlyConnector(resolved)
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}

	db := sql.OpenDB(connector)

	err = db.PingContext(ctx)
	if err != nil {
		closeDBIgnoringErr(db)

		return nil, fmt.Errorf("opening db: %w", err)
	}

	return db, nil
}

// readOnlyConnector opens the connections of the [*sql.DB] that
// [OpenReadOnly] returns. The close of the [*sql.DB] closes its idle
// connections and then calls [readOnlyConnector.Close], which removes
// the files that those connections created. A connection that a
// [*sql.Rows], a [*sql.Tx], or a [*sql.Conn] still holds stays open
// through that call.
//
// Create instances with [newReadOnlyConnector].
type readOnlyConnector struct {
	driver driver.Driver
	path   string
}

// newReadOnlyConnector creates a new [readOnlyConnector] for the
// database file at path. The path must hold no symbolic link.
func newReadOnlyConnector(path string) (*readOnlyConnector, error) {
	// The sql package gives out a registered driver only through a
	// handle. This handle never connects.
	handle, err := sql.Open("sqlite", fileURI(path)+readOnlyDSNQuery)
	if err != nil {
		return nil, fmt.Errorf("finding the driver: %w", err)
	}

	c := &readOnlyConnector{driver: handle.Driver(), path: path}

	err = handle.Close()
	if err != nil {
		return nil, fmt.Errorf("finding the driver: %w", err)
	}

	return c, nil
}

// Connect opens one connection with [readOnlyDSNQuery]. It implements
// [driver.Connector].
func (c *readOnlyConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.driver.Open(fileURI(c.path) + readOnlyDSNQuery)
	if err != nil {
		return nil, fmt.Errorf("connecting: %w", err)
	}

	return conn, nil
}

// Driver returns the SQLite driver. It implements [driver.Connector].
func (c *readOnlyConnector) Driver() driver.Driver {
	return c.driver
}

// Close removes the `-wal` and `-shm` files of the database when the
// `-wal` file holds no frame. It implements [io.Closer], which the
// close of the [*sql.DB] calls after it closes its idle connections.
func (c *readOnlyConnector) Close() error {
	return removeEmptyWAL(context.Background(), c.path)
}

// removeEmptyWAL removes the `-wal` and `-shm` files of the database
// file at path when the `-wal` file holds no frame and no other
// connection to the database is open. A connection of
// [readOnlyDSNQuery] leaves such files when it creates them.
//
// It returns without a connection to the database when the `-wal` file
// is missing or holds a frame. A `-wal` file with a frame belongs to a
// [Store], which can open the file again. The `-wal` file of an open
// [Store] holds the frame of its instance row. A reader that closes
// beside an open [Store] therefore does not take the write lock of the
// database.
func removeEmptyWAL(ctx context.Context, path string) error {
	empty, err := walIsEmpty(path)
	if err != nil || !empty {
		return err
	}

	walCleanupMu.Lock()
	defer walCleanupMu.Unlock()

	return removeWALIfEmpty(ctx, path)
}

// walIsEmpty reports whether the `-wal` file of the database file at
// path exists and holds no frame. SQLite writes the header of the file
// together with the first frame. A file of zero bytes therefore holds
// no frame.
func walIsEmpty(path string) (bool, error) {
	info, err := os.Stat(path + "-wal")

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("checking the write-ahead log: %w", err)
	}

	return info.Size() == 0, nil
}

// removeWALIfEmpty removes the `-wal` and `-shm` files of the database
// file at path when the `-wal` file holds no frame and no other
// connection to the database is open.
//
// SQLite removes the files when the last connection to the database
// closes, provided that the connection can write the database file.
// SQLite first checkpoints each frame of the `-wal` file into the
// database file, and a reader must not make that change. For that
// reason, removeWALIfEmpty opens two connections:
//
//   - The cleaner can write the database file, and it takes the write
//     lock of the database. No [Store] adds a frame while the cleaner
//     holds that lock, so the check of the `-wal` file that follows
//     stays true.
//   - The pin reads only. While the pin is open, the cleaner is not
//     the last connection, so its close neither checkpoints nor
//     removes a file. The close of the pin does neither in every case.
//
// With an empty `-wal` file, the pin closes first and the cleaner
// closes last. SQLite then removes both files unless a connection of
// another process is open. With a frame in the `-wal` file, the
// cleaner closes first and the pin closes last, so every file stays
// as it is. The same order applies when the cleaner does not get the
// write lock within the busy timeout, and when it cannot take the lock
// because the caller cannot write the `-wal` or `-shm` file.
func removeWALIfEmpty(ctx context.Context, path string) error {
	pin, err := openHeldConn(ctx, path, readOnlyDSNQuery)
	if err != nil {
		return fmt.Errorf("pinning the write-ahead log: %w", err)
	}

	// A connection holds its lock on the database file from its first
	// read of a database in the write-ahead log mode until it closes.
	// That lock is what stops the checkpoint of the cleaner.
	_, err = pin.conn.ExecContext(ctx, `SELECT COUNT(*) FROM sqlite_master`)
	if err != nil {
		return errors.Join(fmt.Errorf("pinning the write-ahead log: %w", err), pin.Close())
	}

	cleaner, err := openHeldConn(ctx, path, walCleanupDSNQuery)
	if err != nil {
		return errors.Join(fmt.Errorf("opening the cleanup connection: %w", err), pin.Close())
	}

	// The cleaner never commits. Its close ends the transaction, so
	// the cleaner holds the write lock until SQLite starts the close.
	_, err = cleaner.conn.ExecContext(ctx, `BEGIN IMMEDIATE`)

	// SQLite reports a `-wal` or `-shm` file that the caller cannot
	// write as SQLITE_READONLY. Neither connection can then remove the
	// files, so the cleanup keeps them as it does on a busy lock.
	switch {
	case isBusy(err) || isReadOnly(err):
		return errors.Join(cleaner.Close(), pin.Close())
	case err != nil:
		return errors.Join(fmt.Errorf("locking the database: %w", err), cleaner.Close(), pin.Close())
	}

	empty, err := walIsEmpty(path)
	if err != nil || !empty {
		return errors.Join(err, cleaner.Close(), pin.Close())
	}

	return errors.Join(pin.Close(), cleaner.Close())
}

// heldConn is one open connection to a database, together with the
// [*sql.DB] that owns it.
//
// Create instances with [openHeldConn].
type heldConn struct {
	db   *sql.DB
	conn *sql.Conn
}

// openHeldConn creates a new [heldConn] to the database file at path.
// The connection has the given query string of the data source name.
func openHeldConn(ctx context.Context, path, query string) (*heldConn, error) {
	db, err := sql.Open("sqlite", fileURI(path)+query)
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		closeDBIgnoringErr(db)

		return nil, fmt.Errorf("connecting: %w", err)
	}

	return &heldConn{db: db, conn: conn}, nil
}

// Close closes the connection, which ends its open transaction.
func (h *heldConn) Close() error {
	// The close of the [*sql.Conn] returns the connection to the idle
	// pool of the handle, and the close of the handle closes that
	// connection. The close of the connection therefore ends before
	// Close returns.
	err := errors.Join(h.conn.Close(), h.db.Close())
	if err != nil {
		return fmt.Errorf("closing db: %w", err)
	}

	return nil
}
