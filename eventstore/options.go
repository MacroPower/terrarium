package eventstore

import (
	"log/slog"
	"time"
)

// Mode identifies the terrarium operational mode that opened a [Store].
// It is recorded on the corresponding `instances` row.
type Mode string

// Mode values.
const (
	// ModeInit is the per-container `terrarium init` mode.
	ModeInit Mode = "init"

	// ModeDaemon is the VM-wide `terrarium daemon` mode.
	ModeDaemon Mode = "daemon"

	// ModeProxy is the host forward-proxy `terrarium proxy` mode.
	ModeProxy Mode = "proxy"
)

// HasFirewall reports whether an instance of the mode runs the
// firewall, the firewall log, and the DNS cache. `terrarium daemon`
// and `terrarium init` run them, and `terrarium proxy` does not.
//
// `terrarium status` reports on an instance of such a mode, and
// [Reader.DefaultInstanceID] prefers one.
func (m Mode) HasFirewall() bool {
	return m == ModeDaemon || m == ModeInit
}

// Option configures optional behavior of a [Store].
//
// The following options are available:
//
//   - [WithChanSize]
//   - [WithBatchSize]
//   - [WithBatchInterval]
//   - [WithLogger]
//   - [WithMode]
//   - [WithInstanceName]
//   - [WithConfigPath]
//   - [WithUID]
//   - [WithRetention]
//   - [WithPruneInterval]
type Option func(*storeOptions)

// storeOptions holds the resolved values configured by [Option] funcs.
type storeOptions struct {
	logger        *slog.Logger
	mode          Mode
	instanceName  string
	configPath    string
	retention     Retention
	chanSize      int
	batchSize     int
	batchInterval time.Duration
	pruneInterval time.Duration

	// The UID to chown the database files to after open. A negative
	// value (the default) disables chowning.
	uid int
}

// Retention bounds the size of the events table and of the policies
// table. MaxAge bounds both tables, and MaxRows and PerSource bound
// only the events table. A zero MaxAge or MaxRows means that bound is
// not enforced.
type Retention struct {
	// MaxAge prunes events older than [time.Now]-MaxAge. It also
	// prunes each policy snapshot that another snapshot of the same
	// instance replaced before that time. See [Store.RecordPolicy].
	MaxAge time.Duration

	// MaxRows caps the number of events after each batch insert. It
	// does not count policy snapshots.
	MaxRows int64

	// PerSource caps the number of events of each [Source] before
	// the global MaxRows bound. A zero on a field means that source
	// has no per-source cap.
	PerSource PerSourceCaps
}

// PerSourceCaps is the row cap for each event [Source]. A zero leaves
// that source uncapped, subject only to the global [Retention.MaxRows];
// a positive value caps that source independently regardless of the
// global bound.
type PerSourceCaps struct {
	// Firewall caps rows where source = [SourceFirewall].
	Firewall int64

	// DNS caps rows where source = [SourceDNS].
	DNS int64

	// Envoy caps rows where source = [SourceEnvoy].
	Envoy int64
}

// Default option values.
const (
	defaultChanSize      = 1024
	defaultBatchSize     = 64
	defaultBatchInterval = 200 * time.Millisecond
	defaultPruneInterval = 60 * time.Second
	defaultMaxAge        = 720 * time.Hour
	defaultMaxRows       = 1_000_000
)

func defaultStoreOptions() storeOptions {
	return storeOptions{
		logger:        slog.Default(),
		chanSize:      defaultChanSize,
		batchSize:     defaultBatchSize,
		batchInterval: defaultBatchInterval,
		pruneInterval: defaultPruneInterval,
		mode:          ModeInit,
		uid:           -1,
		retention: Retention{
			MaxAge:  defaultMaxAge,
			MaxRows: defaultMaxRows,
		},
	}
}

// WithChanSize sets the size of the buffered channel between producers
// and the writer goroutine. An [Option].
func WithChanSize(n int) Option {
	return func(o *storeOptions) {
		if n > 0 {
			o.chanSize = n
		}
	}
}

// WithBatchSize sets the maximum number of events flushed per SQLite
// transaction. An [Option].
func WithBatchSize(n int) Option {
	return func(o *storeOptions) {
		if n > 0 {
			o.batchSize = n
		}
	}
}

// WithBatchInterval sets the maximum time the writer goroutine waits
// before flushing a partial batch. An [Option].
func WithBatchInterval(d time.Duration) Option {
	return func(o *storeOptions) {
		if d > 0 {
			o.batchInterval = d
		}
	}
}

// WithLogger sets the logger used for diagnostic messages. An [Option].
func WithLogger(l *slog.Logger) Option {
	return func(o *storeOptions) {
		if l != nil {
			o.logger = l
		}
	}
}

// WithMode records the terrarium mode (init, daemon, or proxy) on the
// instance row. An [Option].
func WithMode(m Mode) Option {
	return func(o *storeOptions) {
		if m != "" {
			o.mode = m
		}
	}
}

// WithInstanceName records a name on the instance row. Several
// processes can write one database, and a reader tells their
// instances apart by the name. `terrarium proxy` records its bind
// address and port. The default is no name. An [Option].
func WithInstanceName(name string) Option {
	return func(o *storeOptions) {
		o.instanceName = name
	}
}

// WithConfigPath records the path of the config file of the process
// on the instance row. The default is no path. An [Option].
func WithConfigPath(path string) Option {
	return func(o *storeOptions) {
		o.configPath = path
	}
}

// WithUID chowns the database file and its WAL/SHM siblings to the
// given UID after open so the unprivileged terrarium user can read
// committed-but-not-checkpointed data via the read-only `stats` CLI.
// Negative values disable chowning. An [Option].
func WithUID(uid int) Option {
	return func(o *storeOptions) {
		o.uid = uid
	}
}

// WithRetention sets the retention policy. A zero MaxAge or MaxRows
// disables the corresponding bound. An [Option].
func WithRetention(r Retention) Option {
	return func(o *storeOptions) {
		o.retention = r
	}
}

// WithPruneInterval sets the time between two runs of the pruner that
// enforces [Retention.MaxAge]. The default is 60 seconds. An [Option].
func WithPruneInterval(d time.Duration) Option {
	return func(o *storeOptions) {
		if d > 0 {
			o.pruneInterval = d
		}
	}
}
