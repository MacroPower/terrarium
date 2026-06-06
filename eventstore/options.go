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

// Option configures optional behavior of a [Store].
//
// The following options are available:
//
//   - [WithChanSize]
//   - [WithBatchSize]
//   - [WithBatchInterval]
//   - [WithLogger]
//   - [WithMode]
//   - [WithUID]
//   - [WithRetention]
type Option func(*storeOptions)

// storeOptions holds the resolved values configured by [Option] funcs.
type storeOptions struct {
	logger        *slog.Logger
	mode          Mode
	retention     Retention
	chanSize      int
	batchSize     int
	batchInterval time.Duration

	// uid is the UID to chown the database files to after open. A
	// negative value (the default) disables chowning.
	uid int
}

// Retention bounds the size of the events table. A zero MaxAge or
// MaxRows means that bound is not enforced.
type Retention struct {
	// MaxAge prunes events older than [time.Now]-MaxAge.
	MaxAge time.Duration

	// MaxRows caps the row count after each batch insert.
	MaxRows int64

	// PerSource caps row counts per [Source] before the global
	// MaxRows bound. A zero on a field means that source has no
	// per-source cap.
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
	defaultMaxAge        = 720 * time.Hour
	defaultMaxRows       = 1_000_000
)

func defaultStoreOptions() storeOptions {
	return storeOptions{
		logger:        slog.Default(),
		chanSize:      defaultChanSize,
		batchSize:     defaultBatchSize,
		batchInterval: defaultBatchInterval,
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

// WithMode records the terrarium mode (init or daemon) on the
// instance row. An [Option].
func WithMode(m Mode) Option {
	return func(o *storeOptions) {
		if m != "" {
			o.mode = m
		}
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
