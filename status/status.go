package status

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"go.jacobcolvin.com/terrarium/config"
)

// Options controls what [Collect] gathers.
type Options struct {
	// PIDFile is the path to the daemon PID file. Required.
	PIDFile string

	// ConfigPath is the terrarium YAML config path. Used to resolve
	// log file paths when the YAML overrides the CLI defaults. When
	// empty or unreadable, the fallback paths are used.
	ConfigPath string

	// EnvoyConfigPath is the path to the generated Envoy bootstrap
	// YAML. Parsed to determine listener ports.
	EnvoyConfigPath string

	// EnvoyLogPath is the fallback path for the Envoy process log
	// when the YAML config does not override it.
	EnvoyLogPath string

	// LogLines is the number of lines to tail from each log file.
	// Values <= 0 produce empty log sections but a heading is still
	// rendered.
	LogLines int

	// NoLogs disables log tailing entirely. The [LogsSection]
	// reports Skipped = true and the renderer suppresses the
	// heading.
	NoLogs bool

	// ProbeDNS enables an active DNS probe that sends a minimal A
	// query to the proxy. Off by default because probes pollute the
	// access log an operator is likely reading to diagnose issues.
	ProbeDNS bool
}

// Report is the aggregated result of one [Collect] call.
type Report struct {
	Process  ProcessSection
	Firewall FirewallSection
	DNS      DNSSection
	Envoy    EnvoySection
	Stats    StatsSection
	Logs     LogsSection

	// NonRoot is true when [Collect] ran as a non-root user. The
	// renderer uses this flag together with per-section permission
	// errors to emit a helpful footer.
	NonRoot bool
}

// DaemonState enumerates the observable liveness of the terrarium
// daemon process.
type DaemonState int

// Daemon state values. The zero value is [DaemonUnknown] so that a
// report constructed without any process check is never mistaken for
// a running daemon.
const (
	// DaemonUnknown means liveness could not be determined (for
	// example, the PID file was unreadable due to permissions).
	DaemonUnknown DaemonState = iota

	// DaemonRunning means the PID file was readable and signal 0
	// succeeded against the recorded PID.
	DaemonRunning

	// DaemonNotRunning means the PID file was missing, or the
	// recorded PID did not accept signal 0 (stale PID file).
	DaemonNotRunning
)

// ProcessSection holds the daemon and Envoy process observations.
type ProcessSection struct {
	Daemon DaemonProcess
	Envoy  EnvoyProcess
	Err    error
}

// DaemonProcess describes the state of the daemon process itself.
type DaemonProcess struct {
	// PIDFile is the path [Collect] tried to read.
	PIDFile string

	// PID is the value read from PIDFile when the read succeeded.
	PID int

	// Uptime is the process uptime derived from /proc/<pid>/stat and
	// /proc/uptime. Consult UptimeOK before rendering.
	Uptime time.Duration

	// State is the liveness outcome.
	State DaemonState

	// UptimeOK distinguishes an honest zero from an unknown uptime.
	UptimeOK bool

	// Stale is set when the PID file existed and parsed cleanly but
	// signal 0 failed, indicating the daemon died without cleaning
	// up its PID file.
	Stale bool
}

// EnvoyProcess describes the Envoy child discovered via
// /proc/<daemon-pid>/task/<daemon-pid>/children.
type EnvoyProcess struct {
	// State is [DaemonRunning] when the child PID's /proc/<pid>/comm
	// reads as "envoy", [DaemonUnknown] when the children file is
	// missing/empty (possibly CONFIG_PROC_CHILDREN not compiled
	// into the running kernel) or the child exited before we could
	// read comm, and [DaemonNotRunning] when the daemon itself is
	// not running (no child to look for).
	State DaemonState

	// PID is the Envoy child PID when State is [DaemonRunning].
	PID int

	// Err carries a non-permission error encountered while reading
	// the children or comm files. Permission errors surface on the
	// parent [ProcessSection.Err] instead.
	Err error
}

// FirewallSection summarizes the nftables state relevant to
// terrarium. Counts rather than rule dumps keep the output compact
// and avoid leaking the entire policy.
type FirewallSection struct {
	TableName        string
	TableFamily      string
	Err              error
	ChainCount       int
	FQDNSetCount     int
	CatchAllSetCount int
	ICMPFQDNSetCount int
	IPv4Elements     int
	IPv6Elements     int
	TablePresent     bool
	GuardPresent     bool
}

// DNSState enumerates the observed state of the DNS proxy.
type DNSState int

// DNS state values.
const (
	// DNSUnknown means the daemon's liveness could not be confirmed,
	// so the in-process DNS proxy's state is unknown.
	DNSUnknown DNSState = iota

	// DNSListening means the daemon is confirmed alive, so the
	// in-process DNS proxy must be bound.
	DNSListening

	// DNSUnreachable means --probe-dns was set and the probe failed.
	DNSUnreachable
)

// DNSSection describes the DNS proxy listen state.
type DNSSection struct {
	// ListenAddrs lists the bind addresses the proxy uses under the
	// current IPv6 state. Always contains at least one entry when
	// [Collect] succeeds.
	ListenAddrs []string

	// ProbeErr carries the active probe error when Probed is true
	// and the probe failed.
	ProbeErr error

	// Err carries any error encountered while inspecting system
	// state (e.g., reading /proc/sys/net/ipv6). Soft failures do
	// not populate this field; the collector falls back to the
	// "IPv6 enabled" default instead.
	Err error

	// State is the best observed state given the daemon check and
	// optional active probe.
	State DNSState

	// Probed is true when an active probe was attempted, regardless
	// of success. Separates "did not probe" from "probe succeeded".
	Probed bool
}

// EnvoySection describes the Envoy bootstrap state.
type EnvoySection struct {
	// ConfigPath is the path [Collect] tried to read.
	ConfigPath string

	// Err carries the outcome of reading or parsing the bootstrap
	// config. An [fs.ErrNotExist] is not an error here -- it simply
	// means generate has not been run -- so the collector wraps
	// that case into a sentinel the renderer can special-case.
	Err error

	// Listeners lists the listener ports parsed from the bootstrap
	// YAML, deduplicated and sorted ascending. Ports rather than
	// address/port pairs keep the output compact, because the
	// listener's Address and AdditionalAddresses entries use the
	// same port.
	Listeners []int

	// NotGenerated is true when ConfigPath did not exist, so the
	// renderer can distinguish "not generated yet" from "generated
	// but unreadable".
	NotGenerated bool
}

// StatsSection summarizes the SQLite event store: the configured
// path, the most recent event timestamp, and the event count over
// the last 24 hours.
//
// Ingestion-health counters live on the running daemon's
// [eventstore.Store] / [nflog.Reader] / [dnscache.Cache]; the CLI
// reads them through the heartbeat row written into
// `instance_metrics` (see [eventstore.LatestHeartbeat]).
type StatsSection struct {
	// DBPath is the path the collector resolved from config and
	// XDG defaults. Empty when stats is disabled.
	DBPath string

	// Enabled mirrors [Config.StatsEnabled] so the renderer can
	// distinguish "disabled" from "enabled but unreadable".
	Enabled bool

	// Err carries any error encountered while reading the DB.
	Err error

	// LastEvent is the timestamp of the most recent event. Zero
	// when no events have been written. Sourced from
	// MAX(events.ts), which is set producer-side, so a healthy
	// daemon with no traffic will still report this as "old".
	LastEvent time.Time

	// HeartbeatRecordedAt is the wall-clock time of the most
	// recent heartbeat row for the current instance. Zero when no
	// heartbeat has been written yet (fresh daemon, never ticked).
	// The renderer uses [time.Since] against this to decide
	// staleness.
	HeartbeatRecordedAt time.Time

	// NFLogLastEvent is the most recent firewall event time as
	// recorded by the nflog reader.
	NFLogLastEvent time.Time

	// EventStoreLastWrite is [eventstore.Store.LastWriteTime] at
	// the moment the heartbeat fired.
	EventStoreLastWrite time.Time

	// NFLogKernelDrops is the cumulative kernel-side drop count
	// observed via FlagSeq gaps.
	NFLogKernelDrops uint64

	// NFLogParseErrors is the cumulative count of malformed
	// packets and undecodable prefixes.
	NFLogParseErrors uint64

	// DNSCacheEvictions is the cumulative count of qname-level
	// FIFO and IP-level LRU evictions.
	DNSCacheEvictions uint64

	// Events24h is the total event count in the last 24 hours.
	Events24h int64

	// DBSizeBytes is the on-disk size of the DB file, excluding
	// WAL/SHM siblings.
	DBSizeBytes int64

	// DNSCacheSize is the dnscache entry count at the moment the
	// heartbeat fired.
	DNSCacheSize int64

	// EventStoreDropCount is [eventstore.Store.DropCount] at the
	// moment the heartbeat fired.
	EventStoreDropCount int64

	// FirewallNullDomainRate1h is the fraction of `source =
	// firewall` events in the last hour with `domain IS NULL`.
	// Renderer formats as a percentage. Range [0, 1].
	FirewallNullDomainRate1h float64

	// FirewallNullDomain1h is the numerator behind
	// [FirewallNullDomainRate1h]: count of `source = firewall`
	// events in the last hour with `domain IS NULL`. Carried
	// alongside the rate so the renderer prints exact integers
	// instead of reconstructing them from `rate * total`.
	FirewallNullDomain1h int64

	// FirewallEvents1h is the denominator for
	// [FirewallNullDomainRate1h] (total firewall events in the
	// last hour). Surfaced so a 0/0 rate renders cleanly without a
	// divide-by-zero artifact.
	FirewallEvents1h int64
}

// LogsSection holds the tailed envoy process log. Access events are
// captured by the [Stats] event store, not a tailable log file.
type LogsSection struct {
	EnvoyLog LogTail

	// Requested is the number of lines [Collect] attempted to read
	// per log. Mirrors [Options.LogLines] after clamping to zero.
	Requested int

	// Skipped is true when [Options.NoLogs] was set, so the renderer
	// can suppress the heading entirely.
	Skipped bool
}

// LogTail holds the result of tailing a single log file.
type LogTail struct {
	Path  string
	Err   error
	Lines []string
}

// Collect runs every sub-collector and returns an aggregated
// [Report]. It never returns an error: every I/O failure is stored on
// the appropriate section's Err field so the renderer can still
// produce useful output when individual sources fail.
func Collect(ctx context.Context, opts Options) Report {
	r := Report{
		NonRoot: os.Getuid() != 0,
	}

	// Read terrarium config (best-effort) so log paths can be
	// resolved the same way the daemon resolves them.
	cfg, cfgErr := LoadConfig(ctx, opts.ConfigPath)

	r.Process = collectProcess(opts.PIDFile)
	r.Firewall = collectFirewall()
	r.DNS = collectDNS(opts, r.Process.Daemon.State)
	r.Envoy = collectEnvoy(opts.EnvoyConfigPath)
	r.Stats = collectStats(ctx, cfg)
	r.Logs = collectLogs(cfg, cfgErr, opts)

	return r
}

// LoadConfig reads and parses the terrarium YAML config at path.
// Missing files are not an error -- status must be useful before
// generate has been run -- so LoadConfig returns (nil, nil) for
// [fs.ErrNotExist]. Other errors (permissions, parse failures) are
// returned so callers can surface them on the appropriate section.
// The stats CLI uses it too so both surfaces fall back the same way.
func LoadConfig(ctx context.Context, path string) (*config.Config, error) {
	if path == "" {
		return nil, nil //nolint:nilnil // absent config is a valid state.
	}

	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path.
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil //nolint:nilnil // absent config is a valid state.
		}

		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	cfg, err := config.ParseConfig(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	return cfg, nil
}
