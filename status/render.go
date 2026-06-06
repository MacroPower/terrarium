package status

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"text/tabwriter"
	"time"

	"go.jacobcolvin.com/terrarium/eventstore"
)

// Render writes a sectioned plain-text representation of r to w. The
// output order is: process, firewall, dns, envoy, logs, optional
// footer. Each section is flushed through its own [tabwriter] so
// column widths do not bleed across sections. Returns any write
// error from the first failed flush; subsequent sections are still
// attempted so the caller sees a best-effort render.
func Render(w io.Writer, r Report) error {
	var firstErr error

	keepErr := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	keepErr(renderProcess(w, r.Process))
	keepErr(renderFirewall(w, r.Firewall))
	keepErr(renderDNS(w, r.DNS))
	keepErr(renderEnvoy(w, r.Envoy))
	keepErr(renderStats(w, r.Stats))
	keepErr(renderLogs(w, r.Logs))

	if r.NonRoot && anyPermissionError(r) {
		_, err := fmt.Fprintln(w, "note: re-run as root for complete output")
		keepErr(err)
	}

	return firstErr
}

// NewTabwriter returns a tabwriter configured for terrarium CLI
// output. Minimum column width of 1, tab width of 8, padding of 2,
// no flags. The status renderer and the stats CLI share this
// configuration so column rendering stays consistent.
func NewTabwriter(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
}

// errWriter wraps an [io.Writer] and remembers the first write error.
// The section renderers emit many formatted lines into a buffered
// [tabwriter]; threading an error check through every write would
// obscure the layout, so errWriter accumulates the first failure and
// the renderer reports it once via [errWriter.err].
type errWriter struct {
	w   io.Writer
	err error
}

// printf writes a formatted line and remembers the first error.
func (ew *errWriter) printf(format string, args ...any) {
	if ew.err != nil {
		return
	}

	_, err := fmt.Fprintf(ew.w, format, args...)
	if err != nil {
		ew.err = fmt.Errorf("writing status output: %w", err)
	}
}

// println writes a line and remembers the first error.
func (ew *errWriter) println(args ...any) {
	if ew.err != nil {
		return
	}

	_, err := fmt.Fprintln(ew.w, args...)
	if err != nil {
		ew.err = fmt.Errorf("writing status output: %w", err)
	}
}

// flushSection flushes the section tabwriter, emits a trailing blank
// line into w, and returns the first error seen while writing the
// section or flushing.
func flushSection(w io.Writer, tw *tabwriter.Writer, ew *errWriter) error {
	if ew.err != nil {
		return ew.err
	}

	err := tw.Flush()
	if err != nil {
		return fmt.Errorf("flushing status section: %w", err)
	}

	_, err = fmt.Fprintln(w)
	if err != nil {
		return fmt.Errorf("writing status output: %w", err)
	}

	return nil
}

func renderProcess(w io.Writer, s ProcessSection) error {
	tw := NewTabwriter(w)
	ew := &errWriter{w: tw}

	ew.println("PROCESS")

	switch s.Daemon.State {
	case DaemonRunning:
		uptime := "?"
		if s.Daemon.UptimeOK {
			uptime = humanDuration(s.Daemon.Uptime)
		}

		ew.printf("  daemon:\trunning (pid=%d, uptime=%s)\n", s.Daemon.PID, uptime)

	case DaemonNotRunning:
		switch {
		case s.Daemon.Stale:
			ew.printf("  daemon:\tnot running (stale PID file: %d)\n", s.Daemon.PID)
		case errors.Is(s.Err, fs.ErrNotExist):
			// Never reachable today (ENOENT maps to NotRunning
			// without Err), but left here so future changes to the
			// PID-file read path stay consistent.
			ew.printf("  daemon:\tnot running (no pid file at %s)\n", s.Daemon.PIDFile)
		default:
			ew.printf("  daemon:\tnot running (no pid file at %s)\n", s.Daemon.PIDFile)
		}

	case DaemonUnknown:
		switch {
		case errors.Is(s.Err, fs.ErrPermission):
			ew.printf("  daemon:\tunknown (pid file permission denied: %s)\n", s.Daemon.PIDFile)
		case s.Err != nil:
			ew.printf("  daemon:\tunknown (%s)\n", s.Err)
		default:
			ew.println("  daemon:\tunknown")
		}
	}

	if s.Daemon.State == DaemonRunning {
		switch s.Envoy.State {
		case DaemonRunning:
			ew.printf("  envoy:\trunning (pid=%d)\n", s.Envoy.PID)
		case DaemonUnknown:
			ew.println("  envoy:\tunknown (CONFIG_PROC_CHILDREN missing?)")
		case DaemonNotRunning:
			ew.println("  envoy:\tnot running")
		}
	}

	return flushSection(w, tw, ew)
}

func renderFirewall(w io.Writer, s FirewallSection) error {
	tw := NewTabwriter(w)
	ew := &errWriter{w: tw}

	ew.println("FIREWALL")

	if errors.Is(s.Err, fs.ErrPermission) {
		ew.println("  state:\tpermission denied")

		return flushSection(w, tw, ew)
	}

	if s.Err != nil {
		ew.printf("  state:\terror (%s)\n", s.Err)
	}

	tableState := "absent"
	if s.TablePresent {
		tableState = "present"
	}

	ew.printf("  table:\t%s (%s, %s)\n", s.TableName, s.TableFamily, tableState)

	if !s.GuardPresent {
		ew.println("  guard:\tabsent (host misconfigured)")
	} else {
		ew.println("  guard:\tpresent")
	}

	if s.TablePresent {
		ew.printf("  chains:\t%d\n", s.ChainCount)
		ew.printf("  fqdn sets:\t%d\n", s.FQDNSetCount)
		ew.printf("  catch-all sets:\t%d\n", s.CatchAllSetCount)
		ew.printf("  icmp fqdn sets:\t%d\n", s.ICMPFQDNSetCount)
		ew.printf("  set elements:\t%d (v4=%d, v6=%d)\n",
			s.IPv4Elements+s.IPv6Elements, s.IPv4Elements, s.IPv6Elements)
	}

	return flushSection(w, tw, ew)
}

func renderDNS(w io.Writer, s DNSSection) error {
	tw := NewTabwriter(w)
	ew := &errWriter{w: tw}

	ew.println("DNS")

	var state string

	switch s.State {
	case DNSListening:
		state = "listening"
	case DNSUnreachable:
		state = "unreachable"
	case DNSUnknown:
		state = "unknown"
	}

	ew.printf("  state:\t%s\n", state)

	if len(s.ListenAddrs) > 0 {
		ew.printf("  listen:\t%s\n", strings.Join(s.ListenAddrs, ", "))
	}

	if s.Probed {
		result := "ok"
		if s.ProbeErr != nil {
			result = fmt.Sprintf("failed (%s)", s.ProbeErr)
		}

		ew.printf("  probe:\t%s\n", result)
	}

	return flushSection(w, tw, ew)
}

func renderEnvoy(w io.Writer, s EnvoySection) error {
	tw := NewTabwriter(w)
	ew := &errWriter{w: tw}

	ew.println("ENVOY")

	switch {
	case s.NotGenerated:
		ew.printf("  config:\t%s (not generated)\n", s.ConfigPath)
		ew.println("  listeners:\t(none)")

	case s.Err != nil:
		ew.printf("  config:\t%s\n", s.ConfigPath)
		ew.printf("  error:\t%s\n", s.Err)

	default:
		ew.printf("  config:\t%s\n", s.ConfigPath)

		if len(s.Listeners) == 0 {
			ew.println("  listeners:\t(none)")
		} else {
			ew.printf("  listeners:\t%s\n", joinInts(s.Listeners))
		}
	}

	return flushSection(w, tw, ew)
}

// heartbeatStaleAfter is the staleness window past which the
// renderer flags a heartbeat row as stale. Twice the daemon's tick
// cadence so one missed tick is forgiven and two missed ticks raise
// the flag.
var heartbeatStaleAfter = 2 * eventstore.HeartbeatInterval

// renderStats prints the event store summary. When stats is disabled,
// the section heading is suppressed entirely so the output stays
// compact for the off-by-default case.
func renderStats(w io.Writer, s StatsSection) error {
	if !s.Enabled {
		return nil
	}

	tw := NewTabwriter(w)
	ew := &errWriter{w: tw}

	ew.println("STATS")
	ew.printf("  db:\t%s\n", s.DBPath)

	if s.Err != nil {
		ew.printf("  error:\t%s\n", s.Err)

		return flushSection(w, tw, ew)
	}

	if s.LastEvent.IsZero() {
		ew.println("  last event:\t(none)")
	} else {
		ew.printf("  last event:\t%s ago\n", humanDuration(time.Since(s.LastEvent)))
	}

	ew.printf("  events 24h:\t%d\n", s.Events24h)
	ew.printf("  db size:\t%d bytes\n", s.DBSizeBytes)

	writeHeartbeatLines(ew, s)

	err := flushSection(w, tw, ew)
	if err != nil {
		return err
	}

	if s.HeartbeatRecordedAt.IsZero() {
		return nil
	}

	err = renderNFLog(w, s)
	if err != nil {
		return err
	}

	err = renderDNSCache(w, s)
	if err != nil {
		return err
	}

	return renderFirewallEvents1h(w, s)
}

// writeHeartbeatLines emits the eventstore drops / last-write /
// heartbeat lines into tw. When the heartbeat row is absent only
// the "(none yet)" placeholder line is emitted; the caller suppresses
// the NFLOG / DNS CACHE / FIREWALL EVENTS sub-sections in that case.
func writeHeartbeatLines(ew *errWriter, s StatsSection) {
	if s.HeartbeatRecordedAt.IsZero() {
		ew.println("  heartbeat:\t(none yet)")

		return
	}

	ew.printf("  eventstore drops:\t%d\n", s.EventStoreDropCount)

	if s.EventStoreLastWrite.IsZero() {
		ew.println("  eventstore last write:\t(none)")
	} else {
		ew.printf("  eventstore last write:\t%s ago\n",
			humanDuration(time.Since(s.EventStoreLastWrite)))
	}

	hbAgo := time.Since(s.HeartbeatRecordedAt)
	if hbAgo > heartbeatStaleAfter {
		ew.printf("  heartbeat:\t%s ago (stale)\n", humanDuration(hbAgo))

		return
	}

	ew.printf("  heartbeat:\t%s ago\n", humanDuration(hbAgo))
}

// renderNFLog prints the NFLOG sub-section (kernel drops, parse
// errors, last event) of [renderStats].
func renderNFLog(w io.Writer, s StatsSection) error {
	tw := NewTabwriter(w)
	ew := &errWriter{w: tw}

	ew.println("NFLOG")
	ew.printf("  kernel drops:\t%d\n", s.NFLogKernelDrops)
	ew.printf("  parse errors:\t%d\n", s.NFLogParseErrors)

	if s.NFLogLastEvent.IsZero() {
		ew.println("  last event:\t(none)")
	} else {
		ew.printf("  last event:\t%s ago\n",
			humanDuration(time.Since(s.NFLogLastEvent)))
	}

	return flushSection(w, tw, ew)
}

// renderDNSCache prints the DNS CACHE sub-section (entries,
// evictions) of [renderStats].
func renderDNSCache(w io.Writer, s StatsSection) error {
	tw := NewTabwriter(w)
	ew := &errWriter{w: tw}

	ew.println("DNS CACHE")
	ew.printf("  entries:\t%d\n", s.DNSCacheSize)
	ew.printf("  evictions:\t%d\n", s.DNSCacheEvictions)

	return flushSection(w, tw, ew)
}

// renderFirewallEvents1h prints the FIREWALL EVENTS (1h)
// sub-section of [renderStats].
func renderFirewallEvents1h(w io.Writer, s StatsSection) error {
	tw := NewTabwriter(w)
	ew := &errWriter{w: tw}

	ew.println("FIREWALL EVENTS (1h)")
	ew.printf("  null domain rate:\t%.1f%% (%d / %d)\n",
		s.FirewallNullDomainRate1h*100, s.FirewallNullDomain1h, s.FirewallEvents1h)

	return flushSection(w, tw, ew)
}

func renderLogs(w io.Writer, s LogsSection) error {
	if s.Skipped {
		return nil
	}

	return renderLogTail(w, "ENVOY LOG", s.EnvoyLog, s.Requested)
}

func renderLogTail(w io.Writer, heading string, t LogTail, requested int) error {
	ew := &errWriter{w: w}

	ew.printf("%s (%s, last %d)\n", heading, t.Path, requested)

	switch {
	case errors.Is(t.Err, fs.ErrNotExist):
		ew.println("  (no log file yet)")
	case errors.Is(t.Err, fs.ErrPermission):
		ew.println("  (permission denied)")
	case t.Err != nil:
		ew.printf("  (error: %s)\n", t.Err)
	case len(t.Lines) == 0:
		ew.println("  (empty)")
	default:
		for _, line := range t.Lines {
			ew.printf("  %s\n", line)
		}
	}

	ew.println()

	return ew.err
}

// anyPermissionError reports whether any section recorded an error
// that wraps [fs.ErrPermission], so the renderer can hint at re-run
// as root.
func anyPermissionError(r Report) bool {
	errs := []error{
		r.Process.Err,
		r.Firewall.Err,
		r.DNS.Err,
		r.Envoy.Err,
		r.Logs.EnvoyLog.Err,
	}

	for _, e := range errs {
		if errors.Is(e, fs.ErrPermission) {
			return true
		}
	}

	return false
}

// joinInts formats a list of ports as a comma-separated string.
func joinInts(ps []int) string {
	var b strings.Builder

	for i, p := range ps {
		if i > 0 {
			b.WriteString(", ")
		}

		fmt.Fprintf(&b, "%d", p)
	}

	return b.String()
}

// humanDuration formats d in the most natural unit breakdown:
// "3d4h", "2h14m", "5m12s", "45s". Negative or zero durations render
// as "0s".
func humanDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}

	const (
		day    = 24 * time.Hour
		hour   = time.Hour
		minute = time.Minute
		sec    = time.Second
	)

	switch {
	case d >= day:
		return fmt.Sprintf("%dd%dh", d/day, (d%day)/hour)
	case d >= hour:
		return fmt.Sprintf("%dh%dm", d/hour, (d%hour)/minute)
	case d >= minute:
		return fmt.Sprintf("%dm%ds", d/minute, (d%minute)/sec)
	default:
		return fmt.Sprintf("%ds", d/sec)
	}
}
