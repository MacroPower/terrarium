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

func renderProcess(w io.Writer, s ProcessSection) error {
	tw := NewTabwriter(w)

	fmt.Fprintln(tw, "PROCESS")

	switch s.Daemon.State {
	case DaemonRunning:
		uptime := "?"
		if s.Daemon.UptimeOK {
			uptime = humanDuration(s.Daemon.Uptime)
		}

		fmt.Fprintf(tw, "  daemon:\trunning (pid=%d, uptime=%s)\n", s.Daemon.PID, uptime)
	case DaemonNotRunning:
		switch {
		case s.Daemon.Stale:
			fmt.Fprintf(tw, "  daemon:\tnot running (stale PID file: %d)\n", s.Daemon.PID)
		case errors.Is(s.Err, fs.ErrNotExist):
			// Never reachable today (ENOENT maps to NotRunning
			// without Err), but left here so future changes to the
			// PID-file read path stay consistent.
			fmt.Fprintf(tw, "  daemon:\tnot running (no pid file at %s)\n", s.Daemon.PIDFile)
		default:
			fmt.Fprintf(tw, "  daemon:\tnot running (no pid file at %s)\n", s.Daemon.PIDFile)
		}
	case DaemonUnknown:
		switch {
		case errors.Is(s.Err, fs.ErrPermission):
			fmt.Fprintf(tw, "  daemon:\tunknown (pid file permission denied: %s)\n", s.Daemon.PIDFile)
		case s.Err != nil:
			fmt.Fprintf(tw, "  daemon:\tunknown (%s)\n", s.Err)
		default:
			fmt.Fprintln(tw, "  daemon:\tunknown")
		}
	}

	if s.Daemon.State == DaemonRunning {
		switch s.Envoy.State {
		case DaemonRunning:
			fmt.Fprintf(tw, "  envoy:\trunning (pid=%d)\n", s.Envoy.PID)
		case DaemonUnknown:
			fmt.Fprintln(tw, "  envoy:\tunknown (CONFIG_PROC_CHILDREN missing?)")
		case DaemonNotRunning:
			fmt.Fprintln(tw, "  envoy:\tnot running")
		}
	}

	err := tw.Flush()
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(w)

	return err
}

func renderFirewall(w io.Writer, s FirewallSection) error {
	tw := NewTabwriter(w)

	fmt.Fprintln(tw, "FIREWALL")

	if errors.Is(s.Err, fs.ErrPermission) {
		fmt.Fprintln(tw, "  state:\tpermission denied")

		err := tw.Flush()
		if err != nil {
			return err
		}

		_, err = fmt.Fprintln(w)

		return err
	}

	if s.Err != nil {
		fmt.Fprintf(tw, "  state:\terror (%s)\n", s.Err)
	}

	tableState := "absent"
	if s.TablePresent {
		tableState = "present"
	}

	fmt.Fprintf(tw, "  table:\t%s (%s, %s)\n", s.TableName, s.TableFamily, tableState)

	if !s.GuardPresent {
		fmt.Fprintln(tw, "  guard:\tabsent (host misconfigured)")
	} else {
		fmt.Fprintln(tw, "  guard:\tpresent")
	}

	if s.TablePresent {
		fmt.Fprintf(tw, "  chains:\t%d\n", s.ChainCount)
		fmt.Fprintf(tw, "  fqdn sets:\t%d\n", s.FQDNSetCount)
		fmt.Fprintf(tw, "  catch-all sets:\t%d\n", s.CatchAllSetCount)
		fmt.Fprintf(tw, "  icmp fqdn sets:\t%d\n", s.ICMPFQDNSetCount)
		fmt.Fprintf(tw, "  set elements:\t%d (v4=%d, v6=%d)\n",
			s.IPv4Elements+s.IPv6Elements, s.IPv4Elements, s.IPv6Elements)
	}

	err := tw.Flush()
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(w)

	return err
}

func renderDNS(w io.Writer, s DNSSection) error {
	tw := NewTabwriter(w)

	fmt.Fprintln(tw, "DNS")

	var state string
	switch s.State {
	case DNSListening:
		state = "listening"
	case DNSUnreachable:
		state = "unreachable"
	case DNSUnknown:
		state = "unknown"
	}

	fmt.Fprintf(tw, "  state:\t%s\n", state)

	if len(s.ListenAddrs) > 0 {
		fmt.Fprintf(tw, "  listen:\t%s\n", strings.Join(s.ListenAddrs, ", "))
	}

	if s.Probed {
		result := "ok"
		if s.ProbeErr != nil {
			result = fmt.Sprintf("failed (%s)", s.ProbeErr)
		}

		fmt.Fprintf(tw, "  probe:\t%s\n", result)
	}

	err := tw.Flush()
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(w)

	return err
}

func renderEnvoy(w io.Writer, s EnvoySection) error {
	tw := NewTabwriter(w)

	fmt.Fprintln(tw, "ENVOY")

	switch {
	case s.NotGenerated:
		fmt.Fprintf(tw, "  config:\t%s (not generated)\n", s.ConfigPath)
		fmt.Fprintln(tw, "  listeners:\t(none)")
	case s.Err != nil:
		fmt.Fprintf(tw, "  config:\t%s\n", s.ConfigPath)
		fmt.Fprintf(tw, "  error:\t%s\n", s.Err)
	default:
		fmt.Fprintf(tw, "  config:\t%s\n", s.ConfigPath)

		if len(s.Listeners) == 0 {
			fmt.Fprintln(tw, "  listeners:\t(none)")
		} else {
			fmt.Fprintf(tw, "  listeners:\t%s\n", joinInts(s.Listeners))
		}
	}

	err := tw.Flush()
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(w)

	return err
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

	fmt.Fprintln(tw, "STATS")
	fmt.Fprintf(tw, "  db:\t%s\n", s.DBPath)

	if s.Err != nil {
		fmt.Fprintf(tw, "  error:\t%s\n", s.Err)

		err := tw.Flush()
		if err != nil {
			return err
		}

		_, err = fmt.Fprintln(w)

		return err
	}

	if s.LastEvent.IsZero() {
		fmt.Fprintln(tw, "  last event:\t(none)")
	} else {
		fmt.Fprintf(tw, "  last event:\t%s ago\n", humanDuration(time.Since(s.LastEvent)))
	}

	fmt.Fprintf(tw, "  events 24h:\t%d\n", s.Events24h)
	fmt.Fprintf(tw, "  db size:\t%d bytes\n", s.DBSizeBytes)

	writeHeartbeatLines(tw, s)

	err := tw.Flush()
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(w)
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
func writeHeartbeatLines(tw io.Writer, s StatsSection) {
	if s.HeartbeatRecordedAt.IsZero() {
		fmt.Fprintln(tw, "  heartbeat:\t(none yet)")
		return
	}

	fmt.Fprintf(tw, "  eventstore drops:\t%d\n", s.EventStoreDropCount)

	if s.EventStoreLastWrite.IsZero() {
		fmt.Fprintln(tw, "  eventstore last write:\t(none)")
	} else {
		fmt.Fprintf(tw, "  eventstore last write:\t%s ago\n",
			humanDuration(time.Since(s.EventStoreLastWrite)))
	}

	hbAgo := time.Since(s.HeartbeatRecordedAt)
	if hbAgo > heartbeatStaleAfter {
		fmt.Fprintf(tw, "  heartbeat:\t%s ago (stale)\n", humanDuration(hbAgo))
		return
	}

	fmt.Fprintf(tw, "  heartbeat:\t%s ago\n", humanDuration(hbAgo))
}

// renderNFLog prints the NFLOG sub-section (kernel drops, parse
// errors, last event) of [renderStats].
func renderNFLog(w io.Writer, s StatsSection) error {
	tw := NewTabwriter(w)

	fmt.Fprintln(tw, "NFLOG")
	fmt.Fprintf(tw, "  kernel drops:\t%d\n", s.NFLogKernelDrops)
	fmt.Fprintf(tw, "  parse errors:\t%d\n", s.NFLogParseErrors)

	if s.NFLogLastEvent.IsZero() {
		fmt.Fprintln(tw, "  last event:\t(none)")
	} else {
		fmt.Fprintf(tw, "  last event:\t%s ago\n",
			humanDuration(time.Since(s.NFLogLastEvent)))
	}

	err := tw.Flush()
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(w)

	return err
}

// renderDNSCache prints the DNS CACHE sub-section (entries,
// evictions) of [renderStats].
func renderDNSCache(w io.Writer, s StatsSection) error {
	tw := NewTabwriter(w)

	fmt.Fprintln(tw, "DNS CACHE")
	fmt.Fprintf(tw, "  entries:\t%d\n", s.DNSCacheSize)
	fmt.Fprintf(tw, "  evictions:\t%d\n", s.DNSCacheEvictions)

	err := tw.Flush()
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(w)

	return err
}

// renderFirewallEvents1h prints the FIREWALL EVENTS (1h)
// sub-section of [renderStats].
func renderFirewallEvents1h(w io.Writer, s StatsSection) error {
	tw := NewTabwriter(w)

	fmt.Fprintln(tw, "FIREWALL EVENTS (1h)")
	fmt.Fprintf(tw, "  null domain rate:\t%.1f%% (%d / %d)\n",
		s.FirewallNullDomainRate1h*100, s.FirewallNullDomain1h, s.FirewallEvents1h)

	err := tw.Flush()
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(w)

	return err
}

func renderLogs(w io.Writer, s LogsSection) error {
	if s.Skipped {
		return nil
	}

	return renderLogTail(w, "ENVOY LOG", s.EnvoyLog, s.Requested)
}

func renderLogTail(w io.Writer, heading string, t LogTail, requested int) error {
	_, err := fmt.Fprintf(w, "%s (%s, last %d)\n", heading, t.Path, requested)
	if err != nil {
		return err
	}

	switch {
	case errors.Is(t.Err, fs.ErrNotExist):
		_, err = fmt.Fprintln(w, "  (no log file yet)")
	case errors.Is(t.Err, fs.ErrPermission):
		_, err = fmt.Fprintln(w, "  (permission denied)")
	case t.Err != nil:
		_, err = fmt.Fprintf(w, "  (error: %s)\n", t.Err)
	case len(t.Lines) == 0:
		_, err = fmt.Fprintln(w, "  (empty)")
	default:
		for _, line := range t.Lines {
			_, err = fmt.Fprintf(w, "  %s\n", line)
			if err != nil {
				return err
			}
		}
	}

	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(w)

	return err
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
		day  = 24 * time.Hour
		hour = time.Hour
		min  = time.Minute
		sec  = time.Second
	)

	switch {
	case d >= day:
		return fmt.Sprintf("%dd%dh", d/day, (d%day)/hour)
	case d >= hour:
		return fmt.Sprintf("%dh%dm", d/hour, (d%hour)/min)
	case d >= min:
		return fmt.Sprintf("%dm%ds", d/min, (d%min)/sec)
	default:
		return fmt.Sprintf("%ds", d/sec)
	}
}
