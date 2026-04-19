package status

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"text/tabwriter"
	"time"
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
	keepErr(renderLogs(w, r.Logs))

	if r.NonRoot && anyPermissionError(r) {
		_, err := fmt.Fprintln(w, "note: re-run as root for complete output")
		keepErr(err)
	}

	return firstErr
}

// newTabwriter returns a tabwriter configured for status output.
// Minimum column width of 1, tab width of 8, padding of 2, no flags.
func newTabwriter(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
}

func renderProcess(w io.Writer, s ProcessSection) error {
	tw := newTabwriter(w)

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
	tw := newTabwriter(w)

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
	tw := newTabwriter(w)

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
	tw := newTabwriter(w)

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

func renderLogs(w io.Writer, s LogsSection) error {
	if s.Skipped {
		return nil
	}

	err := renderLogTail(w, "ENVOY LOG", s.EnvoyLog, s.Requested)
	if err != nil {
		return err
	}

	return renderLogTail(w, "ENVOY ACCESS LOG", s.EnvoyAccessLog, s.Requested)
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
		r.Logs.EnvoyAccessLog.Err,
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
