package status_test

import (
	"bytes"
	"errors"
	"io/fs"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/status"
)

// reportFixture builds a baseline [status.Report] suitable for mutation
// in individual test cases.
func reportFixture() status.Report {
	return status.Report{
		Process: status.ProcessSection{
			Daemon: status.DaemonProcess{
				State:    status.DaemonRunning,
				PID:      1234,
				PIDFile:  "/run/terrarium/terrarium.pid",
				Uptime:   2*time.Hour + 14*time.Minute,
				UptimeOK: true,
			},
			Envoy: status.EnvoyProcess{
				State: status.DaemonRunning,
				PID:   1256,
			},
		},
		Firewall: status.FirewallSection{
			TableName:        "terrarium",
			TableFamily:      "inet",
			TablePresent:     true,
			GuardPresent:     true,
			ChainCount:       4,
			FQDNSetCount:     2,
			CatchAllSetCount: 1,
			ICMPFQDNSetCount: 0,
			IPv4Elements:     6,
			IPv6Elements:     2,
		},
		DNS: status.DNSSection{
			ListenAddrs: []string{"127.0.0.1:53", "[::1]:53"},
			State:       status.DNSListening,
		},
		Envoy: status.EnvoySection{
			ConfigPath: "/run/user/0/terrarium/envoy.yaml",
			Listeners:  []int{15001, 15080, 15443},
		},
		Logs: status.LogsSection{
			Requested: 2,
			EnvoyLog: status.LogTail{
				Path:  "/var/log/envoy.log",
				Lines: []string{"[info] started", "[warn] drain"},
			},
		},
	}
}

func render(t *testing.T, r status.Report) string {
	t.Helper()

	var buf bytes.Buffer

	require.NoError(t, status.Render(&buf, r))

	return buf.String()
}

func TestRenderHappyPath(t *testing.T) {
	t.Parallel()

	out := render(t, reportFixture())

	assert.Contains(t, out, "PROCESS")
	assert.Contains(t, out, "running (pid=1234, uptime=2h14m)")
	assert.Contains(t, out, "running (pid=1256)")
	assert.Contains(t, out, "FIREWALL")
	assert.Contains(t, out, "terrarium (inet, present)")
	assert.Contains(t, out, "guard:")
	assert.Contains(t, out, "chains:")
	assert.Contains(t, out, "4")
	assert.Contains(t, out, "DNS")
	assert.Contains(t, out, "listening")
	assert.Contains(t, out, "127.0.0.1:53, [::1]:53")
	assert.Contains(t, out, "ENVOY")
	assert.Contains(t, out, "15001, 15080, 15443")
	assert.Contains(t, out, "ENVOY LOG")
	assert.Contains(t, out, "  [info] started")
	assert.Contains(t, out, "  [warn] drain")
	assert.NotContains(t, out, "re-run as root")
}

func TestRenderDaemonDownFirewallPresent(t *testing.T) {
	t.Parallel()

	r := reportFixture()
	r.Process.Daemon.State = status.DaemonNotRunning
	r.Process.Daemon.Stale = true
	r.Process.Envoy = status.EnvoyProcess{}
	// Firewall rules persist even when daemon is down.
	r.DNS.State = status.DNSUnknown

	out := render(t, r)

	assert.Contains(t, out, "daemon:")
	assert.Contains(t, out, "not running (stale PID file: 1234)")
	assert.Contains(t, out, "table:")
	assert.Contains(t, out, "terrarium (inet, present)")
	assert.Contains(t, out, "chains:")
	assert.Contains(t, out, "state:")
	assert.Contains(t, out, "unknown")
}

func TestRenderPermissionErrors(t *testing.T) {
	t.Parallel()

	r := reportFixture()
	r.NonRoot = true
	r.Process.Err = fs.ErrPermission
	r.Process.Daemon.State = status.DaemonUnknown
	r.Firewall.Err = fs.ErrPermission
	r.Logs.EnvoyLog.Err = fs.ErrPermission
	r.Logs.EnvoyLog.Lines = nil

	out := render(t, r)

	assert.Contains(t, out, "permission denied")
	assert.Contains(t, out, "re-run as root for complete output")
}

func TestRenderEnvoyNotGenerated(t *testing.T) {
	t.Parallel()

	r := reportFixture()
	r.Envoy = status.EnvoySection{
		ConfigPath:   "/run/user/0/terrarium/envoy.yaml",
		NotGenerated: true,
	}

	out := render(t, r)

	assert.Contains(t, out, "(not generated)")
	assert.Contains(t, out, "listeners:")
	assert.Contains(t, out, "(none)")
}

func TestRenderTableAbsent(t *testing.T) {
	t.Parallel()

	r := reportFixture()
	r.Firewall.TablePresent = false
	r.Firewall.ChainCount = 0

	out := render(t, r)

	assert.Contains(t, out, "terrarium (inet, absent)")
	assert.NotContains(t, out, "chains:")
}

func TestRenderGuardAbsent(t *testing.T) {
	t.Parallel()

	r := reportFixture()
	r.Firewall.GuardPresent = false

	out := render(t, r)

	assert.Contains(t, out, "guard:")
	assert.Contains(t, out, "absent (host misconfigured)")
}

func TestRenderLogsSkipped(t *testing.T) {
	t.Parallel()

	r := reportFixture()
	r.Logs.Skipped = true

	out := render(t, r)

	assert.NotContains(t, out, "ENVOY LOG")
	assert.NotContains(t, out, "ENVOY ACCESS LOG")
}

func TestRenderProbeFailure(t *testing.T) {
	t.Parallel()

	r := reportFixture()
	r.DNS.State = status.DNSUnreachable
	r.DNS.Probed = true
	r.DNS.ProbeErr = errors.New("i/o timeout")

	out := render(t, r)

	assert.Contains(t, out, "unreachable")
	assert.Contains(t, out, "probe:")
	assert.Contains(t, out, "failed (i/o timeout)")
}

func TestRenderStatsHeartbeatSubsections(t *testing.T) {
	t.Parallel()

	r := reportFixture()
	r.Stats = status.StatsSection{
		Enabled:                  true,
		DBPath:                   "/var/lib/terrarium/events.db",
		LastEvent:                time.Now().Add(-3 * time.Second),
		Events24h:                1827,
		DBSizeBytes:              409600,
		EventStoreDropCount:      0,
		EventStoreLastWrite:      time.Now().Add(-time.Second),
		HeartbeatRecordedAt:      time.Now().Add(-5 * time.Second),
		NFLogKernelDrops:         0,
		NFLogParseErrors:         0,
		NFLogLastEvent:           time.Now().Add(-3 * time.Second),
		DNSCacheSize:             42,
		DNSCacheEvictions:        0,
		FirewallEvents1h:         24,
		FirewallNullDomain1h:     3,
		FirewallNullDomainRate1h: 0.125,
	}

	out := render(t, r)

	assert.Contains(t, out, "STATS")
	assert.Contains(t, out, "eventstore drops:")
	assert.Contains(t, out, "eventstore last write:")
	assert.Contains(t, out, "heartbeat:")
	assert.NotContains(t, out, "(stale)")
	assert.NotContains(t, out, "(none yet)")

	assert.Contains(t, out, "NFLOG")
	assert.Contains(t, out, "kernel drops:")
	assert.Contains(t, out, "parse errors:")

	assert.Contains(t, out, "DNS CACHE")
	assert.Contains(t, out, "entries:")
	assert.Contains(t, out, "evictions:")

	assert.Contains(t, out, "FIREWALL EVENTS (1h)")
	assert.Contains(t, out, "null domain rate:")
	assert.Contains(t, out, "12.5% (3 / 24)")
}

func TestRenderStatsHeartbeatNoneYet(t *testing.T) {
	t.Parallel()

	r := reportFixture()
	r.Stats = status.StatsSection{
		Enabled:   true,
		DBPath:    "/var/lib/terrarium/events.db",
		LastEvent: time.Now().Add(-3 * time.Second),
		Events24h: 1827,
	}

	out := render(t, r)

	assert.Contains(t, out, "(none yet)")
	assert.NotContains(t, out, "NFLOG")
	assert.NotContains(t, out, "DNS CACHE")
	assert.NotContains(t, out, "FIREWALL EVENTS")
}

func TestHumanDurationFormat(t *testing.T) {
	t.Parallel()

	// Indirect test via rendered output; humanDuration is unexported.
	cases := map[string]struct {
		uptime time.Duration
		want   string
	}{
		"45 seconds": {uptime: 45 * time.Second, want: "uptime=45s"},
		"5m12s":      {uptime: 5*time.Minute + 12*time.Second, want: "uptime=5m12s"},
		"2h14m":      {uptime: 2*time.Hour + 14*time.Minute, want: "uptime=2h14m"},
		"3d4h":       {uptime: 3*24*time.Hour + 4*time.Hour, want: "uptime=3d4h"},
		"zero":       {uptime: 0, want: "uptime=0s"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := reportFixture()
			r.Process.Daemon.Uptime = tc.uptime

			assert.Contains(t, render(t, r), tc.want)
		})
	}
}
