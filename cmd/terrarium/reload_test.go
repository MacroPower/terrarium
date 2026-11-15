//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/dnsproxy"
	"go.jacobcolvin.com/terrarium/dnstest"
	"go.jacobcolvin.com/terrarium/firewall"
)

func TestWritePIDFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "test.pid")

	err := writePIDFile(path)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	pid, err := strconv.Atoi(string(data))
	require.NoError(t, err)
	assert.Equal(t, os.Getpid(), pid)
}

func TestDaemonReloadRequiresRoot(t *testing.T) {
	t.Parallel()

	if os.Getuid() == 0 {
		t.Skip("test requires non-root")
	}

	usr := config.NewUser()
	err := DaemonReload(t.Context(), usr, "/nonexistent.pid")
	require.ErrorIs(t, err, ErrNotRoot)
}

func TestDaemonReloadInvalidConfig(t *testing.T) {
	t.Parallel()

	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	err := os.WriteFile(configPath, []byte("invalid: [yaml: {{{"), 0o644)
	require.NoError(t, err)

	usr := config.NewUser()
	usr.ConfigPath = configPath

	err = DaemonReload(t.Context(), usr, filepath.Join(dir, "test.pid"))
	assert.ErrorContains(t, err, "parsing config")
}

func TestDaemonReloadMissingPIDFile(t *testing.T) {
	t.Parallel()

	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	// Write a valid minimal config (empty egress = unrestricted).
	err := os.WriteFile(configPath, []byte("{}"), 0o644)
	require.NoError(t, err)

	usr := config.NewUser()
	usr.ConfigPath = configPath

	err = DaemonReload(t.Context(), usr, filepath.Join(dir, "nonexistent.pid"))
	assert.ErrorContains(t, err, "reading PID file")
}

func TestValidateStartupOnlyStatsChanges(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		bound boundStats
		cfg   *config.Config
		want  error
	}{
		"stats disabled, group differs, no error": {
			bound: boundStats{enabled: false, nflogGroup: 5000},
			cfg: &config.Config{
				Stats: &config.Stats{
					Enabled:  false,
					Firewall: &config.StatsFirewall{NFLogGroup: 6000},
				},
			},
			want: nil,
		},
		"stats enabled, group matches, no error": {
			bound: boundStats{enabled: true, nflogGroup: 5000},
			cfg: &config.Config{
				Stats: &config.Stats{
					Enabled:  true,
					Firewall: &config.StatsFirewall{NFLogGroup: 5000},
				},
			},
			want: nil,
		},
		"stats enabled, group changed, error": {
			bound: boundStats{enabled: true, nflogGroup: 5000},
			cfg: &config.Config{
				Stats: &config.Stats{
					Enabled:  true,
					Firewall: &config.StatsFirewall{NFLogGroup: 7000},
				},
			},
			want: ErrReloadNFLogGroupChanged,
		},
		"stats enabled, default vs explicit default match": {
			bound: boundStats{enabled: true, nflogGroup: config.DefaultStatsFirewallNFLogGroup},
			cfg: &config.Config{
				Stats: &config.Stats{Enabled: true},
			},
			want: nil,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := validateStartupOnlyStatsChanges(t.Context(), tt.bound, tt.cfg)
			if tt.want != nil {
				require.ErrorIs(t, err, tt.want)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDaemonReloadStalePID(t *testing.T) {
	t.Parallel()

	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	err := os.WriteFile(configPath, []byte("{}"), 0o644)
	require.NoError(t, err)

	pidPath := filepath.Join(dir, "test.pid")

	// Use PID 2^22-1 which is almost certainly not running.
	err = os.WriteFile(pidPath, []byte("4194303"), 0o644)
	require.NoError(t, err)

	usr := config.NewUser()
	usr.ConfigPath = configPath

	err = DaemonReload(t.Context(), usr, pidPath)
	require.ErrorIs(t, err, ErrDaemonNotRunning)
}

// TestDaemonReloadEndsDaemon checks the reload command against a
// daemon whose reload stops after it started to replace a running
// part. The command must wait for the outcome of the reload and
// return its error.
//
// The test process stands for the daemon. It records its own PID,
// and it handles the SIGHUP of the command as the daemon does.
func TestDaemonReloadEndsDaemon(t *testing.T) {
	t.Parallel()

	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0o644))

	usr := config.NewUser()
	usr.ConfigPath = configPath

	pidPath := filepath.Join(dir, "test.pid")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	recorder, err := newReloadRecorder(reloadStatusPath(pidPath))
	require.NoError(t, err)
	require.NoError(t, writePIDFile(pidPath))

	var finished atomic.Bool

	errIncomplete := errors.New("starting envoy")
	served := make(chan error, 1)
	ctx := context.WithoutCancel(t.Context())

	go func() {
		served <- serveReloads(ctx, sigCh, func(context.Context, string) {}, recorder,
			func(context.Context) error {
				// The reload takes several polls of the status, so a
				// command that does not wait for the outcome returns
				// before the reload finishes.
				time.Sleep(3 * reloadPollInterval)
				finished.Store(true)

				return errIncomplete
			},
			func(context.Context) {},
		)
	}()

	// The signal loop returns when the channel closes, also when the
	// command sent no signal.
	t.Cleanup(func() {
		signal.Stop(sigCh)
		close(sigCh)
		<-served
	})

	err = DaemonReload(t.Context(), usr, pidPath)

	assert.True(t, finished.Load(), "the command returned before the reload finished")
	require.ErrorIs(t, err, ErrReloadEndedDaemon)
	require.ErrorContains(t, err, errIncomplete.Error())
}

// TestReloadInfrastructureRejected checks a reload that cannot read
// or parse its config. The error must wrap [ErrReloadRejected], and
// the infra must stay as it was, so the daemon keeps running the
// previous config.
func TestReloadInfrastructureRejected(t *testing.T) {
	t.Parallel()

	// A nil content means that the config file does not exist.
	tests := map[string]struct {
		content []byte
	}{
		"missing config": {},
		"invalid config": {
			content: []byte("egress: [{{{"),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			usr := config.NewUser()
			usr.ConfigPath = filepath.Join(dir, "config.yaml")
			usr.EnvoyConfigPath = filepath.Join(dir, "envoy", "envoy.yaml")
			usr.CADir = filepath.Join(dir, "ca")
			usr.CertsDir = filepath.Join(dir, "certs")

			if tt.content != nil {
				require.NoError(t, os.WriteFile(usr.ConfigPath, tt.content, 0o644))
			}

			// The reload must stop before it reaches these parts. They
			// do not run, so a reload that stops them fails the test.
			envoyProc := &envoyProcess{}
			dnsProxy := &dnsproxy.Proxy{}

			inf := &infra{
				envoyProc:    envoyProc,
				dnsProxy:     dnsProxy,
				drainTimeout: 30 * time.Second,
			}

			err := reloadInfrastructure(t.Context(), usr, firewall.UIDs{VMMode: true}, inf)
			require.ErrorIs(t, err, ErrReloadRejected)

			assert.Same(t, envoyProc, inf.envoyProc)
			assert.Same(t, dnsProxy, inf.dnsProxy)
			assert.Nil(t, inf.conn)
			assert.Equal(t, 30*time.Second, inf.drainTimeout)
			assert.NoFileExists(t, usr.EnvoyConfigPath)
		})
	}
}

// TestReloadInfrastructureRejectedBeforeCAInstall checks a reload that
// changes a startup-only stats field when the CA directory holds a CA
// certificate. The Envoy that keeps running serves certificates of
// the CA that the trust store held before the reload. The reload must
// therefore reject the config before it installs the certificate.
//
// The reload must also reject the config before it makes the path of
// the Envoy bootstrap traversable. The directory above the bootstrap
// must therefore keep its mode.
func TestReloadInfrastructureRejectedBeforeCAInstall(t *testing.T) {
	t.Parallel()

	// Only the owner can enter the directory that holds the files of
	// the reload.
	dir := filepath.Join(t.TempDir(), "private")
	require.NoError(t, os.Mkdir(dir, 0o700))

	usr := config.NewUser()
	usr.ConfigPath = filepath.Join(dir, "config.yaml")
	usr.EnvoyConfigPath = filepath.Join(dir, "envoy", "envoy.yaml")
	usr.CADir = filepath.Join(dir, "ca")
	usr.CertsDir = filepath.Join(dir, "certs")

	content := `egress:
  - toFQDNs:
      - matchName: api.example.com
stats:
  enabled: true
  firewall:
    nflogGroup: 5001
`
	require.NoError(t, os.WriteFile(usr.ConfigPath, []byte(content), 0o644))

	// The directory of the test is part of the certificate, so no
	// other file on the host holds the same bytes.
	caCert := []byte("CA certificate of " + dir + "\n")

	require.NoError(t, os.MkdirAll(usr.CADir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(usr.CADir, "ca.pem"), caCert, 0o644))

	// The reload must stop before it reaches these parts. They do not
	// run, so a reload that stops them fails the test.
	envoyProc := &envoyProcess{}
	dnsProxy := &dnsproxy.Proxy{}

	inf := &infra{
		envoyProc:    envoyProc,
		dnsProxy:     dnsProxy,
		drainTimeout: 30 * time.Second,
		boundStats:   boundStats{enabled: true, nflogGroup: 5000},
	}

	err := reloadInfrastructure(t.Context(), usr, firewall.UIDs{VMMode: true}, inf)
	require.ErrorIs(t, err, ErrReloadRejected)
	require.ErrorIs(t, err, ErrReloadNFLogGroupChanged)

	assert.Same(t, envoyProc, inf.envoyProc)
	assert.Same(t, dnsProxy, inf.dnsProxy)
	assert.Nil(t, inf.conn)
	assert.Equal(t, 30*time.Second, inf.drainTimeout)

	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), "the reload changed the mode of %s", dir)

	// A user without write access to the trust store gets an install
	// error in place of the rejection. Root can write there, so also
	// check that neither installed copy holds the certificate.
	for _, path := range []string{caTrustStorePath, caContainerTrustPath} {
		installed, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		assert.NotEqual(t, string(caCert), string(installed), "the reload installed the CA certificate at %s", path)
	}
}

// TestRunReloadPhases checks which errors of a reload wrap
// [ErrReloadRejected]. The daemon keeps running after an error that
// wraps it, so an error from the replace phase must never wrap it.
//
// The test also checks that the reload discards what it generated
// only after an error from the replace phase. The daemon exits only
// then, and its next start must not reuse the generated configs.
func TestRunReloadPhases(t *testing.T) {
	t.Parallel()

	errPrepare := errors.New("prepare")
	errReplace := errors.New("replace")

	tests := map[string]struct {
		prepareErr   error
		replaceErr   error
		err          error
		wantRejected bool
		wantReplace  bool
		wantDiscard  bool
	}{
		"both phases succeed": {
			wantReplace: true,
		},
		"prepare stops the reload": {
			prepareErr:   errPrepare,
			err:          errPrepare,
			wantRejected: true,
		},
		"replace stops the reload": {
			replaceErr:  errReplace,
			err:         errReplace,
			wantReplace: true,
			wantDiscard: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			inputs := &reloadInputs{}

			var (
				got       *reloadInputs
				replaced  bool
				discarded bool
			)

			err := runReloadPhases(
				func() (*reloadInputs, error) {
					if tt.prepareErr != nil {
						return nil, tt.prepareErr
					}

					return inputs, nil
				},
				func(in *reloadInputs) error {
					replaced = true
					got = in

					return tt.replaceErr
				},
				func() {
					assert.True(t, replaced, "the reload discarded its configs before the replace phase")

					discarded = true
				},
			)

			if tt.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tt.err)
			}

			if tt.wantRejected {
				require.ErrorIs(t, err, ErrReloadRejected)
			} else {
				require.NotErrorIs(t, err, ErrReloadRejected)
			}

			assert.Equal(t, tt.wantReplace, replaced)
			assert.Equal(t, tt.wantDiscard, discarded)

			if tt.wantReplace {
				assert.Same(t, inputs, got)
			}
		})
	}
}

// TestRemoveEnvoyBootstrap checks that the removal deletes a
// bootstrap, accepts a bootstrap that does not exist, and reports a
// bootstrap that it cannot remove.
func TestRemoveEnvoyBootstrap(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// Creates the bootstrap at path. A nil create leaves the path
		// empty.
		create  func(t *testing.T, path string)
		wantErr bool
	}{
		"existing bootstrap": {
			create: func(t *testing.T, path string) {
				t.Helper()

				require.NoError(t, os.WriteFile(path, []byte("static_resources: {}\n"), 0o644))
			},
		},
		"missing bootstrap": {},
		"missing directory": {
			create: func(t *testing.T, path string) {
				t.Helper()

				require.NoError(t, os.Remove(filepath.Dir(path)))
			},
		},
		"bootstrap that it cannot remove": {
			// os.Remove does not remove a directory that holds a file.
			create: func(t *testing.T, path string) {
				t.Helper()

				require.NoError(t, os.Mkdir(path, 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(path, "file"), nil, 0o644))
			},
			wantErr: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := filepath.Join(t.TempDir(), "envoy")
			require.NoError(t, os.Mkdir(dir, 0o755))

			path := filepath.Join(dir, "envoy.yaml")

			if tt.create != nil {
				tt.create(t, path)
			}

			err := removeEnvoyBootstrap(path)
			if tt.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, "removing envoy bootstrap")
				assert.DirExists(t, path)

				return
			}

			require.NoError(t, err)
			assert.NoFileExists(t, path)
		})
	}
}

// TestReplaceDNSProxy checks that the infra names the DNS proxy that
// runs after replaceDNSProxy returns. The previous DNS proxy must
// have released its port before the replacement starts.
func TestReplaceDNSProxy(t *testing.T) {
	t.Parallel()

	errStart := errors.New("start")

	tests := map[string]struct {
		err       error
		hasBefore bool
	}{
		"replacement starts": {
			hasBefore: true,
		},
		"replacement does not start": {
			hasBefore: true,
			err:       errStart,
		},
		"no proxy before": {},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			upstream := dnstest.StartServer(t, "1.2.3.4")
			cfg := &config.Config{}

			inf := &infra{}

			var before *dnsproxy.Proxy

			if tt.hasBefore {
				before = dnstest.StartProxy(t, cfg, upstream)
				inf.dnsProxy = before

				requireDNSAnswer(t, before.Addr)
			}

			var after *dnsproxy.Proxy

			start := func() (*dnsproxy.Proxy, error) {
				if before != nil {
					requireUDPPortReleased(t, before.Addr)
				}

				if tt.err != nil {
					return nil, tt.err
				}

				after = dnstest.StartProxy(t, cfg, upstream)

				return after, nil
			}

			err := replaceDNSProxy(t.Context(), inf, start)

			t.Cleanup(func() {
				stopDNSProxy(t.Context(), after)
			})

			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				require.ErrorContains(t, err, "starting DNS proxy")

				// A nil proxy shows that no DNS proxy runs, so a
				// shutdown does not stop a proxy a second time.
				assert.Nil(t, inf.dnsProxy)

				return
			}

			require.NoError(t, err)
			require.Same(t, after, inf.dnsProxy)

			requireDNSAnswer(t, inf.dnsProxy.Addr)
		})
	}
}

// requireDNSAnswer fails the test unless the DNS server at addr
// answers an A query over UDP.
func requireDNSAnswer(t *testing.T, addr string) {
	t.Helper()

	client := &dns.Client{Net: "udp"}
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, addr)
	require.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
}

// TestReplaceEnvoy checks that the infra names the Envoy that runs
// after replaceEnvoy returns, and that the previous Envoy has exited
// before the replacement starts.
func TestReplaceEnvoy(t *testing.T) {
	t.Parallel()

	errStart := errors.New("start")

	tests := map[string]struct {
		err        error
		hasBefore  bool
		needsEnvoy bool
	}{
		"replacement starts": {
			hasBefore:  true,
			needsEnvoy: true,
		},
		"replacement does not start": {
			hasBefore:  true,
			needsEnvoy: true,
			err:        errStart,
		},
		"new config needs no envoy": {
			hasBefore: true,
		},
		"no envoy before": {
			needsEnvoy: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			inf := &infra{drainTimeout: 30 * time.Second}

			var before *envoyProcess

			if tt.hasBefore {
				before = startEnvoyStub(t, false)
				inf.envoyProc = before
			}

			var (
				after *envoyProcess
				start func() (*envoyProcess, error)
			)

			if tt.needsEnvoy {
				start = func() (*envoyProcess, error) {
					if before != nil {
						assert.True(t, envoyExited(before),
							"the previous envoy must have exited before the replacement starts")
					}

					if tt.err != nil {
						return nil, tt.err
					}

					after = startEnvoyStub(t, false)

					return after, nil
				}
			}

			err := replaceEnvoy(t.Context(), inf, 20*time.Second, start)

			t.Cleanup(func() {
				stopEnvoy(t.Context(), after, 30*time.Second)
			})

			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			} else {
				require.NoError(t, err)
			}

			if before != nil {
				require.True(t, envoyExited(before), "the previous envoy must have exited")
			}

			// A nil process shows that no Envoy runs, so a shutdown
			// does not signal a process that has exited.
			assert.Same(t, after, inf.envoyProc)
			assert.Equal(t, 20*time.Second, inf.drainTimeout)

			if after != nil {
				assert.False(t, envoyExited(after), "the replacement must still run")
			}
		})
	}
}
