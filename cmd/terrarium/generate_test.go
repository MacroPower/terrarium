package main

import (
	"bytes"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/accesslog"
	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/envoy"
)

func TestGenerate(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		setup   func(t *testing.T) *config.User
		err     error
		wantMsg string
	}{
		"missing file": {
			setup: func(t *testing.T) *config.User {
				t.Helper()

				return &config.User{
					ConfigPath:      "/nonexistent/path/config.yaml",
					CertsDir:        t.TempDir(),
					CADir:           t.TempDir(),
					EnvoyConfigPath: filepath.Join(t.TempDir(), "envoy.yaml"),
				}
			},
			wantMsg: "reading config",
		},
		"invalid YAML": {
			setup: func(t *testing.T) *config.User {
				t.Helper()

				dir := t.TempDir()
				path := filepath.Join(dir, "config.yaml")
				require.NoError(t, os.WriteFile(path, []byte(":\n  :\n  - [invalid"), 0o644))

				return &config.User{
					ConfigPath:      path,
					CertsDir:        t.TempDir(),
					CADir:           t.TempDir(),
					EnvoyConfigPath: filepath.Join(t.TempDir(), "envoy.yaml"),
				}
			},
			wantMsg: "parsing config",
		},
		"empty FQDN selector": {
			setup: func(t *testing.T) *config.User {
				t.Helper()

				dir := t.TempDir()
				path := filepath.Join(dir, "config.yaml")
				cfg := "egress:\n  - toFQDNs:\n      - {}\n"
				require.NoError(t, os.WriteFile(path, []byte(cfg), 0o644))

				return &config.User{
					ConfigPath:      path,
					CertsDir:        t.TempDir(),
					CADir:           t.TempDir(),
					EnvoyConfigPath: filepath.Join(t.TempDir(), "envoy.yaml"),
				}
			},
			err:     config.ErrFQDNSelectorEmpty,
			wantMsg: "parsing config",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			usr := tt.setup(t)

			cfg, err := Generate(t.Context(), usr, false)
			require.Error(t, err)
			require.Nil(t, cfg)
			require.ErrorContains(t, err, tt.wantMsg)

			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			}
		})
	}
}

// icmpFamilyMismatchPolicy is a policy whose only egress rule has an
// IPv6 ICMP field and an IPv4 CIDR, so the rule allows nothing.
const icmpFamilyMismatchPolicy = "egress:\n" +
	"  - toCIDR:\n" +
	"      - 10.0.0.0/8\n" +
	"    icmps:\n" +
	"      - fields:\n" +
	"          - type: 128\n" +
	"            family: IPv6\n"

// icmpFamilyMismatchWarning is the text that every warning about a
// rule of [icmpFamilyMismatchPolicy] holds.
const icmpFamilyMismatchWarning = "policy: every icmps field of the rule has another address family " +
	"than the destinations of the rule, so the rule allows nothing"

// TestParseConfigICMPFamilyMismatch replaces the default logger, which
// is incompatible with t.Parallel().
//
//nolint:paralleltest // see comment above.
func TestParseConfigICMPFamilyMismatch(t *testing.T) {
	const msg = "policy: every icmps field of the rule has another address family"

	tests := map[string]struct {
		yaml string
		// want lists the parts of each warning in the log, in order.
		// Without entries, the test expects no warning.
		want [][]string
	}{
		"egress rule": {
			yaml: icmpFamilyMismatchPolicy,
			want: [][]string{{
				icmpFamilyMismatchWarning,
				"list=egress", "rule_index=0", "icmp_family=IPv6", "cidr_family=IPv4",
			}},
		},
		"egressDeny rule": {
			yaml: "egress:\n" +
				"  - toCIDR:\n" +
				"      - 10.0.0.0/8\n" +
				"egressDeny:\n" +
				"  - toCIDR:\n" +
				"      - 10.1.0.0/16\n" +
				"  - toEntities:\n" +
				"      - world-ipv6\n" +
				"    icmps:\n" +
				"      - fields:\n" +
				"          - type: EchoRequest\n",
			want: [][]string{{
				"so the rule denies nothing",
				"list=egressDeny", "rule_index=1", "icmp_family=IPv4", "cidr_family=IPv6",
			}},
		},
		"one warning for each rule": {
			yaml: icmpFamilyMismatchPolicy +
				"  - toCIDR:\n" +
				"      - 2001:db8::/32\n" +
				"    icmps:\n" +
				"      - fields:\n" +
				"          - type: EchoRequest\n" +
				"            family: IPv4\n",
			want: [][]string{
				{"list=egress", "rule_index=0", "icmp_family=IPv6", "cidr_family=IPv4"},
				{"list=egress", "rule_index=1", "icmp_family=IPv4", "cidr_family=IPv6"},
			},
		},
		"one field has the family of a CIDR": {
			yaml: "egress:\n" +
				"  - toCIDR:\n" +
				"      - 10.0.0.0/8\n" +
				"    icmps:\n" +
				"      - fields:\n" +
				"          - type: EchoRequest\n" +
				"            family: IPv4\n" +
				"          - type: EchoRequest\n" +
				"            family: IPv6\n",
		},
		"rule without CIDRs": {
			yaml: "egress:\n" +
				"  - icmps:\n" +
				"      - fields:\n" +
				"          - type: EchoRequest\n" +
				"            family: IPv6\n",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			logs := captureLogs(t)

			cfg, err := parseConfig(t.Context(), []byte(tt.yaml))
			require.NoError(t, err)
			require.NotNil(t, cfg)

			var warnings []string

			for line := range strings.Lines(logs.String()) {
				if strings.Contains(line, msg) {
					warnings = append(warnings, line)
				}
			}

			require.Len(t, warnings, len(tt.want))

			for i, parts := range tt.want {
				assert.Contains(t, warnings[i], "level=WARN")

				for _, part := range parts {
					assert.Contains(t, warnings[i], part)
				}
			}
		})
	}
}

// TestParseConfigInvalid replaces the default logger, which is
// incompatible with t.Parallel().
//
//nolint:paralleltest // see comment above.
func TestParseConfigInvalid(t *testing.T) {
	logs := captureLogs(t)

	// The icmps of the rule have another family than its CIDR, and
	// validation rejects the rule for its toPorts.
	cfg, err := parseConfig(t.Context(), []byte(icmpFamilyMismatchPolicy+
		"    toPorts:\n"+
		"      - ports:\n"+
		"          - port: \"443\"\n"))
	require.ErrorIs(t, err, config.ErrICMPWithToPorts)
	assert.Nil(t, cfg)
	assert.NotContains(t, logs.String(), "policy: every icmps field")
}

// TestGenerateWarnsICMPFamilyMismatch replaces the default logger,
// which is incompatible with t.Parallel().
//
//nolint:paralleltest // see comment above.
func TestGenerateWarnsICMPFamilyMismatch(t *testing.T) {
	logs := captureLogs(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(icmpFamilyMismatchPolicy), 0o644))

	usr := &config.User{
		ConfigPath:      path,
		CertsDir:        filepath.Join(dir, "certs"),
		CADir:           filepath.Join(dir, "ca"),
		EnvoyConfigPath: filepath.Join(dir, "envoy.yaml"),
	}

	cfg, err := Generate(t.Context(), usr, false)
	require.NoError(t, err)
	assert.Empty(t, cfg.ResolveICMPRules(), "the rule must allow nothing")

	out := logs.String()
	assert.Contains(t, out, "level=WARN")
	assert.Contains(t, out, icmpFamilyMismatchWarning)
	assert.Contains(t, out, "list=egress rule_index=0 icmp_family=IPv6 cidr_family=IPv4")
}

func TestGenerateDeterministicOutput(t *testing.T) {
	t.Parallel()

	yamlCfg := []byte("egress:\n" +
		"  - toPorts:\n" +
		"      - ports:\n" +
		"          - port: \"443\"\n" +
		"          - port: \"80\"\n" +
		"    toFQDNs:\n" +
		"      - matchName: api.example.com\n" +
		"      - matchName: cdn.example.com\n" +
		"  - toPorts:\n" +
		"      - ports:\n" +
		"          - port: \"8080\"\n" +
		"    toFQDNs:\n" +
		"      - matchPattern: \"*.example.org\"\n")

	cfg, err := config.ParseConfig(t.Context(), yamlCfg)
	require.NoError(t, err)

	const iterations = 10

	envoyResults := make([]string, iterations)

	for i := range iterations {
		conf, err := GenerateEnvoyFromConfig(t.Context(), cfg, "", "", false)
		require.NoError(t, err)

		envoyResults[i] = conf
	}

	for i := 1; i < iterations; i++ {
		assert.Equal(t, envoyResults[0], envoyResults[i], "envoy config differs on iteration %d", i)
	}
}

func egressRules(rules ...config.EgressRule) *[]config.EgressRule {
	return &rules
}

// lockedBuffer is a [bytes.Buffer] that goroutines can share.
type lockedBuffer struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

// Write appends p to the buffer.
func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

// String returns the buffered text.
func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// captureLogs sends the default [slog.Logger] to a buffer until the
// test ends, and returns the buffer. The default logger is process
// state, so the calling test must not run in parallel.
//
// [slog.SetDefault] also points the standard log package at the new
// handler. It does not undo that redirection when it restores the
// built-in default logger, which writes through the log package. The
// cleanup therefore restores the writer and the flags of the log
// package too.
func captureLogs(t *testing.T) *lockedBuffer {
	t.Helper()

	buf := &lockedBuffer{}
	prev := slog.Default()
	prevWriter, prevFlags := log.Writer(), log.Flags()

	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})

	return buf
}

// TestCaptureLogsRestoresLoggers replaces the default logger, which is
// incompatible with t.Parallel().
//
//nolint:paralleltest // see comment above.
func TestCaptureLogsRestoresLoggers(t *testing.T) {
	wantLogger := slog.Default()
	wantWriter, wantFlags := log.Writer(), log.Flags()

	t.Run("capture", func(t *testing.T) {
		logs := captureLogs(t)

		slog.InfoContext(t.Context(), "during capture")
		assert.Contains(t, logs.String(), "during capture")
	})

	// Later tests in the package log through the default logger, so
	// their output must reach the original writer again.
	assert.Same(t, wantLogger, slog.Default())
	assert.Same(t, wantWriter, log.Writer())
	assert.Equal(t, wantFlags, log.Flags())
}

// TestNewALSConfig replaces the default logger, which is incompatible
// with t.Parallel().
//
//nolint:paralleltest // see comment above.
func TestNewALSConfig(t *testing.T) {
	longSocket := "/" + strings.Repeat("a", accesslog.MaxSocketPathLen)

	tests := map[string]struct {
		stats       *config.Stats
		wantEnabled bool
		wantWarning bool
	}{
		"stats disabled": {
			stats: &config.Stats{Socket: longSocket},
		},
		"stats enabled": {
			stats:       &config.Stats{Enabled: true},
			wantEnabled: true,
		},
		"socket past the platform limit": {
			stats:       &config.Stats{Enabled: true, Socket: longSocket},
			wantWarning: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			logs := captureLogs(t)

			cfg := &config.Config{Stats: tt.stats}
			socket := cfg.StatsSocket(config.DefaultStatsSocket)

			als := newALSConfig(t.Context(), cfg, socket)

			assert.Equal(t, tt.wantEnabled, als.enabled)
			assert.Equal(t, socket, als.socket)

			if !tt.wantWarning {
				assert.NotContains(t, logs.String(), "socket path too long")

				return
			}

			out := logs.String()
			assert.Contains(t, out, "level=WARN")
			assert.Contains(t, out, "stats: socket path too long, envoy access loggers omitted")
			assert.Contains(t, out, "socket="+longSocket)
			assert.Contains(t, out, "limit is "+strconv.Itoa(accesslog.MaxSocketPathLen)+" bytes")
		})
	}
}

func TestGenerateEnvoyFromConfig(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg          *config.Config
		certsDir     string
		caBundlePath string
		want         []string
		notWant      []string
		err          error
	}{
		"basic TLS and HTTP": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "github.com"}, {MatchName: "golang.org"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			want: []string{
				"tls_passthrough", "http_forward",
				"github.com", "golang.org",
				"dynamic_forward_proxy_cluster",
			},
		},
		"with tcp forwards": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "golang.org"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				}),
				TCPForwards: []config.TCPForward{{Port: 22, Host: "github.com"}},
			},
			want: []string{
				"tls_passthrough", "http_forward",
				"tcp_forward_22", "github.com",
			},
		},
		"multiple tcp forwards": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				}),
				TCPForwards: []config.TCPForward{
					{Port: 22, Host: "github.com"},
					{Port: 3306, Host: "db.example.com"},
				},
			},
			want: []string{
				"tcp_forward_22", "tcp_forward_3306",
				"github.com", "db.example.com",
			},
		},
		"extra ports with tcp forwards": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "github.com"}, {MatchName: "golang.org"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{
						{Port: "80"}, {Port: "443"}, {Port: "8080"},
					}}},
				}),
				TCPForwards: []config.TCPForward{{Port: 22, Host: "github.com"}},
			},
			want: []string{
				"tls_passthrough", "http_forward",
				"tls_passthrough_8080", "tcp_forward_22",
			},
		},
		"no tcp forwards no extra ports": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "golang.org"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			notWant: []string{"tcp_forward", "STRICT_DNS"},
		},
		"stats enabled emits grpc accesslog cluster": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				}),
				Stats: &config.Stats{Enabled: true},
			},
			want: []string{
				"terrarium_accesslog",
				"envoy.access_loggers.http_grpc",
				"envoy.access_loggers.tcp_grpc",
				"path: /run/terrarium/accesslog.sock",
			},
		},
		"stats socket past the platform limit drops grpc accesslog": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				}),
				Stats: &config.Stats{
					Enabled: true,
					Socket:  "/" + strings.Repeat("a", accesslog.MaxSocketPathLen),
				},
			},
			want: []string{"tls_passthrough", "http_forward"},
			notWant: []string{
				"terrarium_accesslog",
				"envoy.access_loggers.http_grpc",
				"envoy.access_loggers.tcp_grpc",
			},
		},
		"path restricted domain gets direct response": {
			caBundlePath: "/etc/ssl/bundle.pem",
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}, {Port: "80"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Path: "/v1/completions"},
							{Path: "/v1/models"},
						}},
					}},
				},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "cdn.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			want: []string{
				"restricted_api.example.com",
				"/v1/completions",
				"/v1/models",
				"direct_response",
				"403",
				"cdn.example.com",
			},
		},
		"MITM filter chain with certs": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}, {Port: "80"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "cdn.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			certsDir:     "/etc/terrarium/certs",
			caBundlePath: "/etc/ssl/bundle.pem",
			want: []string{
				"mitm_forward_proxy_cluster",
				"DownstreamTlsContext",
				"/etc/terrarium/certs/api.example.com/cert.pem",
				"/etc/terrarium/certs/api.example.com/key.pem",
				"UpstreamTlsContext",
				"mitm_api.example.com",
				"dynamic_forward_proxy_cluster",
				"alpn_protocols",
				"h2",
				"http/1.1",
				"auto_config",
				"HttpProtocolOptions",
			},
		},
		"no MITM without certsDir": {
			caBundlePath: "/etc/ssl/bundle.pem",
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{
					Ports: []config.Port{{Port: "443"}, {Port: "80"}},
					Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
				}},
			})},
			certsDir: "",
			notWant:  []string{"DownstreamTlsContext", "mitm_api.example.com"},
		},
		"MITM rules without CA bundle": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{
					Ports: []config.Port{{Port: "443"}, {Port: "80"}},
					Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
				}},
			})},
			certsDir: "/etc/terrarium/certs",
			err:      envoy.ErrMITMCABundleMissing,
		},
		"no MITM cluster without path rules": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			notWant: []string{"mitm_forward_proxy_cluster", "UpstreamTlsContext"},
		},
		"method-only restriction": {
			caBundlePath: "/etc/ssl/bundle.pem",
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}, {Port: "80"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Method: "GET"}}},
					}},
				},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "cdn.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			want: []string{
				"restricted_api.example.com",
				":method",
				"regex: ^GET$",
				"direct_response",
				"403",
				"cdn.example.com",
			},
		},
		"paths and methods paired not cross-producted": {
			caBundlePath: "/etc/ssl/bundle.pem",
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{
					Ports: []config.Port{{Port: "443"}, {Port: "80"}},
					Rules: &config.L7Rules{HTTP: []config.HTTPRule{
						{Path: "/v1/", Method: "GET"},
						{Path: "/v1/", Method: "POST"},
					}},
				}},
			})},
			want: []string{
				"restricted_api.example.com",
				"regex: /v1/",
				":method",
				"regex: ^GET$",
				"regex: ^POST$",
				"direct_response",
				"403",
			},
			notWant: []string{
				"^(GET|POST)$",
			},
		},
		"MITM triggered by methods-only rule": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{
					Ports: []config.Port{{Port: "443"}, {Port: "80"}},
					Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Method: "GET"}}},
				}},
			})},
			certsDir:     "/etc/terrarium/certs",
			caBundlePath: "/etc/ssl/bundle.pem",
			want: []string{
				"mitm_forward_proxy_cluster",
				"DownstreamTlsContext",
				"/etc/terrarium/certs/api.example.com/cert.pem",
				"mitm_api.example.com",
				":method",
				"auto_config",
				"HttpProtocolOptions",
			},
		},
		"no method restriction has no method header": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			notWant: []string{":method"},
		},
		"host-only restriction": {
			caBundlePath: "/etc/ssl/bundle.pem",
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{
					Ports: []config.Port{{Port: "443"}, {Port: "80"}},
					Rules: &config.L7Rules{HTTP: []config.HTTPRule{
						{Host: "api.example.com"},
					}},
				}},
			})},
			want: []string{
				"restricted_api.example.com",
				":authority",
				"regex: ^api.example.com(:[0-9]+)?$",
				"direct_response",
				"403",
			},
			notWant: []string{":method"},
		},
		"host and method combined": {
			caBundlePath: "/etc/ssl/bundle.pem",
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{
					Ports: []config.Port{{Port: "443"}, {Port: "80"}},
					Rules: &config.L7Rules{HTTP: []config.HTTPRule{
						{Method: "GET", Host: "api.example.com"},
					}},
				}},
			})},
			want: []string{
				":method",
				"regex: ^GET$",
				":authority",
				"regex: ^api.example.com(:[0-9]+)?$",
			},
		},
		"no host restriction has no authority header": {
			caBundlePath: "/etc/ssl/bundle.pem",
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{
					Ports: []config.Port{{Port: "443"}, {Port: "80"}},
					Rules: &config.L7Rules{HTTP: []config.HTTPRule{
						{Method: "GET"},
					}},
				}},
			})},
			want:    []string{":method"},
			notWant: []string{":authority"},
		},
		"per-port domain scoping": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "always.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{
						{Port: "443"}, {Port: "80"}, {Port: "8080"},
					}}},
				},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "only8080.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080"}}}},
				},
			)},
			want: []string{
				"tls_passthrough_8080",
				"only8080.com",
				"always.com",
			},
		},
		"open port gets catch-all TLS chain": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "github.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				},
				config.EgressRule{ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080"}}}}},
			)},
			want: []string{
				"tls_passthrough_8080",
				"tls_passthrough_8080_open",
			},
		},
		"open port 80 gets catch-all HTTP vhost": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "github.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				},
				config.EgressRule{ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "80"}}}}},
			)},
			want: []string{
				"name: open",
				`- "*"`,
			},
		},
		"open port overrides L7 restrictions": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}, {Port: "80"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/", Method: "GET"}}},
					}},
				},
				config.EgressRule{ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "443"}, {Port: "80"},
				}}}},
			)},
			certsDir:     "/etc/terrarium/certs",
			caBundlePath: "/etc/ssl/bundle.pem",
			want: []string{
				"api.example.com",
				"tls_passthrough",
				"http_forward",
			},
			notWant: []string{
				"restricted_",
				"direct_response",
				"403",
				"mitm_api.example.com",
				"DownstreamTlsContext",
			},
		},
		"bare wildcard TLS catch-all passthrough": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchPattern: "*"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			})},
			want: []string{
				"tls_passthrough",
				"tls_passthrough_open",
			},
			notWant: []string{
				`server_names`,
			},
		},
		"bare wildcard HTTP catch-all vhost": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchPattern: "*"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "80"}}}},
			})},
			want: []string{
				"http_forward",
				`- "*"`,
			},
		},
		"bare wildcard HTTP no duplicate open vhost": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "80"}}}},
				},
				config.EgressRule{ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "80"}}}}},
			)},
			want: []string{
				"http_forward",
				`- "*"`,
			},
			notWant: []string{
				"name: open",
			},
		},
		"nil egress produces open listeners": {
			cfg: &config.Config{},
			want: []string{
				"tls_passthrough", "http_forward", "catch_all_tcp",
				"original_dst", "dynamic_forward_proxy_cluster",
			},
		},
		"empty egress produces blocked output": {
			cfg: &config.Config{Egress: egressRules()},
			want: []string{
				"listeners: []",
			},
			notWant: []string{
				"tls_passthrough", "http_forward", "catch_all_tcp",
				"original_dst", "dynamic_forward_proxy_cluster",
			},
		},
		"nil egress with tcp forwards": {
			cfg: &config.Config{
				TCPForwards: []config.TCPForward{{Port: 22, Host: "github.com"}},
			},
			want: []string{
				"tcp_forward_22", "github.com", "STRICT_DNS",
				"tls_passthrough", "http_forward", "catch_all_tcp",
				"original_dst", "dynamic_forward_proxy_cluster",
			},
		},
		"empty rule with FQDN+L7 generates FQDN listeners": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}, {Port: "80"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				},
			)},
			certsDir:     "/etc/terrarium/certs",
			caBundlePath: "/etc/ssl/bundle.pem",
			want: []string{
				"tls_passthrough",
				"http_forward",
				"restricted_api.example.com",
				"mitm_api.example.com",
				"DownstreamTlsContext",
				"/v1/",
				"403",
				"dynamic_forward_proxy_cluster",
			},
		},
		"empty HTTP produces passthrough not MITM": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{
					Ports: []config.Port{{Port: "443"}, {Port: "80"}},
					Rules: &config.L7Rules{HTTP: []config.HTTPRule{}},
				}},
			})},
			certsDir:     "/etc/terrarium/certs",
			caBundlePath: "/etc/ssl/bundle.pem",
			want: []string{
				"api.example.com",
				"tls_passthrough",
				"http_forward",
			},
			notWant: []string{
				"restricted_api.example.com",
				"direct_response",
				"mitm_forward_proxy_cluster",
				"DownstreamTlsContext",
			},
		},
		"wildcard gets RBAC filter": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			want: []string{
				"envoy.filters.network.rbac",
				"stat_prefix: wildcard_depth",
				"ALLOW",
				`^[-a-zA-Z0-9_]+\\.example\\.com$`,
			},
		},
		"double-star wildcard gets multi-label RBAC regex": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchPattern: "**.example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			want: []string{
				"envoy.filters.network.rbac",
				"ALLOW",
				`^[-a-zA-Z0-9_]+(\\.[-a-zA-Z0-9_]+)*\\.example\\.com$`,
				"*.example.com",
				"envoy.filters.http.rbac",
				`^[-a-zA-Z0-9_]+(\\.[-a-zA-Z0-9_]+)*\\.example\\.com(:\\d+)?$`,
			},
			notWant: []string{
				"**.example.com",
			},
		},
		"exact domain no RBAC": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			want:    []string{"example.com"},
			notWant: []string{"envoy.filters.network.rbac"},
		},
		"mixed wildcard and exact": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "github.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			want: []string{
				"github.com",
				"*.example.com",
				"envoy.filters.network.rbac",
				`^[-a-zA-Z0-9_]+\\.example\\.com$`,
			},
		},
		"multiple wildcards": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{
					{MatchPattern: "*.a.com"},
					{MatchPattern: "*.b.com"},
				},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			want: []string{
				`^[-a-zA-Z0-9_]+\\.a\\.com$`,
				`^[-a-zA-Z0-9_]+\\.b\\.com$`,
				"envoy.filters.network.rbac",
			},
		},
		"wildcard on extra port": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080"}}}},
			})},
			want: []string{
				"tls_passthrough_8080",
				"envoy.filters.network.rbac",
				`^[-a-zA-Z0-9_]+\\.example\\.com$`,
			},
		},
		"MITM on extra port": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{
					Ports: []config.Port{{Port: "8080"}},
					Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
				}},
			})},
			certsDir:     "/etc/terrarium/certs",
			caBundlePath: "/etc/ssl/bundle.pem",
			want: []string{
				"tls_passthrough_8080",
				"mitm_api.example.com",
				"/etc/terrarium/certs/api.example.com/cert.pem",
				"DownstreamTlsContext",
			},
		},
		"wildcard HTTP gets RBAC filter on :authority": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			want: []string{
				"envoy.filters.http.rbac",
				":authority",
				`^[-a-zA-Z0-9_]+\\.example\\.com(:\\d+)?$`,
				"envoy.filters.network.rbac",
				`^[-a-zA-Z0-9_]+\\.example\\.com$`,
			},
		},
		"exact domain HTTP no RBAC": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "80"}}}},
			})},
			notWant: []string{"envoy.filters.http.rbac"},
		},
		"mixed wildcard and exact HTTP RBAC includes both": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "github.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "80"}}}},
				},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "80"}}}},
				},
			)},
			want: []string{
				"envoy.filters.http.rbac",
				`^[-a-zA-Z0-9_]+\\.example\\.com(:\\d+)?$`,
				`^github\\.com(:\\d+)?$`,
			},
		},
		"open port 80 no HTTP RBAC despite wildcards": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "80"}}}},
				},
				config.EgressRule{ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "80"}}}}},
			)},
			notWant: []string{"envoy.filters.http.rbac"},
		},
		"bare wildcard HTTP no RBAC": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchPattern: "*"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "80"}}}},
			})},
			notWant: []string{"envoy.filters.http.rbac"},
		},
		"double-star wildcard HTTP gets multi-label RBAC regex": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchPattern: "**.example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "80"}}}},
			})},
			want: []string{
				"envoy.filters.http.rbac",
				":authority",
				`^[-a-zA-Z0-9_]+(\\.[-a-zA-Z0-9_]+)*\\.example\\.com(:\\d+)?$`,
			},
		},
		"multiple wildcards HTTP RBAC": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{
					{MatchPattern: "*.a.com"},
					{MatchPattern: "*.b.com"},
				},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "80"}}}},
			})},
			want: []string{
				"envoy.filters.http.rbac",
				`^[-a-zA-Z0-9_]+\\.a\\.com(:\\d+)?$`,
				`^[-a-zA-Z0-9_]+\\.b\\.com(:\\d+)?$`,
			},
		},
		"HTTP forward listener has path normalization": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "80"}}}},
			})},
			want: []string{
				"normalize_path: true",
				"merge_slashes: true",
				"path_with_escaped_slashes_action: UNESCAPE_AND_REDIRECT",
			},
		},
		"MITM listener has path normalization": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{
					Ports: []config.Port{{Port: "443"}, {Port: "80"}},
					Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
				}},
			})},
			certsDir:     "/etc/terrarium/certs",
			caBundlePath: "/etc/ssl/bundle.pem",
			want: []string{
				"mitm_api.example.com",
				"normalize_path: true",
				"merge_slashes: true",
				"path_with_escaped_slashes_action: UNESCAPE_AND_REDIRECT",
			},
		},
		"MITM config with HTTP forward has path normalization": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{
					Ports: []config.Port{{Port: "443"}},
					Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
				}},
			})},
			certsDir:     "/etc/terrarium/certs",
			caBundlePath: "/etc/ssl/bundle.pem",
			want: []string{
				"mitm_api.example.com",
				"normalize_path: true",
				"merge_slashes: true",
				"path_with_escaped_slashes_action: UNESCAPE_AND_REDIRECT",
				"http_forward",
			},
		},
		"passthrough-only config still has HTTP forward": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			})},
			want: []string{
				"tls_passthrough",
				"http_forward",
				"catch_all_tcp",
			},
		},
		"headers presence check": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{
					Ports: []config.Port{{Port: "443"}, {Port: "80"}},
					Rules: &config.L7Rules{HTTP: []config.HTTPRule{
						{Headers: []string{"X-Custom", "Authorization"}},
					}},
				}},
			})},
			certsDir:     "/etc/terrarium/certs",
			caBundlePath: "/etc/ssl/bundle.pem",
			want: []string{
				"restricted_api.example.com",
				"present_match: true",
				"name: X-Custom",
				"name: Authorization",
				"direct_response",
				"403",
			},
		},
		"headerMatches value check": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{
					Ports: []config.Port{{Port: "443"}, {Port: "80"}},
					Rules: &config.L7Rules{HTTP: []config.HTTPRule{
						{HeaderMatches: []config.HeaderMatch{{Name: "X-Token", Value: "secret"}}},
					}},
				}},
			})},
			certsDir:     "/etc/terrarium/certs",
			caBundlePath: "/etc/ssl/bundle.pem",
			want: []string{
				"restricted_api.example.com",
				"%CEL(request.headers['x-token'])%",
				"clear_route_cache: true",
				"key: terrarium.header_value.x-token",
				"exact: secret",
				"direct_response",
				"403",
			},
			notWant: []string{"present_match", "name: X-Token"},
		},
		"headers combined with method and path": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{
					Ports: []config.Port{{Port: "443"}, {Port: "80"}},
					Rules: &config.L7Rules{HTTP: []config.HTTPRule{
						{Method: "GET", Path: "/v1/", Headers: []string{"X-Custom"}},
					}},
				}},
			})},
			certsDir:     "/etc/terrarium/certs",
			caBundlePath: "/etc/ssl/bundle.pem",
			want: []string{
				"restricted_api.example.com",
				":method",
				"regex: ^GET$",
				"regex: /v1/",
				"name: X-Custom",
				"present_match: true",
			},
		},
		"separate FQDN and CIDR generates Envoy for FQDN only": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				},
				config.EgressRule{
					ToCIDR:  []string{"10.0.0.0/8"},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			want: []string{
				"tls_passthrough", "http_forward",
				"api.example.com",
				"dynamic_forward_proxy_cluster",
			},
			notWant: []string{
				"10.0.0.0",
			},
		},
		"route actions have request timeout": {
			caBundlePath: "/etc/ssl/bundle.pem",
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}, {Port: "80"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "cdn.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			want: []string{
				"timeout: 3600s",
			},
		},
		"HCMs have stream idle timeout": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			want: []string{
				"stream_idle_timeout: 300s",
			},
		},
		"HCMs set UseRemoteAddress and SkipXffAppend": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			want: []string{
				"use_remote_address: true",
				"skip_xff_append: true",
			},
		},
		"gRPC route match and timeout handling": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			want: []string{
				"grpc: {}",
				"grpc_timeout_header_max: 0s",
			},
		},
		"TLS listener has default filter chain for missing SNI": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			})},
			want: []string{
				"default_filter_chain:",
				"missing_sni_blackhole",
				"tls_passthrough_no_sni",
				"missing_sni src=%DOWNSTREAM_REMOTE_ADDRESS% dst=%DOWNSTREAM_LOCAL_ADDRESS%",
			},
		},
		"TLS filter chains have transport_protocol tls": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}, {Port: "80"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "cdn.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				},
				config.EgressRule{ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080"}}}}},
			)},
			certsDir:     "/etc/terrarium/certs",
			caBundlePath: "/etc/ssl/bundle.pem",
			want: []string{
				"transport_protocol: tls",
			},
		},
		"clusters have connect timeout": {
			caBundlePath: "/etc/ssl/bundle.pem",
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}, {Port: "80"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Method: "GET", Path: "/v1/"}}},
					}},
				}),
				TCPForwards: []config.TCPForward{{Port: 22, Host: "github.com"}},
			},
			want: []string{
				"connect_timeout: 5s",
			},
		},
		"custom max downstream connections": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
				Envoy: &config.EnvoySettings{MaxDownstreamConnections: 1024},
			},
			want: []string{
				fmt.Sprintf("max_active_downstream_connections: %d", 1024),
			},
			notWant: []string{
				fmt.Sprintf("max_active_downstream_connections: %d", config.DefaultEnvoyMaxDownstreamConnections),
			},
		},
		"default max downstream connections": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			want: []string{
				fmt.Sprintf("max_active_downstream_connections: %d", config.DefaultEnvoyMaxDownstreamConnections),
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			conf, err := GenerateEnvoyFromConfig(t.Context(), tt.cfg, tt.certsDir, tt.caBundlePath, false)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)

				return
			}

			require.NoError(t, err)

			for _, s := range tt.want {
				assert.Contains(t, conf, s)
			}

			for _, s := range tt.notWant {
				assert.NotContains(t, conf, s)
			}
		})
	}
}
