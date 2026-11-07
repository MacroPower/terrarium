package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/spf13/cobra"
	"go.jacobcolvin.com/niceyaml"

	"go.jacobcolvin.com/terrarium/accesslog"
	"go.jacobcolvin.com/terrarium/certs"
	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/envoy"
	"go.jacobcolvin.com/terrarium/eventstore"
)

var (
	// ErrDenyRulesUnsupported is returned when the policy contains
	// egressDeny rules, which proxy mode cannot enforce (they match
	// CIDRs, ports, and ICMP at the packet layer). Refusing to start
	// keeps deny semantics fail-closed.
	ErrDenyRulesUnsupported = errors.New("egressDeny rules are not supported in proxy mode")

	// ErrEnvoyNotFound is returned when no envoy binary is on PATH.
	ErrEnvoyNotFound = errors.New(
		"envoy binary not found on PATH " +
			"(install it from envoyproxy.io on Linux or `brew install envoy` on macOS)")

	// ErrSystemCABundleMissing means that --ca-bundle-out is set but no
	// system CA bundle exists, so the client bundle has no roots.
	ErrSystemCABundleMissing = errors.New("no system CA bundle found")
)

// proxyOptions carries the proxy command's flag values.
type proxyOptions struct {
	bindAddress string
	caOut       string
	caBundleOut string
	resolvers   []string
	httpPort    int
}

// proxyCmd builds the `terrarium proxy` subcommand: an HTTP forward
// proxy on the host, filtered by the same policy YAML as the
// container modes. It serves as Claude Code's
// sandbox.network.httpProxyPort.
func proxyCmd(usr *config.User) *cobra.Command {
	opts := proxyOptions{}

	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run an HTTP forward proxy filtered by the egress policy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return Proxy(cmd.Context(), usr, opts)
		},
	}

	cmd.Flags().IntVar(&opts.httpPort, "http-port", 8080,
		"port for the HTTP proxy listener")
	cmd.Flags().StringVar(&opts.bindAddress, "bind-address", "127.0.0.1",
		"address the proxy listener binds")
	cmd.Flags().StringVar(&opts.caOut, "ca-out", "",
		"write the MITM CA certificate PEM to this path (only when the policy has L7 rules)")
	cmd.Flags().StringVar(&opts.caBundleOut, "ca-bundle-out", "",
		"write the system CA bundle plus the MITM CA to this path, for clients that read one trust file")
	cmd.Flags().StringSliceVar(&opts.resolvers, "resolver", nil,
		"DNS resolver ip:port for upstream resolution (default: system resolver)")

	return cmd
}

// parseResolvers converts --resolver flag values to address/port pairs.
func parseResolvers(resolvers []string) ([]netip.AddrPort, error) {
	out := make([]netip.AddrPort, 0, len(resolvers))

	for _, r := range resolvers {
		ap, err := netip.ParseAddrPort(r)
		if err != nil {
			return nil, fmt.Errorf("parsing resolver %q: %w", r, err)
		}

		out = append(out, ap)
	}

	return out, nil
}

// proxyBootstrapPath returns the proxy-mode Envoy bootstrap path:
// envoy-proxy.yaml next to the container-mode bootstrap, so the two
// modes never clobber each other's configs.
func proxyBootstrapPath(usr *config.User) string {
	return filepath.Join(filepath.Dir(usr.EnvoyConfigPath), "envoy-proxy.yaml")
}

// GenerateProxy reads the policy from usr.ConfigPath and generates
// MITM certs for restricted rules. It writes the proxy-mode Envoy
// bootstrap and exports the CA files that opts names, then returns the
// parsed config and the bootstrap path.
//
// The proxy reuses the CA in usr.CADir across runs, so clients that
// trust it keep working after a restart. See [exportCA] for the files
// it exports.
func GenerateProxy(
	ctx context.Context, usr *config.User, opts proxyOptions,
) (*config.Config, string, error) {
	data, err := os.ReadFile(usr.ConfigPath)
	if err != nil {
		return nil, "", fmt.Errorf("reading config: %w", err)
	}

	cfg, err := config.ParseConfig(ctx, data)
	if err != nil {
		return nil, "", fmt.Errorf("parsing config: %w", err)
	}

	resolvers, err := parseResolvers(opts.resolvers)
	if err != nil {
		return nil, "", err
	}

	mitmRules := collectMITMRules(ctx, cfg)

	caPath := ""
	certsDir := ""

	if len(mitmRules) > 0 {
		caPath, _, err = certs.LoadOrGenerateCA(usr.CADir)
		if err != nil {
			return nil, "", fmt.Errorf("loading CA: %w", err)
		}

		err = certs.GenerateLeaves(mitmRules, usr.CADir, usr.CertsDir)
		if err != nil {
			return nil, "", fmt.Errorf("generating certs: %w", err)
		}

		certsDir = usr.CertsDir
	}

	// Skip the exported files, which hold the MITM CA, when choosing
	// the bundle that verifies upstream servers.
	systemBundle := certs.FindCABundle(opts.caOut, opts.caBundleOut)

	err = exportCA(ctx, caPath, systemBundle, opts)
	if err != nil {
		return nil, "", err
	}

	envoyConf, err := GenerateProxyEnvoyFromConfig(ctx, cfg, certsDir, systemBundle,
		opts.bindAddress, opts.httpPort, resolvers)
	if err != nil {
		return nil, "", fmt.Errorf("generating envoy config: %w", err)
	}

	path := proxyBootstrapPath(usr)

	err = os.MkdirAll(filepath.Dir(path), 0o755)
	if err != nil {
		return nil, "", fmt.Errorf("creating envoy config directory: %w", err)
	}

	err = os.WriteFile(path, []byte(envoyConf), 0o644) //nolint:gosec // G306: config, not a secret.
	if err != nil {
		return nil, "", fmt.Errorf("writing envoy config: %w", err)
	}

	return cfg, path, nil
}

// exportCA writes the CA files that opts names. The caPath argument is
// the MITM CA certificate, or empty when the policy has no L7 rules.
//
//   - opts.caOut receives the MITM CA alone, for clients that add one
//     certificate to their default roots, such as NODE_EXTRA_CA_CERTS
//     or a keychain import. exportCA skips it without a MITM CA.
//   - opts.caBundleOut receives the roots from systemBundle followed by
//     the MITM CA, for clients that read a single trust file, such as
//     SSL_CERT_FILE. The roots let those clients verify the hosts that
//     the proxy tunnels without inspection. Without a MITM CA, the
//     file holds the roots alone, so clients can point at it whatever
//     the policy holds.
//
// exportCA replaces each file in one rename, so a client that reads it
// during a restart sees either the old or the new contents.
func exportCA(ctx context.Context, caPath, systemBundle string, opts proxyOptions) error {
	var caPEM []byte

	if caPath != "" {
		var err error

		caPEM, err = os.ReadFile(caPath) //nolint:gosec // G304: path from the CA directory.
		if err != nil {
			return fmt.Errorf("reading CA: %w", err)
		}
	}

	switch {
	case opts.caOut != "" && caPEM != nil:
		err := writeFileAtomic(opts.caOut, caPEM)
		if err != nil {
			return fmt.Errorf("writing CA to %s: %w", opts.caOut, err)
		}

		slog.InfoContext(ctx, "proxy: CA certificate written",
			slog.String("path", opts.caOut))

	case opts.caOut != "":
		// No L7 rules means no MITM and no CA; make the no-op explicit
		// rather than silently leaving --ca-out unfulfilled.
		slog.InfoContext(ctx, "proxy: no L7 rules, no MITM CA to export",
			slog.String("ca_out", opts.caOut))
	}

	if opts.caBundleOut == "" {
		return nil
	}

	if systemBundle == "" {
		return fmt.Errorf("writing %s: %w", opts.caBundleOut, ErrSystemCABundleMissing)
	}

	roots, err := os.ReadFile(systemBundle) //nolint:gosec // G304: path from FindCABundle.
	if err != nil {
		return fmt.Errorf("reading system CA bundle: %w", err)
	}

	bundle := make([]byte, 0, len(roots)+len(caPEM)+1)
	bundle = append(bundle, roots...)

	if len(caPEM) > 0 {
		if len(bundle) > 0 && bundle[len(bundle)-1] != '\n' {
			bundle = append(bundle, '\n')
		}

		bundle = append(bundle, caPEM...)
	}

	err = writeFileAtomic(opts.caBundleOut, bundle)
	if err != nil {
		return fmt.Errorf("writing CA bundle to %s: %w", opts.caBundleOut, err)
	}

	slog.InfoContext(ctx, "proxy: CA bundle written",
		slog.String("path", opts.caBundleOut),
		slog.String("system_bundle", systemBundle),
		slog.Bool("mitm_ca", len(caPEM) > 0))

	return nil
}

// writeFileAtomic writes data to a temporary file next to path with
// mode 0o644, then renames it over path.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)

	err := os.MkdirAll(dir, 0o755)
	if err != nil {
		return fmt.Errorf("creating dir for %s: %w", path, err)
	}

	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}

	tmp := f.Name()

	_, err = f.Write(data)
	if err == nil {
		// CreateTemp creates the file with mode 0o600.
		err = f.Chmod(0o644)
	}

	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}

	if err == nil {
		err = os.Rename(tmp, path)
	}

	if err != nil {
		removeErr := os.Remove(tmp)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			slog.Debug("removing temp file",
				slog.String("path", tmp),
				slog.Any("err", removeErr),
			)
		}

		return fmt.Errorf("writing %s: %w", path, err)
	}

	return nil
}

// GenerateProxyEnvoyFromConfig builds the proxy-mode Envoy bootstrap
// YAML: a CONNECT-terminating front listener on bindAddress:httpPort
// plus internal enforcement listeners per TLS policy port and for
// plain HTTP. Packet-layer rule kinds (CIDR, ICMP, UDP, port ranges,
// TCP forwards) cannot be enforced by a forward proxy: allow rules of
// those kinds are skipped with a warning (fail-closed), and deny
// rules are rejected with [ErrDenyRulesUnsupported].
func GenerateProxyEnvoyFromConfig(
	ctx context.Context,
	cfg *config.Config,
	certsDir, caBundlePath string,
	bindAddress string,
	httpPort int,
	resolvers []netip.AddrPort,
) (string, error) {
	// Resolve open (toPorts-only) rules once; both the policy check and
	// the filtered-mode assembly consume them.
	openPortRules := cfg.ResolveOpenPortRules(ctx)

	err := checkProxyPolicy(ctx, cfg, openPortRules)
	if err != nil {
		return "", err
	}

	als := alsConfig{
		enabled:  cfg.StatsEnabled(),
		socket:   cfg.StatsSocket(),
		bufBytes: cfg.StatsBufferBytes(),
		flushMs:  cfg.StatsFlushIntervalMs(),
	}

	params := envoy.ProxyListenerParams{
		BindAddress: bindAddress,
		Port:        httpPort,
		AccessLog:   als.httpListenerLog("proxy"),
		Resolvers:   resolvers,
	}

	var (
		listeners []envoy.Listener
		allRules  []config.ResolvedRule
		tlsPorts  []int
	)

	switch {
	case cfg.IsEgressBlocked():
		params.Mode = envoy.ProxyModeBlocked

	case cfg.IsEgressUnrestricted() || cfg.HasUnrestrictedOpenPorts(ctx):
		// A toPorts-only rule with no ports allows all destinations
		// on all ports; Cilium OR semantics override any L7 rules.
		params.Mode = envoy.ProxyModeOpen

	default:
		params.Mode = envoy.ProxyModeFiltered
		listeners, allRules, tlsPorts = assembleFilteredProxy(
			ctx, cfg, als, certsDir, resolvers, openTCPPorts(openPortRules), &params)
	}

	front := envoy.BuildProxyListener(params)
	listeners = append([]envoy.Listener{front}, listeners...)

	allClusters, err := envoy.BuildProxyClusters(
		allRules, tlsPorts, len(params.HTTPDomains) > 0,
		params.Mode == envoy.ProxyModeOpen, caBundlePath, resolvers,
	)
	if err != nil {
		return "", fmt.Errorf("building proxy clusters: %w", err)
	}

	if als.enabled {
		allClusters = append(allClusters, envoy.BuildAccessLogCluster(als.socket))
	}

	envoySettings := cfg.EnvoyDefaults()

	bs := envoy.Bootstrap{
		OverloadManager: envoy.OverloadManager{
			ResourceMonitors: []envoy.NamedTyped{{
				Name: "envoy.resource_monitors.global_downstream_max_connections",
				TypedConfig: envoy.DownstreamConnectionsConfig{
					AtType:                         "type.googleapis.com/envoy.extensions.resource_monitors.downstream_connections.v3.DownstreamConnectionsConfig",
					MaxActiveDownstreamConnections: envoySettings.MaxDownstreamConnections,
				},
			}},
		},
		StaticResources: envoy.StaticResources{
			Listeners: listeners,
			Clusters:  allClusters,
		},
	}

	// Internal listeners require the bootstrap extension.
	if len(listeners) > 1 {
		bs.BootstrapExtensions = []envoy.NamedTyped{
			envoy.InternalListenerBootstrapExtension(),
		}
	}

	var buf bytes.Buffer

	err = niceyaml.NewEncoder(&buf).Encode(bs)
	if err != nil {
		return "", fmt.Errorf("marshaling envoy config: %w", err)
	}

	return buf.String(), nil
}

// assembleFilteredProxy builds the internal enforcement listeners for
// filtered mode and fills params with the front listener's CONNECT
// authority allowlists. The openTCP argument holds the single TCP
// ports from toPorts-only rules. It returns the internal listeners,
// the union of
// resolved rules they enforce (for cluster determination), and the
// sorted TLS policy ports.
func assembleFilteredProxy(
	ctx context.Context,
	cfg *config.Config,
	als alsConfig,
	certsDir string,
	resolvers []netip.AddrPort,
	openTCP map[int]bool,
	params *envoy.ProxyListenerParams,
) ([]envoy.Listener, []config.ResolvedRule, []int) {
	// TLS ports: every non-80 port with FQDN/serverName rules or an
	// open toPorts rule.
	tlsPortSet := make(map[int]bool)

	if slices.Contains(cfg.ResolvePorts(ctx), 443) || openTCP[443] {
		tlsPortSet[443] = true
	}

	for _, p := range cfg.ExtraPorts(ctx) {
		tlsPortSet[p] = true
	}

	for p := range openTCP {
		if p != 80 {
			tlsPortSet[p] = true
		}
	}

	var (
		listeners []envoy.Listener
		allRules  []config.ResolvedRule
	)

	tlsPorts := slices.Sorted(maps.Keys(tlsPortSet))
	params.ConnectTLS = make(map[int][]string, len(tlsPorts))

	for _, p := range tlsPorts {
		rules := cfg.ResolveRulesForPort(ctx, p)
		rules = append(rules, cfg.ResolveServerNameRulesForPort(ctx, p)...)
		open := openTCP[p]

		if open {
			// Cilium OR semantics: an open port rule admits all
			// traffic on the port, overriding L7 restrictions.
			rules = envoy.StripL7Restrictions(rules)
		}

		params.ConnectTLS[p] = proxyVhostDomains(rules, open)
		allRules = append(allRules, rules...)

		listeners = append(listeners, envoy.BuildInternalTLSListener(
			p, rules, open,
			als.tcpListenerLog(fmt.Sprintf("tls_internal_%d", p)),
			als.httpListenerLog(fmt.Sprintf("tls_internal_mitm_%d", p)),
			certsDir, resolvers,
		))
	}

	// Plain HTTP: port-80 rules and/or an open port-80 rule.
	rules80 := cfg.ResolveRulesForPort(ctx, 80)
	open80 := openTCP[80]

	if open80 {
		rules80 = envoy.StripL7Restrictions(rules80)
	}

	if len(rules80) > 0 || open80 {
		params.HTTPDomains = proxyVhostDomains(rules80, open80)
		allRules = append(allRules, rules80...)

		listeners = append(listeners, envoy.BuildInternalHTTPListener(
			rules80, open80, als.httpListenerLog("http_internal"), resolvers,
		))
	}

	return listeners, allRules, tlsPorts
}

// proxyVhostDomains extracts the rule domains for a front-listener
// CONNECT vhost, appending the bare wildcard for open ports.
func proxyVhostDomains(rules []config.ResolvedRule, open bool) []string {
	domains := make([]string, 0, len(rules)+1)
	for _, r := range rules {
		domains = append(domains, r.Domain)
	}

	if open {
		domains = append(domains, "*")
	}

	return domains
}

// checkProxyPolicy rejects deny rules (fail-closed) and warns about
// allow rule kinds a forward proxy cannot enforce. Skipping an allow
// rule only narrows the policy; skipping a deny rule would widen it,
// so deny rules are an error. The openPortRules argument is the
// already-resolved toPorts-only rule set.
func checkProxyPolicy(ctx context.Context, cfg *config.Config, openPortRules []config.ResolvedOpenPort) error {
	denyV4, denyV6 := cfg.ResolveDenyCIDRRules(ctx)
	if len(denyV4) > 0 || len(denyV6) > 0 ||
		len(cfg.ResolveDenyPortOnlyRules(ctx)) > 0 ||
		len(cfg.ResolveDenyICMPRules()) > 0 {
		return ErrDenyRulesUnsupported
	}

	if cfg.HasCIDRRules() {
		slog.WarnContext(ctx,
			"proxy: toCIDR/toCIDRSet rules are not enforced by the forward proxy; "+
				"only their serverNames and L7 constraints apply")
	}

	if len(cfg.ResolveICMPRules()) > 0 {
		slog.WarnContext(ctx, "proxy: icmps rules are not enforced by the forward proxy")
	}

	if cfg.HasFQDNNonTCPPorts(ctx) {
		// Ports without an explicit protocol default to ANY, which
		// includes UDP in container mode. A CONNECT proxy is TCP-only,
		// so UDP egress (DNS, QUIC) stays blocked by the sandbox.
		slog.DebugContext(ctx,
			"proxy: UDP egress is not proxied; policy ports apply to TCP only")
	}

	if len(cfg.TCPForwards) > 0 {
		slog.WarnContext(ctx, "proxy: tcpForwards are not supported in proxy mode")
	}

	for _, op := range openPortRules {
		if op.Protocol == config.ProtoTCP && op.EndPort != 0 {
			slog.WarnContext(ctx, "proxy: open port ranges are not supported in proxy mode",
				slog.Int("port", op.Port),
				slog.Int("end_port", op.EndPort))
		}
	}

	return nil
}

// openTCPPorts returns the single TCP ports from the resolved
// toPorts-only rules. Ranges and non-TCP protocols are excluded
// (warned about in [checkProxyPolicy]).
func openTCPPorts(openPortRules []config.ResolvedOpenPort) map[int]bool {
	out := make(map[int]bool)

	for _, op := range openPortRules {
		if op.Protocol == config.ProtoTCP && op.EndPort == 0 {
			out[op.Port] = true
		}
	}

	return out
}

// Proxy generates the proxy-mode bootstrap, starts Envoy on the
// host, and supervises it until a signal arrives or Envoy exits. No
// root, network namespaces, or nftables involved: the only privilege
// needed is binding the listen port.
func Proxy(ctx context.Context, usr *config.User, opts proxyOptions) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, bootstrapPath, err := GenerateProxy(ctx, usr, opts)
	if err != nil {
		return err
	}

	envoyBin, err := exec.LookPath("envoy")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEnvoyNotFound, err)
	}

	store := openProxyEventStore(ctx, cfg)

	defer func() {
		closeErr := store.Close() //nolint:contextcheck // shutdown flush must not inherit a canceled ctx.
		if closeErr != nil {
			slog.DebugContext(ctx, "closing event store", slog.Any("err", closeErr))
		}
	}()

	accessLogSrv := openProxyAccessLog(ctx, cfg, store)
	if accessLogSrv != nil {
		defer accessLogSrv.Shutdown(context.WithoutCancel(ctx))
	}

	envoySettings := cfg.EnvoyDefaults()

	//nolint:gosec // G204: binary from PATH lookup, args from CLI flags.
	cmd := exec.CommandContext(ctx, envoyBin,
		"-c", bootstrapPath,
		"--log-level", cfg.EnvoyLogLevel(),
		// Hot restart uses a shared-memory region keyed by base-id;
		// disabling it lets multiple Envoys coexist on one host.
		"--disable-hot-restart",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// On ctx cancellation (signal), drain gracefully: SIGTERM first,
	// SIGKILL after the drain timeout.
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.WaitDelay = envoySettings.DrainTimeout.Duration

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("starting envoy: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", opts.bindAddress, opts.httpPort)

	err = waitForListener(ctx, addr, envoySettings.StartupTimeout.Duration)
	if err != nil {
		stopEnvoy(ctx, cmd, envoySettings.DrainTimeout.Duration)

		return fmt.Errorf("%w: %w", ErrEnvoyNotRunning, err)
	}

	slog.InfoContext(ctx, "proxy: ready",
		slog.String("address", addr),
		slog.String("bootstrap", bootstrapPath))

	err = cmd.Wait()
	if ctx.Err() != nil {
		// Signal-initiated shutdown: Envoy was SIGTERM'd by Cancel.
		slog.InfoContext(ctx, "proxy: shut down")

		return nil
	}

	if err != nil {
		return fmt.Errorf("%w: %w", ErrEnvoyNotRunning, err)
	}

	return ErrEnvoyNotRunning
}

// openProxyEventStore opens the SQLite event store when stats is
// enabled. Unlike the container-mode variant, no ownership changes
// are needed: everything runs as the invoking user. On failure it
// logs and returns nil so [eventstore.Store] receivers behave as
// no-ops.
func openProxyEventStore(ctx context.Context, cfg *config.Config) *eventstore.Store {
	if !cfg.StatsEnabled() {
		return nil
	}

	path := cfg.StatsPath(config.StatsDBDefault())
	perSource := cfg.StatsRetentionPerSource()

	store, err := eventstore.Open(ctx, path,
		eventstore.WithMode(eventstore.ModeProxy),
		eventstore.WithRetention(eventstore.Retention{
			MaxAge:  cfg.StatsRetentionMaxAge(),
			MaxRows: cfg.StatsRetentionMaxRows(),
			PerSource: eventstore.PerSourceCaps{
				Firewall: perSource.Firewall,
				DNS:      perSource.DNS,
				Envoy:    perSource.Envoy,
			},
		}),
	)
	if err != nil {
		slog.WarnContext(ctx, "stats: opening event store, ingestion disabled",
			slog.String("path", path),
			slog.Any("err", err))

		return nil
	}

	slog.InfoContext(ctx, "stats: event store opened",
		slog.String("path", path),
		slog.String("instance", store.InstanceID()))

	return store
}

// openProxyAccessLog binds the gRPC AccessLog UDS when stats is
// enabled. On failure it logs and returns nil; the data plane is
// never blocked by stats ingestion.
func openProxyAccessLog(
	ctx context.Context, cfg *config.Config, store *eventstore.Store,
) *accesslog.Server {
	if !cfg.StatsEnabled() || store == nil {
		return nil
	}

	socket := cfg.StatsSocket()

	srv, err := accesslog.Start(ctx, socket, store)
	if err != nil {
		slog.WarnContext(ctx, "stats: opening accesslog socket, ingestion disabled",
			slog.String("socket", socket),
			slog.Any("err", err))

		return nil
	}

	slog.InfoContext(ctx, "stats: accesslog socket open",
		slog.String("socket", socket))

	return srv
}
