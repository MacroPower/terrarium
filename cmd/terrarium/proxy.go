package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.jacobcolvin.com/niceyaml"

	"go.jacobcolvin.com/terrarium/accesslog"
	"go.jacobcolvin.com/terrarium/certs"
	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/envoy"
	"go.jacobcolvin.com/terrarium/envoybin"
	"go.jacobcolvin.com/terrarium/eventstore"
)

var (
	// ErrDenyRulesUnsupported is returned when the policy contains
	// egressDeny rules, which proxy mode cannot enforce (they match
	// CIDRs, ports, and ICMP at the packet layer). Refusing to start
	// keeps deny semantics fail-closed.
	ErrDenyRulesUnsupported = errors.New("egressDeny rules are not supported in proxy mode")

	// ErrSystemCABundleMissing means that --ca-bundle-out is set but no
	// system CA bundle exists, so the client bundle has no roots.
	ErrSystemCABundleMissing = errors.New("no system CA bundle found")

	// ErrReadyFileIsDir means that --ready-file names a directory. The
	// proxy removes the ready file at startup and on exit, and it must
	// not remove a directory.
	ErrReadyFileIsDir = errors.New("ready file is a directory")
)

// The loopback addresses. The proxy binds loopbackIPv4 by default, and
// container mode skips both as upstream resolvers because the DNS proxy
// listens on them.
const (
	loopbackIPv4 = "127.0.0.1"
	loopbackIPv6 = "::1"
)

// osLinux is the [runtime.GOOS] value of Linux.
const osLinux = "linux"

// proxyOptions carries the proxy command's flag values.
type proxyOptions struct {
	bindAddress string
	caOut       string
	caBundleOut string
	// The name of an Envoy binary that replaces the managed build. See
	// [proxyEnvoyPath].
	envoyPath string
	// The value of the --envoy-log flag. The proxy command copies it
	// to the user, or the default when the command line has no such
	// flag. [Proxy] reads the path from the user.
	envoyLog  string
	resolvers []string
	httpPort  int
}

// proxyCmd builds the `terrarium proxy` subcommand: an HTTP forward
// proxy on the host, filtered by the same policy YAML as the
// container modes. It serves as Claude Code's
// sandbox.network.httpProxyPort.
//
// The proxy runs the managed Envoy build of inst, unless the
// --envoy-path flag or the envoy.path config key names another binary.
func proxyCmd(usr *config.User, inst *envoybin.Installer) *cobra.Command {
	opts := proxyOptions{}

	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run an HTTP forward proxy filtered by the egress policy",
		Long: "Run an HTTP forward proxy filtered by the egress policy.\n\n" +
			"The proxy runs Envoy " + envoybin.Version + " from " +
			"$XDG_DATA_HOME/terrarium/envoy. It checks the SHA-256 of that " +
			"binary at every start, and it installs the binary when the " +
			"binary is missing. Run `terrarium envoy install` ahead of time " +
			"on a machine that starts the proxy offline.\n\n" +
			"To run another Envoy binary, pass --envoy-path or set the " +
			"envoy.path config key. The proxy does not check the hash of " +
			"that binary.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// The default log path holds the listen address, which
			// the flags set. An empty --envoy-log value is a choice
			// of the user, so only a missing flag selects the default.
			usr.EnvoyLogPath = opts.envoyLog
			if !cmd.Flags().Changed(usr.Flags.EnvoyLogPath) {
				usr.EnvoyLogPath = proxyEnvoyLogDefault(opts)
			}

			return Proxy(cmd.Context(), usr, inst, opts)
		},
	}

	cmd.Flags().IntVar(&opts.httpPort, "http-port", 8080,
		"port for the HTTP proxy listener")
	cmd.Flags().StringVar(&opts.bindAddress, "bind-address", loopbackIPv4,
		"bind the proxy listener to this IP address")
	cmd.Flags().StringVar(&opts.caOut, "ca-out", "",
		"write the MITM CA certificate PEM to this path (only when the policy has L7 rules)")
	cmd.Flags().StringVar(&opts.caBundleOut, "ca-bundle-out", "",
		"write the system CA bundle plus the MITM CA to this path, for clients that read one trust file")
	cmd.Flags().StringSliceVar(&opts.resolvers, "resolver", nil,
		"upstream DNS resolver as ip:port (default: system resolver)")
	cmd.Flags().StringVar(&opts.envoyPath, "envoy-path", "",
		"Envoy binary to run without a hash check, as a path or a command on PATH "+
			"(default: the managed build)")

	// The proxy runs as the invoking user and does not intercept DNS,
	// so it does not register the UID flags of the container modes.
	usr.RegisterFlags(cmd.Flags(),
		usr.Flags.CADir,
		usr.Flags.CertsDir,
		usr.Flags.EnvoyConfigPath,
		usr.Flags.ReadyFile,
	)

	// The proxy registers this flag itself, because the default of
	// [config.User.RegisterFlags] is the log file of container mode.
	// The command fills in the default of the proxy when it runs.
	cmd.Flags().StringVar(&opts.envoyLog, usr.Flags.EnvoyLogPath, "",
		"Envoy process log file path, or an empty value to log to stderr "+
			"(default: "+config.ProxyEnvoyLogDefault("<bind-address>-<http-port>")+")")

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

// proxyEnvoyPath returns the name of the Envoy binary that replaces the
// managed build. The value of the --envoy-path flag in opts takes
// priority over the envoy.path key of cfg. An empty result selects the
// managed build.
func proxyEnvoyPath(cfg *config.Config, opts proxyOptions) string {
	if opts.envoyPath != "" {
		return opts.envoyPath
	}

	return cfg.EnvoyDefaults().Path
}

// proxyInstanceName returns the name that the default file paths of
// one proxy hold: the bind address and the port of opts, such as
// 127.0.0.1-8080. At most one proxy serves a listen address, so the
// names of two running proxies differ.
//
// The name is one path element, because an underscore replaces each
// path separator of the bind address.
func proxyInstanceName(opts proxyOptions) string {
	addr := strings.ReplaceAll(opts.bindAddress, string(filepath.Separator), "_")

	return addr + "-" + strconv.Itoa(opts.httpPort)
}

// proxyBootstrapPath returns the proxy-mode Envoy bootstrap path: the
// file envoy-proxy-<name>.yaml next to the container-mode bootstrap.
// The [proxyInstanceName] of opts stands for <name>. A proxy therefore
// never replaces the bootstrap of container mode or of a proxy on
// another listen address. Of usr.EnvoyConfigPath, only the directory
// changes the path.
func proxyBootstrapPath(usr *config.User, opts proxyOptions) string {
	return filepath.Join(filepath.Dir(usr.EnvoyConfigPath),
		"envoy-proxy-"+proxyInstanceName(opts)+".yaml")
}

// proxyEnvoyLogDefault returns the Envoy process log path of a proxy
// that runs without the --envoy-log flag. See
// [config.ProxyEnvoyLogDefault] for the path.
func proxyEnvoyLogDefault(opts proxyOptions) string {
	return config.ProxyEnvoyLogDefault(proxyInstanceName(opts))
}

// proxyStatsSocket returns the access log socket path of the proxy
// with opts, which is the stats.socket of cfg. When cfg does not set
// one, the path is the result of [config.ProxyStatsSocketDefault] for
// the [proxyInstanceName] of opts. Proxies on different listen
// addresses therefore have different default sockets.
func proxyStatsSocket(cfg *config.Config, opts proxyOptions) string {
	return cfg.StatsSocket(config.ProxyStatsSocketDefault(proxyInstanceName(opts)))
}

// proxyEnvoyArgs returns the arguments of the Envoy that a proxy runs
// on the operating system goos, which is a value of [runtime.GOOS].
// Envoy loads the bootstrap at bootstrapPath and logs at logLevel. It
// writes its process log to logPath, or to its stderr when logPath is
// empty.
//
// Without the --concurrency argument, Envoy counts the CPUs of the host
// while it parses its arguments, before it applies --log-level and
// --log-path. On every system but Linux, it logs a debug line about
// that count at that moment. The line reaches the stderr of Envoy at
// every log level, also when Envoy has a log file. The arguments for
// those systems therefore set --concurrency to the number of logical
// CPUs, which is the count of Envoy there.
//
// On Linux, Envoy does not log that line, and its count also honors
// the CPU limit of the cgroup. The arguments for Linux leave that count
// to Envoy.
func proxyEnvoyArgs(goos, bootstrapPath, logLevel, logPath string) []string {
	args := []string{
		"-c", bootstrapPath,
		"--log-level", logLevel,
		// Hot restart uses a shared-memory region keyed by base-id.
		// Disabling it lets multiple Envoys coexist on one host.
		"--disable-hot-restart",
	}

	if logPath != "" {
		args = append(args, "--log-path", logPath)
	}

	if goos != osLinux {
		args = append(args, "--concurrency", strconv.Itoa(runtime.NumCPU()))
	}

	return args
}

// prepareProxyEnvoyLog creates the Envoy process log file at path, and
// its parent directory, before Envoy opens the file.
//
// A new file has mode 0o600, because a verbose Envoy log level records
// request headers. Envoy appends to the file, so an existing file keeps
// its contents and its mode.
func prepareProxyEnvoyLog(path string) error {
	err := os.MkdirAll(filepath.Dir(path), 0o755)
	if err != nil {
		return fmt.Errorf("creating envoy log directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // G304: path from CLI flags.
	if err != nil {
		return fmt.Errorf("creating envoy log file: %w", err)
	}

	err = f.Close()
	if err != nil {
		return fmt.Errorf("closing envoy log file: %w", err)
	}

	return nil
}

// createReadyFile creates an empty file at path to signal that the
// proxy accepts connections.
func createReadyFile(path string) error {
	f, err := os.Create(path) //nolint:gosec // G304: path from CLI flags.
	if err != nil {
		return fmt.Errorf("creating ready file: %w", err)
	}

	err = f.Close()
	if err != nil {
		return fmt.Errorf("closing ready file: %w", err)
	}

	return nil
}

// removeReadyFile removes the ready file at path. A missing file is
// not an error.
//
// It returns [ErrReadyFileIsDir] and leaves path in place when path is
// a directory. It removes a symbolic link, not the target of the link.
func removeReadyFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("checking ready file: %w", err)
	}

	if info.IsDir() {
		return fmt.Errorf("%w: %s", ErrReadyFileIsDir, path)
	}

	err = os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing ready file: %w", err)
	}

	return nil
}

// GenerateProxy reads the policy from usr.ConfigPath and generates
// MITM certs for restricted rules. It writes the proxy-mode Envoy
// bootstrap and exports the CA files that opts names, then returns the
// parsed config and the bootstrap path.
//
// The proxy reuses the CA in usr.CADir across runs, so clients that
// trust it keep working after a restart. See [exportCA] for the files
// it exports.
//
// See [GenerateProxyEnvoyFromConfig] for the probeToken argument.
func GenerateProxy(
	ctx context.Context, usr *config.User, opts proxyOptions, probeToken string,
) (*config.Config, string, error) {
	data, err := os.ReadFile(usr.ConfigPath)
	if err != nil {
		return nil, "", fmt.Errorf("reading config: %w", err)
	}

	cfg, err := parseConfig(ctx, data)
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

		warnUntrustedCA(ctx, caPath)

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
		opts.bindAddress, opts.httpPort, resolvers, probeToken)
	if err != nil {
		return nil, "", fmt.Errorf("generating envoy config: %w", err)
	}

	path := proxyBootstrapPath(usr, opts)

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
//
// When stats is enabled, the access loggers send to the socket that
// [proxyStatsSocket] returns for bindAddress and httpPort. Each
// decision gives one log entry. The access loggers of the front
// listener skip each request that the listener passes to an internal
// listener, because the access loggers of the internal listener log
// the decision for that request.
//
// When probeToken is not empty, the front listener answers the probe
// request of [waitForProxyListener] for that token. Envoy then loads
// the bootstrap only when the environment variable
// [envoy.ProxyProbeTokenEnv] is set. The access loggers skip the probe
// request.
func GenerateProxyEnvoyFromConfig(
	ctx context.Context,
	cfg *config.Config,
	certsDir, caBundlePath string,
	bindAddress string,
	httpPort int,
	resolvers []netip.AddrPort,
	probeToken string,
) (string, error) {
	// Resolve open (toPorts-only) rules once; both the policy check and
	// the filtered-mode assembly consume them.
	openPortRules := cfg.ResolveOpenPortRules(ctx)

	err := checkProxyPolicy(ctx, cfg, openPortRules)
	if err != nil {
		return "", err
	}

	als := newALSConfig(ctx, cfg, proxyStatsSocket(cfg,
		proxyOptions{bindAddress: bindAddress, httpPort: httpPort}))

	params := envoy.ProxyListenerParams{
		BindAddress: bindAddress,
		Port:        httpPort,
		AccessLog:   als.httpListenerLog("proxy"),
		Resolvers:   resolvers,
		ProbeToken:  probeToken,
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
		openTCP := openTCPPorts(openPortRules)

		// Proxy mode opens only the single TCP ports of toPorts-only
		// rules. A UDP entry or a port range keeps the HTTP rules of
		// a CIDR rule on its port.
		err = checkCatchAllL7Ports(ctx, cfg, openTCP)
		if err != nil {
			return "", err
		}

		params.Mode = envoy.ProxyModeFiltered
		listeners, allRules, tlsPorts = assembleFilteredProxy(
			ctx, cfg, als, certsDir, resolvers, openTCP, &params)
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

// proxyShutdownSignals returns the signals that shut [Proxy] down.
// SIGHUP is one of them unless the process started with SIGHUP
// ignored, because a handler for SIGHUP ends that ignore.
func proxyShutdownSignals() []os.Signal {
	sigs := []os.Signal{os.Interrupt, syscall.SIGTERM}
	if !signal.Ignored(syscall.SIGHUP) {
		sigs = append(sigs, syscall.SIGHUP)
	}

	return sigs
}

// newProbeToken returns a random token that identifies the bootstrap
// and the Envoy of one proxy run. See [waitForProxyListener] for its
// use.
func newProbeToken() (string, error) {
	b := make([]byte, 16)

	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("generating probe token: %w", err)
	}

	return hex.EncodeToString(b), nil
}

// Proxy generates the proxy-mode bootstrap, starts Envoy on the
// host, and supervises it until a signal arrives or Envoy exits. No
// root, network namespaces, or nftables involved: the only privilege
// needed is binding the listen port.
//
// Proxy runs the managed Envoy build of inst and checks the hash of
// that binary before every start. It installs the build when the build
// is missing. When [proxyEnvoyPath] names a binary, Proxy runs that
// binary without a hash check and does not use inst. See [resolveEnvoy]
// for the errors of both cases.
//
// When the host cannot execute the managed build, the error of Proxy
// names the --envoy-path flag and the envoy.path config key. See
// [envoyBinary.startError] for the causes that the error also names.
// The error also names the flag and the key when the managed build
// exits with the status of a dynamic loader that cannot run it. See
// [envoyBinary.exitError].
//
// The kernel does not execute a binary that a process holds open for
// writing. An install that ended a moment ago can leave the managed
// build in that state for a short time. Proxy therefore starts such a
// binary again after a pause. See [startEnvoyWhenFree] for the pauses
// and for the error of a binary that stays in that state.
//
// Envoy writes its process log to the logging.envoy.path of the policy,
// or to usr.EnvoyLogPath when the policy does not set one. When both
// are empty, Envoy logs to the stderr of the proxy. See
// [proxyEnvoyArgs] for the arguments of Envoy.
//
// When usr.ReadyFile is set, Proxy creates that file after its own
// Envoy answers on the listen address and removes it before it returns.
// Proxy also removes a ready file that an earlier run left behind, so
// the file exists only while the proxy is ready. Proxy returns
// [ErrReadyFileIsDir] before it starts Envoy when usr.ReadyFile is a
// directory.
//
// Proxy returns [ErrListenAddressUnavailable] before it starts Envoy
// when it cannot bind the listen address, for example because another
// process holds the port or because opts.bindAddress is not an IP
// address. A refused start still removes usr.ReadyFile, also when a
// running proxy that shares the path created it. Proxy cannot tell that
// file from a stale one.
//
// At most one process serves the listen address, because the front
// listener does not set SO_REUSEPORT. Another process can still take
// the address after the check, for example a second proxy that starts
// at the same moment. Proxy therefore reports that it is ready only
// after its own Envoy answers a probe request on the listen address.
// See [waitForProxyListener] for the probe. When another process
// answers the probe, Proxy stops its Envoy and returns
// [ErrListenAddressUnavailable].
//
// Proxies on different listen addresses write their bootstraps to
// different paths, see [proxyBootstrapPath]. Two proxies on one listen
// address that share a bootstrap directory write their bootstraps to
// one path. When they start at the same moment, both can return an
// error. The Envoy of one proxy can load the bootstrap of the other
// proxy and then take the address. No proxy accepts the probe answer of
// that Envoy.
//
// Proxy opens the event store and the access log socket after its own
// Envoy answers the probe, and before it reports that it is ready. A
// proxy that does not serve its address therefore leaves the access log
// socket of a running proxy in place.
//
// Proxies on different listen addresses open different default sockets,
// see [proxyStatsSocket]. Proxies whose policies set one stats.socket
// share that path. Opening the socket removes the socket of another
// proxy at the same path. When the Envoy of that proxy connects again,
// it sends its events to the proxy that started last.
//
// Envoy might lose the events of the requests that it serves before
// Proxy opens the socket. It buffers the events until the next flush of
// the access log, and it drops them when the socket does not exist at
// that flush.
//
// A proxy that records stats keeps Envoy running for a short time
// after a signal or a cancellation of ctx. Envoy sends its buffered
// events only at the next flush of the access log, and it drops them
// when it stops before that flush. See [accessLogFlushWait] for the
// length of the wait. Envoy still serves requests during the wait, and
// the store might not hold the events of those requests.
//
// Envoy runs in a process group of its own. The signals that a
// terminal sends to its foreground group, such as the SIGINT of a
// Ctrl-C, therefore reach the proxy and not Envoy. On Linux, the kernel
// kills Envoy when the proxy dies. On other systems, Envoy keeps
// running when a signal kills the proxy without a shutdown, such as a
// SIGKILL or a SIGQUIT that reaches the process group of the proxy.
//
// SIGINT, SIGTERM, and SIGHUP shut the proxy down. A hangup of the
// terminal sends SIGHUP to the proxy and not to Envoy, so the proxy
// stops Envoy after a hangup as well. A proxy that starts with SIGHUP
// ignored, such as under nohup, keeps ignoring it.
//
// A signal or a cancellation of ctx stops Envoy and makes Proxy return
// nil. Proxy also returns nil when either arrives before Envoy starts,
// which includes the install of the managed build, or before Envoy
// answers the probe. Proxy returns [ErrEnvoyNotRunning] when Envoy
// exits by itself or does not answer the probe within the startup
// timeout. When Envoy exits before it answers the probe, Proxy returns
// without a wait for the startup timeout, and the error also wraps
// [ErrEnvoyExited] and gives the exit status of Envoy.
func Proxy(ctx context.Context, usr *config.User, inst *envoybin.Installer, opts proxyOptions) error {
	ctx, stop := signal.NotifyContext(ctx, proxyShutdownSignals()...)
	defer stop()

	if usr.ReadyFile != "" {
		err := removeReadyFile(usr.ReadyFile)
		if err != nil {
			return err
		}
	}

	probeToken, err := newProbeToken()
	if err != nil {
		return err
	}

	cfg, bootstrapPath, err := GenerateProxy(ctx, usr, opts, probeToken)
	if err != nil {
		return err
	}

	envoyBin, err := resolveEnvoy(ctx, inst, proxyEnvoyPath(cfg, opts))
	if err != nil {
		if ctx.Err() != nil {
			// The shutdown arrived before Envoy started. It ends an
			// install of the managed build with an error.
			slog.InfoContext(ctx, "proxy: shut down")

			return nil
		}

		return err
	}

	// Envoy holds the binary open itself after it starts.
	defer func() {
		closeErr := envoyBin.Close()
		if closeErr != nil {
			slog.DebugContext(ctx, "closing envoy binary", slog.Any("err", closeErr))
		}
	}()

	addr := net.JoinHostPort(opts.bindAddress, strconv.Itoa(opts.httpPort))

	// Refuse to start while another process listens on addr, before
	// the proxy starts an Envoy that cannot bind addr.
	err = checkListenAddress(ctx, addr)
	if err != nil {
		return err
	}

	envoySettings := cfg.EnvoyDefaults()

	envoyLogPath := cfg.EnvoyLogPath(usr.EnvoyLogPath)
	if envoyLogPath != "" {
		err = prepareProxyEnvoyLog(envoyLogPath)
		if err != nil {
			return err
		}

		// The Envoy log does not reach the terminal, so name the
		// file before Envoy starts.
		slog.InfoContext(ctx, "proxy: starting envoy",
			slog.String("envoy_log", envoyLogPath))
	}

	envoyArgs := proxyEnvoyArgs(runtime.GOOS, bootstrapPath, cfg.EnvoyLogLevel(), envoyLogPath)

	// Envoy runs until envoyCtx ends, so that it can outlive ctx by
	// the wait for its last events. Proxy ends envoyCtx after ctx
	// ends, and when it returns.
	envoyCtx, cancelEnvoy := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelEnvoy()

	newCmd := func() *exec.Cmd {
		cmd := envoyBin.command(envoyCtx, envoyArgs...)

		// Envoy writes here what it does not send to its log file,
		// such as a command line that it rejects and the lines of its
		// stderr access logs. Envoy runs in a background process
		// group, and a terminal with tostop stops a background
		// process that writes to it. The writers are therefore not
		// files, so that os/exec gives Envoy pipes and the proxy, in
		// the foreground group, copies the output to the terminal.
		// WaitDelay bounds the copy after Envoy exits.
		cmd.Stdout = struct{ io.Writer }{os.Stdout}
		cmd.Stderr = struct{ io.Writer }{os.Stderr}

		// The probe answer of Envoy holds the value of this variable,
		// so the answer names the Envoy of this proxy, whichever
		// bootstrap that Envoy loaded.
		cmd.Env = append(os.Environ(), envoy.ProxyProbeTokenEnv+"="+probeToken)

		cmd.SysProcAttr = proxyEnvoyProcAttr()

		// When envoyCtx ends, drain gracefully: SIGTERM first,
		// SIGKILL after the drain timeout.
		cmd.Cancel = func() error {
			return cmd.Process.Signal(syscall.SIGTERM)
		}
		cmd.WaitDelay = envoySettings.DrainTimeout.Duration

		return cmd
	}

	// An install of the managed build that ended a moment ago can
	// leave the binary busy.
	proc, err := startEnvoyWhenFree(ctx, newCmd)
	if err != nil {
		if ctx.Err() != nil {
			// The shutdown arrived before Envoy started. After ctx
			// ends, startEnvoyWhenFree starts no command, and a
			// start that returns an error leaves no process, so
			// Proxy has no process to reap.
			slog.InfoContext(ctx, "proxy: shut down")

			return nil
		}

		return envoyBin.startError(err)
	}

	// A connection to addr can reach a process that took addr after
	// the check, so wait for the probe answer of this Envoy.
	err = waitForProxyListener(ctx, addr, probeToken, proc.exited,
		envoySettings.StartupTimeout.Duration)

	// The time that Envoy keeps running after ctx ends. It stays zero
	// for a proxy without an access log server, which has no events to
	// wait for.
	var flushWait time.Duration

	switch {
	case err == nil:
		// Only the proxy whose Envoy serves addr opens the event
		// store and the access log socket. A second proxy on addr can
		// share those paths with the first proxy, and opening the
		// access log socket removes the socket of the first proxy.
		store := openProxyEventStore(ctx, cfg, usr, opts)

		defer func() {
			closeErr := store.Close() //nolint:contextcheck // shutdown flush must not inherit a canceled ctx.
			if closeErr != nil {
				slog.DebugContext(ctx, "closing event store", slog.Any("err", closeErr))
			}
		}()

		// A proxy that stops without closing the store records no
		// end. The heartbeat is then the only sign in the store that
		// the proxy stopped. The store closes after the last
		// heartbeat, because the deferred calls run in reverse order.
		//
		// Envoy sends its last events after ctx ends, so the
		// heartbeat runs on a context that outlives ctx. The deferred
		// stop runs after Envoy has exited and after the access log
		// server has shut down, so the store has received those
		// events. The store can commit the last of them after the
		// final heartbeat, at a tick of its writer or at Close. Close
		// then raises the last write and the drop count of the final
		// heartbeat to the values after its last commit.
		stopHeartbeat := startHeartbeat(context.WithoutCancel(ctx), store, nil)
		defer stopHeartbeat()

		// Envoy serves the policy, so record it as the policy in
		// force. The snapshot comes before the ready file, so a
		// process that waits for the file finds the snapshot queued.
		recordPolicySnapshot(ctx, store, cfg, usr.ConfigPath)

		accessLogSrv := openProxyAccessLog(ctx, cfg, store, opts)
		if accessLogSrv != nil {
			defer accessLogSrv.Shutdown(context.WithoutCancel(ctx))

			flushWait = accessLogFlushWait(cfg, envoySettings.DrainTimeout.Duration)
		}

		if usr.ReadyFile != "" {
			err = createReadyFile(usr.ReadyFile)
			if err != nil {
				stopEnvoy(ctx, proc, envoySettings.DrainTimeout.Duration)

				return err
			}

			defer func() {
				removeErr := removeReadyFile(usr.ReadyFile)
				if removeErr != nil {
					slog.WarnContext(ctx, "proxy: ready file left behind",
						slog.Any("err", removeErr))
				}
			}()
		}

		slog.InfoContext(ctx, "proxy: ready",
			slog.String("address", addr),
			slog.String("bootstrap", bootstrapPath))

	case ctx.Err() != nil:
		// The shutdown arrived before the listener came up. An early
		// shutdown is not a startup failure, so Proxy reaps Envoy the
		// same way as after the shutdown of a ready proxy.

	case errors.Is(err, ErrListenAddressUnavailable):
		// Another process serves addr. Envoy keeps running without
		// its listener when it bound addr before that process
		// listened there.
		stopEnvoy(ctx, proc, envoySettings.DrainTimeout.Duration)

		return err

	case errors.Is(err, ErrEnvoyExited):
		// The process state exists, because the wait for the process
		// has returned.
		return envoyBin.exitError(err, proc.cmd.ProcessState)

	default:
		stopEnvoy(ctx, proc, envoySettings.DrainTimeout.Duration)

		return fmt.Errorf("%w: %w", ErrEnvoyNotRunning, err)
	}

	select {
	case <-proc.exited:
	case <-ctx.Done():
		// Envoy drops the events that it still holds when it stops,
		// so it keeps running until it has sent them.
		waitForAccessLogFlush(ctx, flushWait, proc.exited)
		cancelEnvoy()
	}

	err = proc.wait()
	if ctx.Err() != nil {
		// Signal-initiated shutdown: the end of envoyCtx sent
		// SIGTERM to Envoy.
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
//
// The instance row of the store tells two proxies apart. It holds the
// [proxyInstanceName] of opts and the path of the config file of usr.
// Proxies on different listen addresses can share one database, and
// each of them adds its own instance row.
func openProxyEventStore(
	ctx context.Context, cfg *config.Config, usr *config.User, opts proxyOptions,
) *eventstore.Store {
	if !cfg.StatsEnabled() {
		return nil
	}

	path := cfg.StatsPath(config.StatsDBDefault())
	perSource := cfg.StatsRetentionPerSource()

	store, err := eventstore.Open(ctx, path,
		eventstore.WithMode(eventstore.ModeProxy),
		eventstore.WithInstanceName(proxyInstanceName(opts)),
		eventstore.WithConfigPath(absConfigPath(usr.ConfigPath)),
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

// openProxyAccessLog binds the gRPC AccessLog UDS of the proxy with
// opts when stats is enabled. See [proxyStatsSocket] for the socket
// path. The invoking user can create the default socket without root.
// On failure it logs and returns nil, so stats ingestion never blocks
// the data plane.
//
// The socket has mode 0o600. Envoy runs as the invoking user in proxy
// mode, so the owner is the only user who must connect. The default
// socket directory can be open to other local users, and a wider mode
// lets a member of the socket's group write forged events.
func openProxyAccessLog(
	ctx context.Context, cfg *config.Config, store *eventstore.Store, opts proxyOptions,
) *accesslog.Server {
	if !cfg.StatsEnabled() || store == nil {
		return nil
	}

	socket := proxyStatsSocket(cfg, opts)

	srv, err := accesslog.Start(ctx, socket, store,
		accesslog.WithSocketMode(0o600))
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
