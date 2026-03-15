package main

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"go.jacobcolvin.com/niceyaml"

	"go.jacobcolvin.com/terrarium/certs"
	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/envoy"
)

// CertsDir is the directory where MITM leaf certificates are stored.
const CertsDir = "/etc/terrarium/certs"

// CADir is the directory where terrarium CA cert and key are stored.
const CADir = "/etc/terrarium/ca"

// Generate reads terrarium YAML config at configPath, resolves domains
// and ports, generates MITM certs for path-restricted rules, and writes
// the Envoy config file to /etc. Firewall rules are applied directly
// via nftables netlink in [Init], not written to files. The parsed
// [*Config] is returned so callers can reuse it without re-parsing.
func Generate(ctx context.Context, configPath string) (*config.Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	cfg, err := config.ParseConfig(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Collect domains that need MITM certs (restricted on any TLS port).
	tlsPorts := []int{443}
	tlsPorts = append(tlsPorts, cfg.ExtraPorts()...)
	mitmSeen := make(map[string]bool)

	var mitmRules []config.ResolvedRule
	for _, port := range tlsPorts {
		portRules := cfg.ResolveRulesForPort(port)

		for _, r := range portRules {
			if r.IsRestricted() && !mitmSeen[r.Domain] {
				mitmSeen[r.Domain] = true
				mitmRules = append(mitmRules, r)
			}
		}
	}

	certsDir := ""
	if len(mitmRules) > 0 {
		err := certs.Generate(mitmRules, CADir, CertsDir)
		if err != nil {
			return nil, fmt.Errorf("generating certs: %w", err)
		}

		certsDir = CertsDir
	}

	caBundlePath := findCABundle()
	envoyConf, err := GenerateEnvoyFromConfig(cfg, certsDir, caBundlePath)
	if err != nil {
		return nil, fmt.Errorf("generating envoy config: %w", err)
	}

	err = os.WriteFile("/etc/envoy-terrarium.yaml", []byte(envoyConf), 0o644)
	if err != nil {
		return nil, fmt.Errorf("writing envoy config: %w", err)
	}

	return cfg, nil
}

// GenerateEnvoyFromConfig builds an Envoy bootstrap YAML configuration
// using per-port rule resolution. Port 443 traffic is matched by TLS
// SNI, port 80 by HTTP Host header. Domains with path restrictions
// are MITM'd via TLS termination using certs from certsDir. Each
// [config.TCPForward] entry creates a plain TCP proxy listener with a
// STRICT_DNS cluster. Open ports (from toPorts-only rules) get
// catch-all passthrough chains.
func GenerateEnvoyFromConfig(cfg *config.Config, certsDir, caBundlePath string) (string, error) {
	accessLog := envoy.BuildAccessLog(cfg.Logging)

	resolvedPorts := cfg.ResolvePorts()

	resolvedPortSet := make(map[int]bool, len(resolvedPorts))
	for _, p := range resolvedPorts {
		resolvedPortSet[p] = true
	}

	openPorts := cfg.ResolveOpenPorts()

	openPortSet := make(map[int]bool, len(openPorts))
	for _, p := range openPorts {
		openPortSet[p] = true
	}

	var listeners []envoy.Listener

	// Only build 443/80 listeners when ResolvePorts includes them.
	if resolvedPortSet[443] {
		rules443 := cfg.ResolveRulesForPort(443)

		if openPortSet[443] {
			rules443 = envoy.StripL7Restrictions(rules443)
		}

		listeners = append(
			listeners,
			envoy.BuildTLSListener(
				"tls_passthrough",
				15443,
				443,
				"tls_passthrough",
				rules443,
				openPortSet[443],
				accessLog,
				certsDir,
			),
		)
	}

	if resolvedPortSet[80] {
		rules80 := cfg.ResolveRulesForPort(80)

		if openPortSet[80] {
			rules80 = envoy.StripL7Restrictions(rules80)
		}

		listeners = append(listeners, envoy.BuildHTTPForwardListener(rules80, openPortSet[80], accessLog))
	}

	for _, fwd := range cfg.TCPForwards {
		name := fmt.Sprintf("tcp_forward_%d", fwd.Port)
		listeners = append(
			listeners,
			envoy.BuildTCPForwardListener(name, config.ProxyPortBase+fwd.Port, name, accessLog),
		)
	}

	// Extra port listeners support both passthrough and MITM (when L7
	// rules with path/method restrictions are present and certsDir is set).
	for _, p := range cfg.ExtraPorts() {
		rulesP := cfg.ResolveRulesForPort(p)

		if openPortSet[p] {
			rulesP = envoy.StripL7Restrictions(rulesP)
		}

		listeners = append(listeners, envoy.BuildTLSListener(
			fmt.Sprintf("tls_passthrough_%d", p),
			config.ProxyPortBase+p, p,
			fmt.Sprintf("tls_passthrough_%d", p),
			rulesP, openPortSet[p], accessLog, certsDir,
		))
	}

	// Use global rules for cluster determination.
	allRules := cfg.ResolveRules()

	bs := envoy.Bootstrap{
		OverloadManager: envoy.OverloadManager{
			ResourceMonitors: []envoy.NamedTyped{{
				Name: "envoy.resource_monitors.global_downstream_max_connections",
				TypedConfig: envoy.DownstreamConnectionsConfig{
					AtType:                         "type.googleapis.com/envoy.extensions.resource_monitors.downstream_connections.v3.DownstreamConnectionsConfig",
					MaxActiveDownstreamConnections: 65535,
				},
			}},
		},
		StaticResources: envoy.StaticResources{
			Listeners: listeners,
			Clusters:  envoy.BuildClusters(allRules, cfg.TCPForwards, caBundlePath),
		},
	}

	var buf bytes.Buffer

	err := niceyaml.NewEncoder(&buf).Encode(bs)
	if err != nil {
		return "", fmt.Errorf("marshaling envoy config: %w", err)
	}

	return buf.String(), nil
}

// findCABundle returns the path to the system CA certificate bundle.
// Checks SSL_CERT_FILE and NIX_SSL_CERT_FILE env vars first, then
// well-known filesystem paths.
func findCABundle() string {
	candidates := []string{
		os.Getenv("SSL_CERT_FILE"),
		os.Getenv("NIX_SSL_CERT_FILE"),
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/ssl/certs/ca-bundle.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}

		_, err := os.Stat(c) //nolint:gosec // G703: paths are hardcoded candidates.
		if err == nil {
			return c
		}
	}

	return ""
}
