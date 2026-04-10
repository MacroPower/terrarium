package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.jacobcolvin.com/niceyaml"

	"go.jacobcolvin.com/terrarium/certs"
	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/envoy"
)

// Generate reads terrarium YAML config from usr.ConfigPath, resolves
// domains and ports, generates MITM certs for path-restricted rules,
// and writes the Envoy config file to usr.EnvoyConfigPath. Firewall
// rules are applied directly via nftables netlink in [Init], not
// written to files. The parsed [*Config] is returned so callers can
// reuse it without re-parsing.
func Generate(ctx context.Context, usr *config.User, vmMode bool) (*config.Config, error) {
	data, err := os.ReadFile(usr.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	cfg, err := config.ParseConfig(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Collect domains that need MITM certs (restricted on any TLS port).
	tlsPorts := []int{443}
	tlsPorts = append(tlsPorts, cfg.ExtraPorts(ctx)...)
	mitmSeen := make(map[string]bool)

	var mitmRules []config.ResolvedRule
	for _, port := range tlsPorts {
		portRules := cfg.ResolveRulesForPort(ctx, port)

		for _, r := range portRules {
			if r.IsRestricted() && !mitmSeen[r.Domain] {
				mitmSeen[r.Domain] = true
				mitmRules = append(mitmRules, r)
			}
		}
	}

	certsDir := ""
	if len(mitmRules) > 0 {
		err := certs.Generate(mitmRules, usr.CADir, usr.CertsDir)
		if err != nil {
			return nil, fmt.Errorf("generating certs: %w", err)
		}

		certsDir = usr.CertsDir
	}

	caBundlePath := certs.FindCABundle()
	envoyConf, err := GenerateEnvoyFromConfig(
		ctx,
		cfg,
		certsDir,
		caBundlePath,
		cfg.EnvoyAccessLogPath(usr.EnvoyAccessLogPath),
		vmMode,
	)
	if err != nil {
		return nil, fmt.Errorf("generating envoy config: %w", err)
	}

	err = os.MkdirAll(filepath.Dir(usr.EnvoyConfigPath), 0o755)
	if err != nil {
		return nil, fmt.Errorf("creating envoy config directory: %w", err)
	}

	err = os.WriteFile(usr.EnvoyConfigPath, []byte(envoyConf), 0o644)
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
func GenerateEnvoyFromConfig(
	ctx context.Context,
	cfg *config.Config,
	certsDir, caBundlePath, accessLogPath string,
	vmMode bool,
) (string, error) {
	accessLog := envoy.BuildAccessLog(cfg.EnvoyAccessLogEnabled(), cfg.EnvoyAccessLogFormat(), accessLogPath)

	resolvedPorts := cfg.ResolvePorts(ctx)

	resolvedPortSet := make(map[int]bool, len(resolvedPorts))
	for _, p := range resolvedPorts {
		resolvedPortSet[p] = true
	}

	openPorts := cfg.ResolveOpenPorts(ctx)

	openPortSet := make(map[int]bool, len(openPorts))
	for _, p := range openPorts {
		openPortSet[p] = true
	}

	var listeners []envoy.Listener

	// In non-blocked modes, always build 443/80 listeners and the
	// catch-all TCP listener for centralized access logging.
	if !cfg.IsEgressBlocked() {
		listeners = append(listeners,
			buildTLSPassthroughListener(ctx, cfg, resolvedPortSet, openPortSet, accessLog, certsDir, vmMode),
			buildHTTPForwardListener(ctx, cfg, resolvedPortSet, openPortSet, accessLog, vmMode),
		)
	}

	for _, fwd := range cfg.TCPForwards {
		name := fmt.Sprintf("tcp_forward_%d", fwd.Port)
		listeners = append(
			listeners,
			envoy.BuildTCPForwardListener(name, config.ProxyPortBase+fwd.Port, name, accessLog, vmMode),
		)
	}

	// Extra port listeners support both passthrough and MITM (when L7
	// rules with path/method restrictions are present and certsDir is set).
	// ServerName rules from CIDR rules are merged so Envoy creates
	// SNI filter chains for them.
	for _, p := range cfg.ExtraPorts(ctx) {
		rulesP := cfg.ResolveRulesForPort(ctx, p)
		rulesP = append(rulesP, cfg.ResolveServerNameRulesForPort(ctx, p)...)

		if openPortSet[p] {
			rulesP = envoy.StripL7Restrictions(rulesP)
		}

		listeners = append(listeners, envoy.BuildTLSListener(
			fmt.Sprintf("tls_passthrough_%d", p),
			config.ProxyPortBase+p, p,
			fmt.Sprintf("tls_passthrough_%d", p),
			rulesP, openPortSet[p], accessLog, certsDir, vmMode,
		))
	}

	// CIDR catch-all listener for forwarding CIDR TCP traffic via
	// original_dst. Only needed when CIDR allow rules exist; the
	// NAT chain redirects matching TCP to this listener.
	if cfg.HasCIDRRules() {
		listeners = append(listeners,
			envoy.BuildCIDRCatchAllListener(config.CIDRCatchAllPort, accessLog, vmMode))
	}

	envoySettings := cfg.EnvoyDefaults()

	// Catch-all TCP and UDP listeners for non-blocked modes.
	if !cfg.IsEgressBlocked() {
		listeners = append(listeners,
			envoy.BuildCatchAllTCPListener(config.CatchAllProxyPort, cfg.IsEgressUnrestricted(), accessLog, vmMode),
			envoy.BuildCatchAllUDPListener(
				config.CatchAllUDPProxyPort, envoySettings.UDPIdleTimeout.Duration, accessLog, vmMode),
		)
	}

	// Use global rules for cluster determination.
	allRules := cfg.ResolveRules(ctx)

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
			Clusters:  envoy.BuildClusters(allRules, cfg.TCPForwards, len(listeners) > 0, caBundlePath),
		},
	}

	var buf bytes.Buffer

	err := niceyaml.NewEncoder(&buf).Encode(bs)
	if err != nil {
		return "", fmt.Errorf("marshaling envoy config: %w", err)
	}

	return buf.String(), nil
}

// buildTLSPassthroughListener creates the port 443 TLS listener. When
// FQDN rules resolve port 443, their rules drive the listener; otherwise
// an open passthrough listener is created for unrestricted auditing.
func buildTLSPassthroughListener(
	ctx context.Context,
	cfg *config.Config,
	resolvedPortSet, openPortSet map[int]bool,
	accessLog []envoy.AccessLog,
	certsDir string,
	transparent bool,
) envoy.Listener {
	rules := cfg.ResolveRulesForPort(ctx, 443)
	rules = append(rules, cfg.ResolveServerNameRulesForPort(ctx, 443)...)
	open := openPortSet[443]

	if !resolvedPortSet[443] {
		rules = nil
		open = true
	} else if open {
		rules = envoy.StripL7Restrictions(rules)
	}

	return envoy.BuildTLSListener(
		"tls_passthrough", 15443, 443, "tls_passthrough",
		rules, open, accessLog, certsDir, transparent,
	)
}

// buildHTTPForwardListener creates the port 80 HTTP listener. When
// FQDN rules resolve port 80, their rules drive the listener; otherwise
// an open HTTP forward listener is created for unrestricted auditing.
func buildHTTPForwardListener(
	ctx context.Context,
	cfg *config.Config,
	resolvedPortSet, openPortSet map[int]bool,
	accessLog []envoy.AccessLog,
	transparent bool,
) envoy.Listener {
	rules := cfg.ResolveRulesForPort(ctx, 80)
	open := openPortSet[80]

	if !resolvedPortSet[80] {
		rules = nil
		open = true
	} else if open {
		rules = envoy.StripL7Restrictions(rules)
	}

	return envoy.BuildHTTPForwardListener(rules, open, accessLog, transparent)
}
