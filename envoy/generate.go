package envoy

import (
	"bytes"
	"fmt"

	"go.jacobcolvin.com/niceyaml"

	"go.jacobcolvin.com/terrarium/config"
)

// BuildAccessLog returns Envoy stderr access log config when logging is
// enabled, or nil when disabled.
func BuildAccessLog(logging bool) []AccessLog {
	if !logging {
		return nil
	}

	return []AccessLog{{
		Name: "envoy.access_loggers.stderr",
		TypedConfig: typeOnly{
			AtType: "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StderrAccessLog",
		},
	}}
}

// stripL7Restrictions converts restricted rules to passthrough by
// clearing their HTTPRules. This implements Cilium's OR semantics
// between open port rules and FQDN+L7 rules on the same port: the
// open port allows ALL traffic, overriding any L7 restrictions.
func stripL7Restrictions(rules []config.ResolvedRule) []config.ResolvedRule {
	result := make([]config.ResolvedRule, len(rules))
	for i, r := range rules {
		result[i] = config.ResolvedRule{Domain: r.Domain}
	}

	return result
}

// GenerateConfig builds an Envoy bootstrap YAML configuration
// using per-port rule resolution. Port 443 traffic is matched by TLS
// SNI, port 80 by HTTP Host header. Domains with path restrictions
// are MITM'd via TLS termination using certs from certsDir. Each
// [config.TCPForward] entry creates a plain TCP proxy listener with a
// STRICT_DNS cluster. Open ports (from toPorts-only rules) get
// catch-all passthrough chains.
func GenerateConfig(cfg *config.Config, certsDir, caBundlePath string) (string, error) {
	accessLog := BuildAccessLog(cfg.Logging)

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

	var listeners []listener

	// Only build 443/80 listeners when ResolvePorts includes them.
	if resolvedPortSet[443] {
		rules443 := cfg.ResolveRulesForPort(443)

		if openPortSet[443] {
			rules443 = stripL7Restrictions(rules443)
		}

		listeners = append(
			listeners,
			buildTLSListener(
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
			rules80 = stripL7Restrictions(rules80)
		}

		listeners = append(listeners, buildHTTPForwardListener(rules80, openPortSet[80], accessLog))
	}

	for _, fwd := range cfg.TCPForwards {
		name := fmt.Sprintf("tcp_forward_%d", fwd.Port)
		listeners = append(listeners, buildTCPForwardListener(name, config.ProxyPortBase+fwd.Port, name, accessLog))
	}

	// Extra port listeners support both passthrough and MITM (when L7
	// rules with path/method restrictions are present and certsDir is set).
	for _, p := range cfg.ExtraPorts() {
		rulesP := cfg.ResolveRulesForPort(p)

		if openPortSet[p] {
			rulesP = stripL7Restrictions(rulesP)
		}

		listeners = append(listeners, buildTLSListener(
			fmt.Sprintf("tls_passthrough_%d", p),
			config.ProxyPortBase+p, p,
			fmt.Sprintf("tls_passthrough_%d", p),
			rulesP, openPortSet[p], accessLog, certsDir,
		))
	}

	// Use global rules for cluster determination.
	allRules := cfg.ResolveRules()

	bs := bootstrap{
		OverloadManager: overloadManager{
			ResourceMonitors: []namedTyped{{
				Name: "envoy.resource_monitors.global_downstream_max_connections",
				TypedConfig: downstreamConnectionsConfig{
					AtType:                         "type.googleapis.com/envoy.extensions.resource_monitors.downstream_connections.v3.DownstreamConnectionsConfig",
					MaxActiveDownstreamConnections: 65535,
				},
			}},
		},
		StaticResources: staticResources{
			Listeners: listeners,
			Clusters:  buildClusters(allRules, cfg.TCPForwards, caBundlePath),
		},
	}

	var buf bytes.Buffer

	err := niceyaml.NewEncoder(&buf).Encode(bs)
	if err != nil {
		return "", fmt.Errorf("marshaling envoy config: %w", err)
	}

	return buf.String(), nil
}
