package envoy

import (
	"fmt"

	"go.jacobcolvin.com/terrarium/config"
)

func hasMITMRules(rules []config.ResolvedRule) bool {
	for _, r := range rules {
		if r.IsRestricted() {
			return true
		}
	}

	return false
}

// BuildClusters creates the static cluster definitions for the Envoy
// bootstrap config, including dynamic forward proxy, MITM, and TCP
// forward clusters as needed.
func BuildClusters(rules []config.ResolvedRule, tcpForwards []config.TCPForward, caBundlePath string) []cluster {
	// Static cluster with no endpoints used as the upstream for the
	// default filter chain on TLS listeners. Connections routed here
	// are immediately reset (no healthy upstream), which is the desired
	// behavior for missing-SNI connections after the access log fires.
	clusters := []cluster{{
		Name:           "missing_sni_blackhole",
		ConnectTimeout: "1s",
		Type:           "STATIC",
		LBPolicy:       "ROUND_ROBIN",
	}}

	// Only add the dynamic forward proxy cluster when there are FQDN rules.
	if len(rules) > 0 {
		clusters = append(clusters, cluster{
			Name:           "dynamic_forward_proxy_cluster",
			ConnectTimeout: "5s",
			LBPolicy:       "CLUSTER_PROVIDED",
			ClusterType: &clusterType{
				Name: "envoy.clusters.dynamic_forward_proxy",
				TypedConfig: clusterDFPConfig{
					AtType:         "type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig",
					DNSCacheConfig: sharedDNSCacheConfig,
				},
			},
		})
	}

	if hasMITMRules(rules) {
		upstreamTLS := upstreamTlsContext{
			AtType: "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
		}
		if caBundlePath != "" {
			upstreamTLS.CommonTlsContext = &upstreamCommonTlsContext{
				ValidationContext: &validationContext{
					TrustedCA: dataSource{Filename: caBundlePath},
				},
			}
		}

		// Upstream SNI handling: auto_sni and auto_san_validation are
		// intentionally omitted here. Envoy's dynamic forward proxy
		// (DFP) cluster factory auto-enables both when
		// upstream_http_protocol_options is absent. Specifically,
		// createClusterImpl in the DFP cluster factory checks whether
		// auto_sni is already set and enables it if not, then does
		// the same for auto_san_validation. If
		// upstream_http_protocol_options IS present, the factory
		// rejects configs that lack auto_sni/auto_san_validation
		// unless allow_insecure_cluster_options is set. Since this
		// cluster omits upstream_http_protocol_options entirely, the
		// factory unconditionally enables both options. The upstream
		// TLS handshake uses SNI derived from the HTTP Host header
		// via auto_sni.
		//
		// See Envoy source:
		//   source/extensions/clusters/dynamic_forward_proxy/cluster.cc
		//   (createClusterImpl method)
		//
		// Cilium achieves correct upstream SNI through a different
		// mechanism. Rather than auto_sni, Cilium uses its custom
		// cilium.tls_wrapper transport socket, which reads the sni_
		// field from Cilium policy filter state and passes it to
		// getClientTlsContext() in the proxylib layer. Cilium
		// explicitly avoids setting auto_sni because it would
		// conflict with (and crash Envoy when combined with) the
		// Cilium Network filter's own SNI injection -- the two
		// mechanisms would race to set the SNI on the upstream
		// connection.
		//
		// Both approaches produce the same result: correct SNI on
		// the upstream TLS handshake.
		clusters = append(clusters, cluster{
			Name:           "mitm_forward_proxy_cluster",
			ConnectTimeout: "5s",
			LBPolicy:       "CLUSTER_PROVIDED",
			ClusterType: &clusterType{
				Name: "envoy.clusters.dynamic_forward_proxy",
				TypedConfig: clusterDFPConfig{
					AtType:         "type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig",
					DNSCacheConfig: sharedDNSCacheConfig,
				},
			},
			TransportSocket: &transportSocket{
				Name:        "envoy.transport_sockets.tls",
				TypedConfig: upstreamTLS,
			},
			TypedExtensionProtocolOptions: map[string]any{
				"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": httpProtocolOptions{
					AtType:                      "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
					UseDownstreamProtocolConfig: useDownstreamProtocolConfig{},
				},
			},
		})
	}

	for _, fwd := range tcpForwards {
		name := fmt.Sprintf("tcp_forward_%d", fwd.Port)
		clusters = append(clusters, cluster{
			Name:           name,
			ConnectTimeout: "5s",
			Type:           "STRICT_DNS",
			LBPolicy:       "ROUND_ROBIN",
			LoadAssignment: &loadAssignment{
				ClusterName: name,
				Endpoints: []endpoint{{
					LBEndpoints: []lbEndpoint{{
						Endpoint: endpointAddress{
							Address: address{SocketAddress: socketAddress{
								Address: fwd.Host, PortValue: fwd.Port,
							}},
						},
					}},
				}},
			},
		})
	}

	return clusters
}
