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
// bootstrap config. When hasListeners is true, the original destination
// and dynamic forward proxy clusters are included alongside MITM and
// TCP forward clusters.
func BuildClusters(
	rules []config.ResolvedRule,
	tcpForwards []config.TCPForward,
	hasListeners bool,
	caBundlePath string,
) []cluster {
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

	// ORIGINAL_DST cluster for the catch-all TCP listener.
	// Envoy retrieves the real destination from conntrack via
	// SO_ORIGINAL_DST after nftables REDIRECT.
	if hasListeners {
		clusters = append(clusters, cluster{
			Name:           "original_dst",
			ConnectTimeout: "5s",
			Type:           "ORIGINAL_DST",
			LBPolicy:       "CLUSTER_PROVIDED",
		})
	}

	// Add the dynamic forward proxy cluster when there are FQDN rules
	// or listeners that reference it (open passthrough/HTTP listeners).
	if len(rules) > 0 || hasListeners {
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

		// Upstream SNI handling: Envoy v1.37+ requires explicit
		// auto_sni and auto_san_validation on DFP clusters that
		// set typed_extension_protocol_options. Earlier versions
		// auto-enabled both via the DFP cluster factory, but
		// v1.37 validates their presence at config time. Setting
		// them in upstream_http_protocol_options ensures the
		// upstream TLS handshake uses the correct SNI (derived
		// from the HTTP Host header) and validates the upstream
		// cert SAN against it.
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
					AtType: "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
					UpstreamHTTPProtocolOptions: &upstreamHTTPProtocolOptions{
						AutoSNI:           true,
						AutoSANValidation: true,
					},
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
