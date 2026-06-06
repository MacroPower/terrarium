package envoy

import (
	"fmt"
	"net"

	"go.jacobcolvin.com/terrarium/config"
)

// MissingSNIBlackholeCluster is the static-no-endpoints cluster name
// used as the upstream for catch-all TCP traffic that should be
// denied. Routing here yields NoHealthyUpstream (response_flags=NH)
// without an ECONNREFUSED at the kernel layer; the access log
// translator keys on that to recognize a TCP deny.
const MissingSNIBlackholeCluster = "missing_sni_blackhole"

// originalDstCluster is the name of the ORIGINAL_DST cluster the
// catch-all TCP listener forwards to. Envoy recovers the destination
// from conntrack via SO_ORIGINAL_DST after nftables REDIRECT.
const originalDstCluster = "original_dst"

// dynamicForwardProxyCluster is the name of the cluster FQDN-based
// egress is routed through by the dynamic forward proxy.
const dynamicForwardProxyCluster = "dynamic_forward_proxy_cluster"

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
		Name:           MissingSNIBlackholeCluster,
		ConnectTimeout: "1s",
		Type:           clusterTypeStatic,
		LBPolicy:       lbPolicyRoundRobin,
	}}

	// ORIGINAL_DST cluster for the catch-all TCP listener.
	// Envoy retrieves the real destination from conntrack via
	// SO_ORIGINAL_DST after nftables REDIRECT.
	if hasListeners {
		clusters = append(clusters, cluster{
			Name:           originalDstCluster,
			ConnectTimeout: "5s",
			Type:           "ORIGINAL_DST",
			LBPolicy:       lbPolicyClusterProvided,
		})
	}

	// Add the dynamic forward proxy cluster when there are FQDN rules
	// or listeners that reference it (open passthrough/HTTP listeners).
	if len(rules) > 0 || hasListeners {
		clusters = append(clusters, cluster{
			Name:           dynamicForwardProxyCluster,
			ConnectTimeout: "5s",
			LBPolicy:       lbPolicyClusterProvided,
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
			LBPolicy:       lbPolicyClusterProvided,
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
					AutoConfig: &autoConfig{},
				},
			},
		})
	}

	for _, fwd := range tcpForwards {
		name := fmt.Sprintf("tcp_forward_%d", fwd.Port)

		clusterType := "STRICT_DNS"
		if net.ParseIP(fwd.Host) != nil {
			clusterType = clusterTypeStatic
		}

		dnsFamily := "V4_ONLY"
		if clusterType == clusterTypeStatic {
			dnsFamily = ""
		}

		clusters = append(clusters, cluster{
			Name:            name,
			ConnectTimeout:  "5s",
			Type:            clusterType,
			LBPolicy:        lbPolicyRoundRobin,
			DNSLookupFamily: dnsFamily,
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
