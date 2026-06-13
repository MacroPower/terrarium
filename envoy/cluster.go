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

// mitmForwardProxyCluster is the name of the dynamic forward proxy
// cluster MITM filter chains route through. Unlike
// [dynamicForwardProxyCluster], it re-encrypts upstream with TLS and
// validates the upstream certificate against the CA bundle.
const mitmForwardProxyCluster = "mitm_forward_proxy_cluster"

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
// TCP forward clusters. When rules contain L7 restrictions, a non-empty
// caBundlePath is required: without one, [ErrMITMCABundleMissing] is
// returned.
func BuildClusters(
	rules []config.ResolvedRule,
	tcpForwards []config.TCPForward,
	hasListeners bool,
	caBundlePath string,
) ([]cluster, error) {
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
		clusters = append(clusters, buildDFPCluster(sharedDNSCacheConfig))
	}

	if hasMITMRules(rules) {
		mitm, err := buildMITMCluster(caBundlePath, sharedDNSCacheConfig)
		if err != nil {
			return nil, fmt.Errorf("building MITM cluster: %w", err)
		}

		clusters = append(clusters, mitm)
	}

	for _, fwd := range tcpForwards {
		clusters = append(clusters, buildTCPForwardCluster(fwd))
	}

	return clusters, nil
}

// buildMITMCluster builds the dynamic forward proxy cluster MITM
// filter chains route through. The upstream connection is TLS with
// SNI derived from the HTTP Host header. The caBundlePath must be
// non-empty; the upstream certificate is always validated against it.
// When the path is empty, [ErrMITMCABundleMissing] is returned, so the
// cluster is never emitted without a trust store.
//
// Upstream SNI handling: Envoy v1.37+ requires explicit auto_sni and
// auto_san_validation on DFP clusters that set
// typed_extension_protocol_options. Earlier versions auto-enabled
// both via the DFP cluster factory, but v1.37 validates their
// presence at config time. Setting them in
// upstream_http_protocol_options ensures the upstream TLS handshake
// uses the correct SNI (derived from the HTTP Host header) and
// validates the upstream cert SAN against it.
func buildMITMCluster(caBundlePath string, dnsCache dnsCacheConfig) (cluster, error) {
	if caBundlePath == "" {
		return cluster{}, ErrMITMCABundleMissing
	}

	upstreamTLS := upstreamTlsContext{
		AtType: "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
		CommonTlsContext: &upstreamCommonTlsContext{
			ValidationContext: &validationContext{
				TrustedCA: dataSource{Filename: caBundlePath},
			},
		},
	}

	return cluster{
		Name:           mitmForwardProxyCluster,
		ConnectTimeout: "5s",
		LBPolicy:       lbPolicyClusterProvided,
		ClusterType: &clusterType{
			Name: "envoy.clusters.dynamic_forward_proxy",
			TypedConfig: clusterDFPConfig{
				AtType:         "type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig",
				DNSCacheConfig: dnsCache,
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
	}, nil
}

// buildDFPCluster builds the plain dynamic forward proxy cluster used
// for FQDN-based egress and SNI passthrough tunneling.
func buildDFPCluster(dnsCache dnsCacheConfig) cluster {
	return cluster{
		Name:           dynamicForwardProxyCluster,
		ConnectTimeout: "5s",
		LBPolicy:       lbPolicyClusterProvided,
		ClusterType: &clusterType{
			Name: "envoy.clusters.dynamic_forward_proxy",
			TypedConfig: clusterDFPConfig{
				AtType:         "type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig",
				DNSCacheConfig: dnsCache,
			},
		},
	}
}

// buildTCPForwardCluster builds the static or STRICT_DNS cluster for
// one [config.TCPForward] entry.
func buildTCPForwardCluster(fwd config.TCPForward) cluster {
	name := fmt.Sprintf("tcp_forward_%d", fwd.Port)

	clusterType := "STRICT_DNS"
	if net.ParseIP(fwd.Host) != nil {
		clusterType = clusterTypeStatic
	}

	dnsFamily := "V4_ONLY"
	if clusterType == clusterTypeStatic {
		dnsFamily = ""
	}

	return cluster{
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
	}
}
