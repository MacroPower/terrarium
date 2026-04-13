package envoy

// Envoy bootstrap config types. These model the subset of the Envoy v3
// API used by terrarium's transparent SNI-filtering proxy.

// Bootstrap is the top-level Envoy bootstrap configuration.
type Bootstrap struct {
	OverloadManager OverloadManager `yaml:"overload_manager"`
	StaticResources StaticResources `yaml:"static_resources"`
}

// OverloadManager configures Envoy's overload manager resource monitors.
type OverloadManager struct {
	ResourceMonitors []NamedTyped `yaml:"resource_monitors"`
}

// StaticResources holds the static listener and cluster definitions.
type StaticResources struct {
	Listeners []Listener `yaml:"listeners"`
	Clusters  []cluster  `yaml:"clusters"`
}

// Listener models an Envoy listener with filter chains and optional
// listener-level filters.
type Listener struct {
	DefaultFilterChain *filterChain       `yaml:"default_filter_chain,omitempty"`
	UDPListenerConfig  *udpListenerConfig `yaml:"udp_listener_config,omitempty"`
	Name               string             `yaml:"name"`
	ListenerFilters    []NamedTyped       `yaml:"listener_filters,omitempty"`
	FilterChains       []filterChain      `yaml:"filter_chains,omitempty"`
	Address            address            `yaml:"address"`
	Transparent        bool               `yaml:"transparent,omitempty"`
}

type address struct {
	SocketAddress socketAddress `yaml:"socket_address"`
}

type socketAddress struct {
	Address    string `yaml:"address"`
	Protocol   string `yaml:"protocol,omitempty"`
	PortValue  int    `yaml:"port_value"`
	Ipv4Compat bool   `yaml:"ipv4_compat,omitempty"`
}

// NamedTyped is a generic Envoy config element with a name and typed_config.
type NamedTyped struct {
	TypedConfig any    `yaml:"typed_config"`
	Name        string `yaml:"name"`
}

type filterChain struct {
	FilterChainMatch *filterChainMatch `yaml:"filter_chain_match,omitempty"`
	TransportSocket  *transportSocket  `yaml:"transport_socket,omitempty"`
	Filters          []filter          `yaml:"filters"`
}

type transportSocket struct {
	TypedConfig any    `yaml:"typed_config"`
	Name        string `yaml:"name"`
}

type downstreamTlsContext struct {
	AtType           string           `yaml:"@type"`
	CommonTlsContext commonTlsContext `yaml:"common_tls_context"`
}

type commonTlsContext struct {
	TlsCertificates []tlsCertificate `yaml:"tls_certificates"`
	AlpnProtocols   []string         `yaml:"alpn_protocols,omitempty"`
}

type tlsCertificate struct {
	CertificateChain dataSource `yaml:"certificate_chain"`
	PrivateKey       dataSource `yaml:"private_key"`
}

type dataSource struct {
	Filename     string `yaml:"filename,omitempty"`
	InlineString string `yaml:"inline_string,omitempty"`
}

type upstreamTlsContext struct {
	CommonTlsContext *upstreamCommonTlsContext `yaml:"common_tls_context,omitempty"`
	AtType           string                    `yaml:"@type"`
}

type upstreamCommonTlsContext struct {
	ValidationContext *validationContext `yaml:"validation_context,omitempty"`
}

type validationContext struct {
	TrustedCA dataSource `yaml:"trusted_ca"`
}

type filterChainMatch struct {
	TransportProtocol string   `yaml:"transport_protocol,omitempty"`
	ServerNames       []string `yaml:"server_names,omitempty"`
}

type filter struct {
	TypedConfig any    `yaml:"typed_config"`
	Name        string `yaml:"name"`
}

type typeOnly struct {
	AtType string `yaml:"@type"`
}

// DownstreamConnectionsConfig limits the number of active downstream connections.
type DownstreamConnectionsConfig struct {
	AtType                         string `yaml:"@type"`
	MaxActiveDownstreamConnections int    `yaml:"max_active_downstream_connections"`
}

type sniFilterConfig struct {
	DNSCacheConfig dnsCacheConfig `yaml:"dns_cache_config"`
	AtType         string         `yaml:"@type"`
	PortValue      int            `yaml:"port_value"`
}

type dnsCacheConfig struct {
	TypedDNSResolverConfig *typedExtensionConfig `yaml:"typed_dns_resolver_config,omitempty"`
	Name                   string                `yaml:"name"`
	DNSLookupFamily        string                `yaml:"dns_lookup_family"`
}

// typedExtensionConfig models an Envoy TypedExtensionConfig with a
// name and an arbitrary typed_config payload (e.g. [typeOnly] or
// [caresDNSResolverConfig]).
type typedExtensionConfig struct {
	TypedConfig any    `yaml:"typed_config"`
	Name        string `yaml:"name"`
}

// caresDNSResolverConfig models Envoy's CaresDnsResolverConfig for
// the c-ares DNS resolver. It specifies explicit resolver addresses
// and options to bypass system resolver configuration.
type caresDNSResolverConfig struct {
	AtType             string             `yaml:"@type"`
	Resolvers          []address          `yaml:"resolvers"`
	DNSResolverOptions dnsResolverOptions `yaml:"dns_resolver_options"`
}

// dnsResolverOptions models Envoy's DnsResolverOptions message.
type dnsResolverOptions struct {
	NoDefaultSearchDomain bool `yaml:"no_default_search_domain"`
}

type tcpProxyConfig struct {
	AtType     string      `yaml:"@type"`
	StatPrefix string      `yaml:"stat_prefix"`
	Cluster    string      `yaml:"cluster"`
	AccessLog  []AccessLog `yaml:"access_log,omitempty"`
}

// AccessLog models an Envoy access log configuration entry.
type AccessLog struct {
	TypedConfig any    `yaml:"typed_config"`
	Name        string `yaml:"name"`
}

// stderrAccessLogConfig models the StderrAccessLog typed config with
// an optional text format. When LogFormat is set, Envoy uses the provided
// format string instead of the default access log format.
type stderrAccessLogConfig struct {
	LogFormat *substitutionFormatString `yaml:"log_format,omitempty"`
	AtType    string                    `yaml:"@type"`
}

// fileAccessLogConfig models the FileAccessLog typed config that writes
// access log entries to a file on disk.
type fileAccessLogConfig struct {
	LogFormat *substitutionFormatString `yaml:"log_format,omitempty"`
	AtType    string                    `yaml:"@type"`
	Path      string                    `yaml:"path"`
}

// substitutionFormatString models Envoy's SubstitutionFormatString
// with text_format_source and json_format fields for command-operator
// log formatting.
type substitutionFormatString struct {
	TextFormatSource *dataSource       `yaml:"text_format_source,omitempty"`
	JsonFormat       map[string]string `yaml:"json_format,omitempty"`
}

type httpConnManagerConfig struct {
	NormalizePath                *bool           `yaml:"normalize_path,omitempty"`
	UseRemoteAddress             *bool           `yaml:"use_remote_address,omitempty"`
	SkipXffAppend                *bool           `yaml:"skip_xff_append,omitempty"`
	AtType                       string          `yaml:"@type"`
	StatPrefix                   string          `yaml:"stat_prefix"`
	StreamIdleTimeout            string          `yaml:"stream_idle_timeout,omitempty"`
	PathWithEscapedSlashesAction string          `yaml:"path_with_escaped_slashes_action,omitempty"`
	RouteConfig                  routeConfig     `yaml:"route_config"`
	AccessLog                    []AccessLog     `yaml:"access_log,omitempty"`
	HTTPFilters                  []filter        `yaml:"http_filters"`
	UpgradeConfigs               []upgradeConfig `yaml:"upgrade_configs,omitempty"`
	MergeSlashes                 bool            `yaml:"merge_slashes,omitempty"`
	StripAnyHostPort             bool            `yaml:"strip_any_host_port,omitempty"`
}

type upgradeConfig struct {
	UpgradeType string `yaml:"upgrade_type"`
}

type routeConfig struct {
	VirtualHosts []virtualHost `yaml:"virtual_hosts"`
}

type virtualHost struct {
	Name    string   `yaml:"name"`
	Domains []string `yaml:"domains"`
	Routes  []route  `yaml:"routes"`
}

type route struct {
	TypedPerFilterConfig   map[string]any        `yaml:"typed_per_filter_config,omitempty"`
	Route                  *routeAction          `yaml:"route,omitempty"`
	DirectResponse         *directResponseAction `yaml:"direct_response,omitempty"`
	Match                  routeMatch            `yaml:"match"`
	RequestHeadersToAdd    []headerValueOption   `yaml:"request_headers_to_add,omitempty"`
	RequestHeadersToRemove []string              `yaml:"request_headers_to_remove,omitempty"`
}

// routeMatch models Envoy's route.RouteMatch message.
//
// When SafeRegex is set (instead of Prefix), it acts as a path_specifier
// on the RouteMatch. Envoy evaluates this via CompiledGoogleReMatcher,
// which calls re2::RE2::FullMatch -- meaning the regex must match the
// entire request path, not a substring. For example, a regex of "/v1/"
// does NOT match the path "/v1/completions"; it only matches the
// literal three-character path "/v1/". To match paths that start with
// "/v1/", the regex must be "/v1/.*".
//
// This is the same full-string match behavior that Cilium produces,
// though the two systems arrive at it differently. Cilium applies
// path restrictions via a HeaderMatcher on the ":path" pseudo-header,
// evaluated by its custom "cilium.l7policy" Envoy filter through the
// NPDS (Network Policy Discovery Service) xDS API. Both mechanisms
// ultimately call CompiledGoogleReMatcher::match(), which delegates to
// RE2::FullMatch, so the behavioral outcome is identical.
//
// Audited and confirmed: terrarium's route-level safe_regex and
// Cilium's header-based L7 policy produce the same accept/reject
// decisions for any given path regex.
//
// Envoy source references:
//   - source/common/router/config_impl.cc: RouteEntryImplBase
//     applies safe_regex via CompiledGoogleReMatcher
//   - source/common/common/matchers.cc: CompiledGoogleReMatcher::match
//     calls re2::RE2::FullMatch
type routeMatch struct {
	SafeRegex *safeRegex             `yaml:"safe_regex,omitempty"`
	Grpc      *grpcRouteMatchOptions `yaml:"grpc,omitempty"`
	Prefix    string                 `yaml:"prefix,omitempty"`
	Headers   []headerMatcher        `yaml:"headers,omitempty"`
}

// grpcRouteMatchOptions is an empty message that, when present on a
// RouteMatch, restricts the route to gRPC requests (content-type
// application/grpc). Mirrors Envoy's route.RouteMatch.GrpcRouteMatchOptions.
type grpcRouteMatchOptions struct{}

type headerMatcher struct {
	StringMatch  *stringMatch `yaml:"string_match,omitempty"`
	PresentMatch *bool        `yaml:"present_match,omitempty"`
	Name         string       `yaml:"name"`
}

type stringMatch struct {
	SafeRegex *safeRegex `yaml:"safe_regex,omitempty"`
	Exact     string     `yaml:"exact,omitempty"`
}

type safeRegex struct {
	Regex string `yaml:"regex"`
}

type rbacConfig struct {
	StatPrefix string    `yaml:"stat_prefix,omitempty"`
	Rules      rbacRules `yaml:"rules"`
	AtType     string    `yaml:"@type"`
}

type rbacRules struct {
	Policies map[string]rbacPolicy `yaml:"policies"`
	Action   string                `yaml:"action"`
}

type rbacPolicy struct {
	Permissions []rbacPermission `yaml:"permissions"`
	Principals  []rbacPrincipal  `yaml:"principals"`
}

// rbacPermission represents a single RBAC permission check.
// Fields are mutually exclusive (Envoy oneof).
type rbacPermission struct {
	RequestedServerName *stringMatch   `yaml:"requested_server_name,omitempty"`
	Header              *headerMatcher `yaml:"header,omitempty"`
}

type rbacPrincipal struct {
	Any bool `yaml:"any"`
}

// headerValueOption models Envoy's HeaderValueOption message used
// by request_headers_to_add on routes. AppendAction controls whether
// the header value is appended or overwrites an existing value.
type headerValueOption struct {
	Header       headerValue `yaml:"header"`
	AppendAction string      `yaml:"append_action,omitempty"`
}

// headerValue models Envoy's HeaderValue message with a key/value pair.
type headerValue struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value,omitempty"`
}

// routerFilterConfig models the per-route override for Envoy's HTTP
// router filter. UpstreamLog adds access logging for requests
// forwarded to upstream clusters.
type routerFilterConfig struct {
	AtType      string      `yaml:"@type"`
	UpstreamLog []AccessLog `yaml:"upstream_log,omitempty"`
}

type routeAction struct {
	MaxStreamDuration *maxStreamDuration `yaml:"max_stream_duration,omitempty"`
	Cluster           string             `yaml:"cluster"`
	Timeout           string             `yaml:"timeout,omitempty"`
	AutoHostRewrite   bool               `yaml:"auto_host_rewrite"`
}

// maxStreamDuration models Envoy's route.MaxStreamDuration message.
// GrpcTimeoutHeaderMax caps the duration extracted from the grpc-timeout
// request header. A value of "0s" means unlimited (honor the client value).
type maxStreamDuration struct {
	GrpcTimeoutHeaderMax string `yaml:"grpc_timeout_header_max"`
}

type directResponseAction struct {
	Body   *dataSource `yaml:"body,omitempty"`
	Status int         `yaml:"status"`
}

type httpDFPFilterConfig struct {
	AtType         string         `yaml:"@type"`
	DNSCacheConfig dnsCacheConfig `yaml:"dns_cache_config"`
}

type cluster struct {
	ClusterType                   *clusterType     `yaml:"cluster_type,omitempty"`
	TransportSocket               *transportSocket `yaml:"transport_socket,omitempty"`
	LoadAssignment                *loadAssignment  `yaml:"load_assignment,omitempty"`
	TypedExtensionProtocolOptions map[string]any   `yaml:"typed_extension_protocol_options,omitempty"`
	Name                          string           `yaml:"name"`
	ConnectTimeout                string           `yaml:"connect_timeout"`
	Type                          string           `yaml:"type,omitempty"`
	LBPolicy                      string           `yaml:"lb_policy"`
	DNSLookupFamily               string           `yaml:"dns_lookup_family,omitempty"`
}

type clusterType struct {
	TypedConfig any    `yaml:"typed_config"`
	Name        string `yaml:"name"`
}

type clusterDFPConfig struct {
	AtType         string         `yaml:"@type"`
	DNSCacheConfig dnsCacheConfig `yaml:"dns_cache_config"`
}

type httpProtocolOptions struct {
	UpstreamHTTPProtocolOptions *upstreamHTTPProtocolOptions `yaml:"upstream_http_protocol_options,omitempty"`
	AutoConfig                  autoConfig                   `yaml:"auto_config"`
	AtType                      string                       `yaml:"@type"`
}

// upstreamHTTPProtocolOptions models Envoy's UpstreamHttpProtocolOptions.
// auto_sni sets the upstream TLS SNI from the Host header; auto_san_validation
// validates the upstream cert SAN against the SNI.
type upstreamHTTPProtocolOptions struct {
	AutoSNI           bool `yaml:"auto_sni"`
	AutoSANValidation bool `yaml:"auto_san_validation"`
}

// autoConfig models Envoy's HttpProtocolOptions.AutoHttpConfig.
// An empty struct serializes to `auto_config: {}`, which tells Envoy
// to negotiate the upstream protocol via ALPN, falling back to HTTP/1.1
// when the upstream does not support h2.
type autoConfig struct{}

type loadAssignment struct {
	ClusterName string     `yaml:"cluster_name"`
	Endpoints   []endpoint `yaml:"endpoints"`
}

type endpoint struct {
	LBEndpoints []lbEndpoint `yaml:"lb_endpoints"`
}

type lbEndpoint struct {
	Endpoint endpointAddress `yaml:"endpoint"`
}

type endpointAddress struct {
	Address address `yaml:"address"`
}

var sharedDNSCacheConfig = dnsCacheConfig{
	Name:            "dynamic_forward_proxy_cache",
	DNSLookupFamily: "ALL",
	TypedDNSResolverConfig: &typedExtensionConfig{
		Name: "envoy.network.dns_resolver.cares",
		TypedConfig: caresDNSResolverConfig{
			AtType: "type.googleapis.com/envoy.extensions.network.dns_resolver.cares.v3.CaresDnsResolverConfig",
			Resolvers: []address{{
				SocketAddress: socketAddress{
					Address:   "127.0.0.1",
					PortValue: 53,
				},
			}},
			DNSResolverOptions: dnsResolverOptions{
				NoDefaultSearchDomain: true,
			},
		},
	},
}

// udpListenerConfig models Envoy's UdpListenerConfig message.
type udpListenerConfig struct {
	DownstreamSocketConfig downstreamSocketConfig `yaml:"downstream_socket_config"`
}

// downstreamSocketConfig models Envoy's UdpSocketConfig for GRO.
type downstreamSocketConfig struct {
	PreferGRO bool `yaml:"prefer_gro,omitempty"`
}

// udpProxyConfig models the Envoy UDP proxy filter typed config.
type udpProxyConfig struct {
	AtType                    string          `yaml:"@type"`
	StatPrefix                string          `yaml:"stat_prefix"`
	Matcher                   udpRouteMatcher `yaml:"matcher"`
	IdleTimeout               string          `yaml:"idle_timeout"`
	AccessLog                 []AccessLog     `yaml:"access_log,omitempty"`
	UsePerPacketLoadBalancing bool            `yaml:"use_per_packet_load_balancing,omitempty"`
}

// udpRouteMatcher models a minimal xds.type.matcher.v3.Matcher that
// routes all traffic to a single cluster via on_no_match.
type udpRouteMatcher struct {
	OnNoMatch udpRouteAction `yaml:"on_no_match"`
}

// udpRouteAction wraps a named typed action for the matcher on_no_match field.
type udpRouteAction struct {
	Action NamedTyped `yaml:"action"`
}

// udpRoute models envoy.extensions.filters.udp.udp_proxy.v3.Route.
type udpRoute struct {
	AtType  string `yaml:"@type"`
	Cluster string `yaml:"cluster"`
}

func boolPtr(v bool) *bool {
	return &v
}
