package envoy

// Envoy enum values, filter names, and type-URLs reused across the
// cluster, listener, filter, route, and access-log builders. Gathered
// here so the repeated literals stay consistent and have a single
// point of change when the upstream Envoy API evolves.
const (
	// The Envoy STATIC cluster discovery type.
	clusterTypeStatic = "STATIC"

	// The Envoy ROUND_ROBIN load-balancing policy.
	lbPolicyRoundRobin = "ROUND_ROBIN"

	// The Envoy CLUSTER_PROVIDED load-balancing policy used by
	// clusters that resolve their own endpoints (original destination,
	// dynamic forward proxy).
	lbPolicyClusterProvided = "CLUSTER_PROVIDED"

	// The Envoy TCP proxy network filter name.
	tcpProxyFilterName = "envoy.filters.network.tcp_proxy"

	// The Any type URL for the TCP proxy filter configuration.
	tcpProxyTypeURL = "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy"

	// The Envoy HTTP router filter name.
	httpRouterFilterName = "envoy.filters.http.router"

	// The Envoy dynamic forward proxy HTTP filter name.
	httpDFPFilterName = "envoy.filters.http.dynamic_forward_proxy"

	// The Any type URL for the dynamic forward proxy HTTP filter
	// configuration.
	httpDFPFilterTypeURL = "type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig"

	// The Envoy HTTP filter that stores values in the filter state of
	// a request.
	httpSetFilterStateFilterName = "envoy.filters.http.set_filter_state"

	// The Any type URL for the configuration of the HTTP filter that
	// stores values in the filter state.
	httpSetFilterStateTypeURL = "type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config"

	// The filter state key of the port that the dynamic forward proxy
	// connects to, in place of the default port of its cluster.
	dynamicPortFilterStateKey = "envoy.upstream.dynamic_port"

	// The prefix of the filter state key of the object that holds the
	// value of a request header. The name of the header in lowercase
	// follows the prefix.
	headerValueStatePrefix = "terrarium.header_value."

	// The filter state key of the object that marks a request whose
	// header values the filter state holds.
	headerValuesStoredStateKey = "terrarium.header_values_stored"

	// The Envoy access log filter that matches each request for which
	// a Common Expression Language (CEL) expression is true.
	celAccessLogFilterName = "envoy.access_loggers.extension_filters.cel"

	// The Any type URL for the configuration of the CEL access log
	// filter.
	celAccessLogFilterTypeURL = "type.googleapis.com/envoy.extensions.access_loggers.filters.cel.v3.ExpressionFilter"

	// The Envoy object factory that creates a filter state object that
	// holds a string.
	stringFilterStateFactory = "envoy.string"

	// The Any type URL for the HTTP router filter configuration.
	httpRouterTypeURL = "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"

	// The Envoy HTTP connection manager network filter name.
	hcmFilterName = "envoy.filters.network.http_connection_manager"

	// The Any type URL for the HTTP connection manager filter
	// configuration.
	hcmTypeURL = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager"

	// The HTTP/2 :authority pseudo-header.
	authorityHeader = ":authority"

	// The default port of the "https" scheme. A Host header without a
	// port names this port on a TLS connection.
	defaultHTTPSPort = 443

	// The HCM stream idle timeout, encoded as an Envoy duration
	// string. It reaps idle streams and tunnels without capping
	// active long-lived transfers.
	streamIdleTimeout5m = "300s"

	// Enables CONNECT handling in HCM and route upgrade configs.
	upgradeTypeConnect = "CONNECT"

	// Enables WebSocket upgrades in HCM upgrade configs.
	upgradeTypeWebsocket = "websocket"

	// The namespace of the route metadata that marks a route for the
	// HEADER_MISMATCH access logger.
	mismatchMetadataNamespace = "terrarium.header_mismatch"

	// The key in [mismatchMetadataNamespace] whose value holds the
	// names of the headers with a LOG mismatch action, joined with
	// commas.
	mismatchLogHeadersKey = "log_headers"

	// The response body for policy 403s.
	accessDeniedBody = "Access denied"

	// The one-hour route and TCP proxy idle timeout, encoded as an
	// Envoy duration string. Generous enough for long-lived streams
	// while still reclaiming abandoned connections.
	routeTimeout1h = "3600s"
)
