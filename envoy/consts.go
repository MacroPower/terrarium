package envoy

// Envoy enum values, filter names, and type-URLs reused across the
// cluster, listener, filter, route, and access-log builders. Gathered
// here so the repeated literals stay consistent and have a single
// point of change when the upstream Envoy API evolves.
const (
	// clusterTypeStatic is the Envoy STATIC cluster discovery type.
	clusterTypeStatic = "STATIC"

	// lbPolicyRoundRobin is the Envoy ROUND_ROBIN load-balancing policy.
	lbPolicyRoundRobin = "ROUND_ROBIN"

	// lbPolicyClusterProvided is the Envoy CLUSTER_PROVIDED
	// load-balancing policy used by clusters that resolve their own
	// endpoints (original destination, dynamic forward proxy).
	lbPolicyClusterProvided = "CLUSTER_PROVIDED"

	// tcpProxyFilterName is the Envoy TCP proxy network filter name.
	tcpProxyFilterName = "envoy.filters.network.tcp_proxy"

	// tcpProxyTypeURL is the Any type URL for the TCP proxy filter
	// configuration.
	tcpProxyTypeURL = "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy"

	// httpRouterFilterName is the Envoy HTTP router filter name.
	httpRouterFilterName = "envoy.filters.http.router"

	// httpDFPFilterName is the Envoy dynamic forward proxy HTTP
	// filter name.
	httpDFPFilterName = "envoy.filters.http.dynamic_forward_proxy"

	// httpDFPFilterTypeURL is the Any type URL for the dynamic
	// forward proxy HTTP filter configuration.
	httpDFPFilterTypeURL = "type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig"

	// httpRouterTypeURL is the Any type URL for the HTTP router filter
	// configuration.
	httpRouterTypeURL = "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"

	// hcmFilterName is the Envoy HTTP connection manager network
	// filter name.
	hcmFilterName = "envoy.filters.network.http_connection_manager"

	// hcmTypeURL is the Any type URL for the HTTP connection manager
	// filter configuration.
	hcmTypeURL = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager"

	// authorityHeader is the HTTP/2 :authority pseudo-header.
	authorityHeader = ":authority"

	// streamIdleTimeout5m is the HCM stream idle timeout, encoded as
	// an Envoy duration string. It reaps idle streams and tunnels
	// without capping active long-lived transfers.
	streamIdleTimeout5m = "300s"

	// upgradeTypeConnect enables CONNECT handling in HCM and route
	// upgrade configs.
	upgradeTypeConnect = "CONNECT"

	// upgradeTypeWebsocket enables WebSocket upgrades in HCM upgrade
	// configs.
	upgradeTypeWebsocket = "websocket"

	// accessDeniedBody is the response body for policy 403s.
	accessDeniedBody = "Access denied"

	// routeTimeout1h is the one-hour route and TCP proxy idle timeout,
	// encoded as an Envoy duration string. Generous enough for
	// long-lived streams while still reclaiming abandoned connections.
	routeTimeout1h = "3600s"
)
