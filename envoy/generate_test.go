package envoy_test

import (
	"testing"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/envoy"
)

func TestBuildGrpcAccessLog_HTTP(t *testing.T) {
	t.Parallel()

	logs := envoy.BuildHTTPGrpcAccessLog("http_forward", 16384, 1000)
	require.Len(t, logs, 1)
	assert.Equal(t, "envoy.access_loggers.http_grpc", logs[0].Name)

	out, err := yaml.Marshal(logs)
	require.NoError(t, err)

	y := string(out)
	assert.Contains(t, y, "HttpGrpcAccessLogConfig")
	assert.Contains(t, y, "log_name: http_forward")
	assert.Contains(t, y, "cluster_name: terrarium_accesslog")
	assert.Contains(t, y, "buffer_size_bytes: 16384")
	// buffer_flush_interval must be a proto Duration string (not
	// a raw integer) — Envoy rejects the integer form.
	assert.Contains(t, y, "buffer_flush_interval: 1.000s")
	assert.NotContains(t, y, "transport_api_version",
		"transport_api_version is deprecated; should not appear in output")
}

func TestBuildGrpcAccessLog_TCP(t *testing.T) {
	t.Parallel()

	logs := envoy.BuildTCPGrpcAccessLog("tls_passthrough", 16384, 1000)
	require.Len(t, logs, 1)
	assert.Equal(t, "envoy.access_loggers.tcp_grpc", logs[0].Name)

	out, err := yaml.Marshal(logs)
	require.NoError(t, err)

	y := string(out)
	assert.Contains(t, y, "TcpGrpcAccessLogConfig")
	assert.Contains(t, y, "log_name: tls_passthrough")
	assert.Contains(t, y, "cluster_name: terrarium_accesslog")
}

func TestBuildAccessLogCluster(t *testing.T) {
	t.Parallel()

	c := envoy.BuildAccessLogCluster("/run/terrarium/als.sock")

	out, err := yaml.Marshal(c)
	require.NoError(t, err)

	y := string(out)
	assert.Contains(t, y, "name: terrarium_accesslog")
	assert.Contains(t, y, "type: STATIC")
	assert.Contains(t, y, "pipe:")
	assert.Contains(t, y, "path: /run/terrarium/als.sock")
	assert.Contains(t, y, "explicit_http_config:")
	assert.Contains(t, y, "http2_protocol_options:")
}

func TestBuildCatchAllUDPListener(t *testing.T) {
	t.Parallel()

	l := envoy.BuildCatchAllUDPListener(15002, 60*time.Second, nil, false)

	assert.Equal(t, "catch_all_udp", l.Name)
	assert.True(t, l.Transparent, "UDP listener must be transparent for TPROXY")
	assert.NotNil(t, l.UDPListenerConfig, "should have UDP listener config")
	assert.Empty(t, l.FilterChains, "UDP listeners should not have filter chains")
	require.Len(t, l.ListenerFilters, 1, "should have UDP proxy listener filter")
	assert.Equal(t, "envoy.filters.udp_listener.udp_proxy", l.ListenerFilters[0].Name)

	// Verify the full YAML output contains the expected Envoy config
	// fields: @type, matcher/route, idle_timeout format, and
	// use_per_packet_load_balancing.
	out, err := yaml.Marshal(l)
	require.NoError(t, err)

	y := string(out)
	assert.Contains(t, y, "protocol: UDP")
	assert.Contains(t, y, "address: 0.0.0.0")
	assert.Contains(t, y, "transparent: true")
	assert.Contains(t, y, "prefer_gro: true")
	assert.Contains(t, y, `"@type": type.googleapis.com/envoy.extensions.filters.udp.udp_proxy.v3.UdpProxyConfig`)
	assert.Contains(t, y, "cluster: original_dst")
	assert.Contains(t, y, `"@type": type.googleapis.com/envoy.extensions.filters.udp.udp_proxy.v3.Route`)
	assert.Contains(t, y, "on_no_match:")
	assert.Contains(t, y, "idle_timeout: 60s")
	assert.Contains(t, y, "use_per_packet_load_balancing: true")
	assert.Contains(t, y, "stat_prefix: catch_all_udp")
	assert.NotContains(t, y, "filter_chains")
}

func TestBuildCatchAllUDPListener_NoAccessLog(t *testing.T) {
	t.Parallel()

	l := envoy.BuildCatchAllUDPListener(15002, 120*time.Second, nil, false)

	out, err := yaml.Marshal(l)
	require.NoError(t, err)

	y := string(out)
	assert.Contains(t, y, "idle_timeout: 120s")
	assert.NotContains(t, y, "envoy.access_loggers.file",
		"UDP listener should not emit access events in v1")
	assert.NotContains(t, y, "envoy.access_loggers.http_grpc")
	assert.NotContains(t, y, "envoy.access_loggers.tcp_grpc")
}

func TestBuildTLSListener_Transparent(t *testing.T) {
	t.Parallel()

	l := envoy.BuildTLSListener(
		"tls_test", 15443, 443, "tls_test",
		nil, true, nil, nil, "", true,
	)

	assert.Equal(t, "0.0.0.0", l.Address.SocketAddress.Address,
		"transparent listener should bind to 0.0.0.0 for IPv4 TPROXY")
	assert.True(t, l.Transparent,
		"transparent listener should have Transparent=true")
	require.Len(t, l.AdditionalAddresses, 1,
		"transparent listener should have IPv6 additional address")
	assert.Equal(t, "::", l.AdditionalAddresses[0].Address.SocketAddress.Address,
		"additional address should be :: for IPv6 TPROXY")
}

func TestBuildTLSListener_NonTransparent(t *testing.T) {
	t.Parallel()

	l := envoy.BuildTLSListener(
		"tls_test", 15443, 443, "tls_test",
		nil, true, nil, nil, "", false,
	)

	assert.Equal(t, "127.0.0.1", l.Address.SocketAddress.Address,
		"non-transparent listener should bind to 127.0.0.1")
	assert.False(t, l.Transparent,
		"non-transparent listener should have Transparent=false")
}

func TestBuildHTTPForwardListener_Transparent(t *testing.T) {
	t.Parallel()

	l := envoy.BuildHTTPForwardListener(nil, true, nil, true)

	assert.Equal(t, "0.0.0.0", l.Address.SocketAddress.Address)
	assert.True(t, l.Transparent)
	require.Len(t, l.AdditionalAddresses, 1)
	assert.Equal(t, "::", l.AdditionalAddresses[0].Address.SocketAddress.Address)
}

func TestBuildCatchAllTCPListener_Transparent(t *testing.T) {
	t.Parallel()

	l := envoy.BuildCatchAllTCPListener(15001, true, nil, true)

	assert.Equal(t, "0.0.0.0", l.Address.SocketAddress.Address)
	assert.True(t, l.Transparent)
	require.Len(t, l.AdditionalAddresses, 1)
	assert.Equal(t, "::", l.AdditionalAddresses[0].Address.SocketAddress.Address)
}

func TestBuildCatchAllTCPListener_NonTransparent(t *testing.T) {
	t.Parallel()

	l := envoy.BuildCatchAllTCPListener(15001, true, nil, false)

	assert.Equal(t, "127.0.0.1", l.Address.SocketAddress.Address)
	assert.False(t, l.Transparent)
}

func TestBuildCIDRCatchAllListener_Transparent(t *testing.T) {
	t.Parallel()

	l := envoy.BuildCIDRCatchAllListener(15003, nil, true)

	assert.Equal(t, "0.0.0.0", l.Address.SocketAddress.Address)
	assert.True(t, l.Transparent)
	require.Len(t, l.AdditionalAddresses, 1)
	assert.Equal(t, "::", l.AdditionalAddresses[0].Address.SocketAddress.Address)
}

func TestBuildCatchAllUDPListener_Transparent(t *testing.T) {
	t.Parallel()

	l := envoy.BuildCatchAllUDPListener(15002, 60*time.Second, nil, true)

	assert.Equal(t, "0.0.0.0", l.Address.SocketAddress.Address,
		"transparent UDP listener should bind to 0.0.0.0 for IPv4 TPROXY")
	assert.True(t, l.Transparent)
	require.Len(t, l.AdditionalAddresses, 1,
		"transparent UDP listener should have IPv6 additional address")
	assert.Equal(t, "::", l.AdditionalAddresses[0].Address.SocketAddress.Address)
}

func TestBuildCatchAllUDPListener_NonTransparent(t *testing.T) {
	t.Parallel()

	l := envoy.BuildCatchAllUDPListener(15002, 60*time.Second, nil, false)

	assert.Equal(t, "0.0.0.0", l.Address.SocketAddress.Address,
		"non-transparent UDP listener should bind to 0.0.0.0")
	assert.True(t, l.Transparent)
}

func TestBuildTCPForwardListener_Transparent(t *testing.T) {
	t.Parallel()

	l := envoy.BuildTCPForwardListener("tcp_fwd_8080", 23080, "tcp_fwd_8080", nil, true)

	assert.Equal(t, "0.0.0.0", l.Address.SocketAddress.Address)
	assert.True(t, l.Transparent)
	require.Len(t, l.AdditionalAddresses, 1)
	assert.Equal(t, "::", l.AdditionalAddresses[0].Address.SocketAddress.Address)
}

func TestBuildTCPForwardListener_NonTransparent(t *testing.T) {
	t.Parallel()

	l := envoy.BuildTCPForwardListener("tcp_fwd_8080", 23080, "tcp_fwd_8080", nil, false)

	assert.Equal(t, "127.0.0.1", l.Address.SocketAddress.Address)
	assert.False(t, l.Transparent)
}
