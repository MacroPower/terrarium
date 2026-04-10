package envoy_test

import (
	"testing"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/envoy"
)

func TestBuildAccessLog(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		logging  bool
		wantLen  int
		wantName string
	}{
		"disabled": {logging: false},
		"enabled":  {logging: true, wantLen: 1, wantName: "envoy.access_loggers.file"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			logs := envoy.BuildAccessLog(tt.logging, "logfmt", "/tmp/access.log")
			if tt.wantLen == 0 {
				assert.Nil(t, logs)
				return
			}

			require.Len(t, logs, tt.wantLen)
			assert.Equal(t, tt.wantName, logs[0].Name)
		})
	}
}

func TestBuildAccessLog_JSONFormat(t *testing.T) {
	t.Parallel()

	logs := envoy.BuildAccessLog(true, "json", "/tmp/access.log")
	require.Len(t, logs, 1)

	out, err := yaml.Marshal(logs)
	require.NoError(t, err)

	y := string(out)
	assert.Contains(t, y, "json_format")
	assert.Contains(t, y, "time:")
	assert.Contains(t, y, "method:")
	assert.NotContains(t, y, "text_format_source")
}

func TestBuildAccessLog_LogfmtFormat(t *testing.T) {
	t.Parallel()

	logs := envoy.BuildAccessLog(true, "logfmt", "/tmp/access.log")
	require.Len(t, logs, 1)

	out, err := yaml.Marshal(logs)
	require.NoError(t, err)

	y := string(out)
	assert.Contains(t, y, "text_format_source")
	assert.Contains(t, y, "time=%START_TIME%")
	assert.NotContains(t, y, "json_format")
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

func TestBuildCatchAllUDPListener_WithAccessLog(t *testing.T) {
	t.Parallel()

	accessLog := envoy.BuildAccessLog(true, "logfmt", "/tmp/access.log")
	l := envoy.BuildCatchAllUDPListener(15002, 120*time.Second, accessLog, false)

	require.Len(t, l.ListenerFilters, 1)
	assert.Equal(t, "envoy.filters.udp_listener.udp_proxy", l.ListenerFilters[0].Name)

	out, err := yaml.Marshal(l)
	require.NoError(t, err)

	y := string(out)
	assert.Contains(t, y, "idle_timeout: 120s")
	assert.Contains(t, y, "envoy.access_loggers.file")
}

func TestBuildTLSListener_Transparent(t *testing.T) {
	t.Parallel()

	l := envoy.BuildTLSListener(
		"tls_test", 15443, 443, "tls_test",
		nil, true, nil, "", true,
	)

	assert.Equal(t, "::", l.Address.SocketAddress.Address,
		"transparent listener should bind to ::")
	assert.True(t, l.Transparent,
		"transparent listener should have Transparent=true")
}

func TestBuildTLSListener_NonTransparent(t *testing.T) {
	t.Parallel()

	l := envoy.BuildTLSListener(
		"tls_test", 15443, 443, "tls_test",
		nil, true, nil, "", false,
	)

	assert.Equal(t, "127.0.0.1", l.Address.SocketAddress.Address,
		"non-transparent listener should bind to 127.0.0.1")
	assert.False(t, l.Transparent,
		"non-transparent listener should have Transparent=false")
}

func TestBuildHTTPForwardListener_Transparent(t *testing.T) {
	t.Parallel()

	l := envoy.BuildHTTPForwardListener(nil, true, nil, true)

	assert.Equal(t, "::", l.Address.SocketAddress.Address)
	assert.True(t, l.Transparent)
}

func TestBuildCatchAllTCPListener_Transparent(t *testing.T) {
	t.Parallel()

	l := envoy.BuildCatchAllTCPListener(15001, true, nil, true)

	assert.Equal(t, "::", l.Address.SocketAddress.Address)
	assert.True(t, l.Transparent)
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

	assert.Equal(t, "::", l.Address.SocketAddress.Address)
	assert.True(t, l.Transparent)
}

func TestBuildCatchAllUDPListener_Transparent(t *testing.T) {
	t.Parallel()

	l := envoy.BuildCatchAllUDPListener(15002, 60*time.Second, nil, true)

	assert.Equal(t, "::", l.Address.SocketAddress.Address,
		"transparent UDP listener should bind to ::")
	assert.True(t, l.Transparent)
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

	assert.Equal(t, "::", l.Address.SocketAddress.Address)
	assert.True(t, l.Transparent)
}

func TestBuildTCPForwardListener_NonTransparent(t *testing.T) {
	t.Parallel()

	l := envoy.BuildTCPForwardListener("tcp_fwd_8080", 23080, "tcp_fwd_8080", nil, false)

	assert.Equal(t, "127.0.0.1", l.Address.SocketAddress.Address)
	assert.False(t, l.Transparent)
}
