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

			logs := envoy.BuildAccessLog(tt.logging, "/tmp/access.log")
			if tt.wantLen == 0 {
				assert.Nil(t, logs)
				return
			}

			require.Len(t, logs, tt.wantLen)
			assert.Equal(t, tt.wantName, logs[0].Name)
		})
	}
}

func TestBuildCatchAllUDPListener(t *testing.T) {
	t.Parallel()

	l := envoy.BuildCatchAllUDPListener(15002, 60*time.Second, nil)

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

	accessLog := envoy.BuildAccessLog(true, "/tmp/access.log")
	l := envoy.BuildCatchAllUDPListener(15002, 120*time.Second, accessLog)

	require.Len(t, l.ListenerFilters, 1)
	assert.Equal(t, "envoy.filters.udp_listener.udp_proxy", l.ListenerFilters[0].Name)

	out, err := yaml.Marshal(l)
	require.NoError(t, err)

	y := string(out)
	assert.Contains(t, y, "idle_timeout: 120s")
	assert.Contains(t, y, "envoy.access_loggers.file")
}
