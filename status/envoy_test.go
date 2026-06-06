package status_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/status"
)

func TestCollectEnvoyMissing(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "envoy.yaml")

	opts := status.Options{EnvoyConfigPath: path}

	r := status.Collect(t.Context(), opts)

	assert.True(t, r.Envoy.NotGenerated)
	require.NoError(t, r.Envoy.Err)
	assert.Empty(t, r.Envoy.Listeners)
}

func TestCollectEnvoyMalformed(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "envoy.yaml")

	require.NoError(t, os.WriteFile(path, []byte("{{not yaml"), 0o644))

	opts := status.Options{EnvoyConfigPath: path}

	r := status.Collect(t.Context(), opts)

	assert.False(t, r.Envoy.NotGenerated)
	assert.Error(t, r.Envoy.Err)
}

func TestCollectEnvoyZeroListeners(t *testing.T) {
	t.Parallel()

	yaml := `
static_resources:
  listeners: []
  clusters: []
overload_manager:
  resource_monitors: []
`
	path := filepath.Join(t.TempDir(), "envoy.yaml")

	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o644))

	opts := status.Options{EnvoyConfigPath: path}

	r := status.Collect(t.Context(), opts)

	require.NoError(t, r.Envoy.Err)
	assert.Empty(t, r.Envoy.Listeners)
}

func TestCollectEnvoyListenersWithAdditionalAddresses(t *testing.T) {
	t.Parallel()

	// Two listeners. The first has an AdditionalAddress on the same
	// port (dual-bind v4+v6), which must not inflate the listener
	// count. Ports are deduplicated and sorted ascending.
	yaml := `
overload_manager:
  resource_monitors: []
static_resources:
  listeners:
    - name: tls_passthrough
      address:
        socket_address:
          address: 127.0.0.1
          port_value: 15443
      additional_addresses:
        - address:
            socket_address:
              address: "::1"
              port_value: 15443
    - name: http_forward
      address:
        socket_address:
          address: 127.0.0.1
          port_value: 15080
      additional_addresses:
        - address:
            socket_address:
              address: "::1"
              port_value: 15080
    - name: catch_all
      address:
        socket_address:
          address: 127.0.0.1
          port_value: 15001
  clusters: []
`
	path := filepath.Join(t.TempDir(), "envoy.yaml")

	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o644))

	opts := status.Options{EnvoyConfigPath: path}

	r := status.Collect(t.Context(), opts)

	require.NoError(t, r.Envoy.Err)
	assert.Equal(t, []int{15001, 15080, 15443}, r.Envoy.Listeners)
}
