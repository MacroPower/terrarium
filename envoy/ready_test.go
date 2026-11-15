package envoy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/envoy"
)

func TestBuildReadyOverlay(t *testing.T) {
	t.Parallel()

	overlay := envoy.BuildReadyOverlay("/run/ready/ready.sock")

	require.Len(t, overlay.StaticResources.Listeners, 1)
	assert.Equal(t, "ready", overlay.StaticResources.Listeners[0].Name)

	y := marshalYAML(t, overlay)

	// The listener binds the socket and lets every user that can open
	// its directory connect. YAML holds the mode 0o666 as the decimal
	// number 438.
	assert.Contains(t, y, "path: /run/ready/ready.sock")
	assert.Contains(t, y, "mode: 438")
	assert.NotContains(t, y, "socket_address")

	// Every request gets status 200 from Envoy itself.
	assert.Contains(t, y, "prefix: /")
	assert.Contains(t, y, "status: 200")
	assert.NotContains(t, y, "cluster")

	// Envoy merges every field of the overlay into the bootstrap of
	// the file, so the overlay names only its listener.
	assert.Equal(t, 1, countOccurrences(y, "static_resources:"))
	assert.NotContains(t, y, "overload_manager")
	assert.NotContains(t, y, "clusters")
}
