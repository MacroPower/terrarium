package status_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.jacobcolvin.com/terrarium/status"
)

func TestCollectDNSListenAddrsDefault(t *testing.T) {
	t.Parallel()

	r := status.Collect(t.Context(), status.Options{})

	assert.Contains(t, r.DNS.ListenAddrs, "127.0.0.1:53")
}

func TestCollectDNSProbeSkippedByDefault(t *testing.T) {
	t.Parallel()

	r := status.Collect(t.Context(), status.Options{})

	assert.False(t, r.DNS.Probed)
}
