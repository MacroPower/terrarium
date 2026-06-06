package status

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/dnstest"
)

func TestProbeDNSSuccess(t *testing.T) {
	t.Parallel()

	addr := dnstest.StartServer(t, "127.0.0.1")

	err := probeDNS(addr, 5*time.Second)
	assert.NoError(t, err)
}

func TestProbeDNSTimeout(t *testing.T) {
	t.Parallel()

	pc, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, pc.Close())
	})

	err = probeDNS(pc.LocalAddr().String(), 50*time.Millisecond)
	assert.Error(t, err)
}
