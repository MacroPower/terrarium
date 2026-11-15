package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFreePorts checks that [freePorts] returns the number of ports
// that the caller asked for, and that the ports differ.
func TestFreePorts(t *testing.T) {
	t.Parallel()

	const n = 8

	ports := freePorts(t, n)
	require.Len(t, ports, n)

	seen := make(map[int]struct{}, n)

	for _, port := range ports {
		assert.Positive(t, port)
		assert.NotContains(t, seen, port)

		seen[port] = struct{}{}
	}
}
