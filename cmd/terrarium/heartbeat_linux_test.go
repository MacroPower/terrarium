//go:build linux

package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go.jacobcolvin.com/terrarium/dnscache"
	"go.jacobcolvin.com/terrarium/eventstore"
)

func TestInfraHeartbeatCounters(t *testing.T) {
	t.Parallel()

	cache := dnscache.New()
	t.Cleanup(cache.Close)

	cache.Add(netip.MustParseAddr("192.0.2.1"), "example.com.", time.Minute)

	tcs := map[string]struct {
		inf  *infra
		want eventstore.Heartbeat
	}{
		"dns cache": {
			inf:  &infra{dnsCache: cache},
			want: eventstore.Heartbeat{DNSCacheSize: 1},
		},
		// The nflog reader is nil in unrestricted mode and with
		// firewall logging disabled.
		"no subsystems": {
			inf:  &infra{},
			want: eventstore.Heartbeat{},
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var got eventstore.Heartbeat

			tc.inf.heartbeatCounters(&got)

			assert.Equal(t, tc.want, got)
		})
	}
}
