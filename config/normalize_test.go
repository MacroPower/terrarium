package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
)

func TestNormalizeCIDRHostBits(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		before string
		after  string
	}{
		"host bits masked IPv4": {
			before: "10.0.1.5/16",
			after:  "10.0.0.0/16",
		},
		"already normalized IPv4": {
			before: "10.0.0.0/16",
			after:  "10.0.0.0/16",
		},
		"host bits masked IPv6": {
			before: "fd00::1/64",
			after:  "fd00::/64",
		},
		"bare IPv4 gets /32": {
			before: "10.0.0.1",
			after:  "10.0.0.1/32",
		},
		"bare IPv6 gets /128": {
			before: "fd00::1",
			after:  "fd00::1/128",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDR: []string{tt.before},
				}),
			}

			err := cfg.Validate()
			require.NoError(t, err)

			got := cfg.EgressRules()[0].ToCIDR[0]
			assert.Equal(t, tt.after, got)
		})
	}
}

func TestNormalizeCIDRSetEntries(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToCIDRSet: []config.CIDRRule{
				{
					CIDR:   "10.0.1.5/16",
					Except: []string{"10.0.1.0/24"},
				},
			},
		}),
	}

	err := cfg.Validate()
	require.NoError(t, err)

	rule := cfg.EgressRules()[0].ToCIDRSet[0]
	assert.Equal(t, "10.0.0.0/16", rule.CIDR)
	assert.Equal(t, "10.0.1.0/24", rule.Except[0])
}

func TestNormalizeCIDRStrictMasksHostBits(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		before string
		after  string
	}{
		"host bits masked": {
			before: "10.0.1.5/16",
			after:  "10.0.0.0/16",
		},
		"already normalized": {
			before: "10.0.0.0/16",
			after:  "10.0.0.0/16",
		},
		"IPv6 host bits masked": {
			before: "fd00::1/64",
			after:  "fd00::/64",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: tt.before}},
				}),
			}

			err := cfg.Validate()
			require.NoError(t, err)

			got := cfg.EgressRules()[0].ToCIDRSet[0].CIDR
			assert.Equal(t, tt.after, got)
		})
	}
}
