package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.jacobcolvin.com/terrarium/config"
)

func TestEmptyRuleWithFQDNSemantics(t *testing.T) {
	t.Parallel()

	// Empty rule + FQDN rule under default-deny: the empty rule
	// contributes nothing (no selectors), but the FQDN rule applies.
	cfg := &config.Config{Egress: egressRules(
		config.EgressRule{},
		config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
			ToPorts: []config.PortRule{{
				Ports: []config.Port{{Port: "443"}},
				Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
			}},
		},
	)}

	assert.False(t, cfg.IsEgressUnrestricted(), "empty rule triggers default-deny, not unrestricted")
	assert.False(t, cfg.IsEgressBlocked(), "FQDN sibling prevents blocked state")
	assert.Equal(t, []int{443}, cfg.ResolvePorts(), "FQDN rule contributes ports")
	assert.Equal(t, []string{"api.example.com"}, cfg.ResolveDomains(), "FQDN rule contributes domains")
}

func TestIsDefaultDenyEnabled(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg  *config.Config
		want bool
	}{
		"nil egress": {
			cfg: &config.Config{},
		},
		"empty egress": {
			cfg: &config.Config{Egress: egressRules()},
		},
		"rules present": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			want: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.cfg.IsDefaultDenyEnabled())
		})
	}
}
