package envoy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/envoy"
)

func TestBuildClusters(t *testing.T) {
	t.Parallel()

	restricted := []config.ResolvedRule{
		{Domain: "passthrough.example.com"},
		{Domain: "restricted.example.com", HTTPRules: []config.ResolvedHTTPRule{
			{Method: "GET"},
		}},
	}

	tests := map[string]struct {
		rules        []config.ResolvedRule
		tcpForwards  []config.TCPForward
		caBundlePath string
		want         []string
		notWant      []string
		err          error
	}{
		"MITM rules with CA bundle": {
			rules:        restricted,
			caBundlePath: "/etc/ssl/bundle.pem",
			want: []string{
				"name: mitm_forward_proxy_cluster",
				"trusted_ca:",
				"filename: /etc/ssl/bundle.pem",
			},
		},
		"no MITM rules without CA bundle": {
			rules: []config.ResolvedRule{{Domain: "example.com"}},
			notWant: []string{
				"mitm_forward_proxy_cluster",
				"trusted_ca:",
			},
		},
		"MITM rules without CA bundle": {
			rules: restricted,
			err:   envoy.ErrMITMCABundleMissing,
		},
		"tcp forwards": {
			tcpForwards: []config.TCPForward{{Port: 22, Host: "github.com"}},
			want:        []string{"name: tcp_forward_22"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			clusters, err := envoy.BuildClusters(tt.rules, tt.tcpForwards, true, tt.caBundlePath)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				assert.Nil(t, clusters)

				return
			}

			require.NoError(t, err)

			y := marshalYAML(t, clusters)

			for _, w := range tt.want {
				assert.Contains(t, y, w)
			}

			for _, nw := range tt.notWant {
				assert.NotContains(t, y, nw)
			}
		})
	}
}
