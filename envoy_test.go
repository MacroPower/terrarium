package terrarium_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium"
)

func TestBuildAccessLog(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		logging  bool
		wantLen  int
		wantName string
	}{
		"disabled": {logging: false},
		"enabled":  {logging: true, wantLen: 1, wantName: "envoy.access_loggers.stderr"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			logs := terrarium.BuildAccessLog(tt.logging)
			if tt.wantLen == 0 {
				assert.Nil(t, logs)
				return
			}

			require.Len(t, logs, tt.wantLen)
			assert.Equal(t, tt.wantName, logs[0].Name)
		})
	}
}

func TestGenerateEnvoyConfig(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg      *terrarium.Config
		certsDir string
		want     []string
		notWant  []string
	}{
		"basic TLS and HTTP": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "github.com"}, {MatchName: "golang.org"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			want: []string{
				"tls_passthrough", "http_forward",
				"github.com", "golang.org",
				"dynamic_forward_proxy_cluster",
			},
		},
		"with tcp forwards": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "golang.org"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				}),
				TCPForwards: []terrarium.TCPForward{{Port: 22, Host: "github.com"}},
			},
			want: []string{
				"tls_passthrough", "http_forward",
				"tcp_forward_22", "github.com",
			},
		},
		"multiple tcp forwards": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				}),
				TCPForwards: []terrarium.TCPForward{
					{Port: 22, Host: "github.com"},
					{Port: 3306, Host: "db.example.com"},
				},
			},
			want: []string{
				"tcp_forward_22", "tcp_forward_3306",
				"github.com", "db.example.com",
			},
		},
		"extra ports with tcp forwards": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "github.com"}, {MatchName: "golang.org"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{
						{Port: "80"}, {Port: "443"}, {Port: "8080"},
					}}},
				}),
				TCPForwards: []terrarium.TCPForward{{Port: 22, Host: "github.com"}},
			},
			want: []string{
				"tls_passthrough", "http_forward",
				"tls_passthrough_8080", "tcp_forward_22",
			},
		},
		"no tcp forwards no extra ports": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "golang.org"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			notWant: []string{"tcp_forward", "STRICT_DNS"},
		},
		"logging enabled": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				}),
				Logging: true,
			},
			want: []string{"envoy.access_loggers.stderr"},
		},
		"path restricted domain gets direct response": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Path: "/v1/completions"},
							{Path: "/v1/models"},
						}},
					}},
				},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "cdn.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			want: []string{
				"restricted_api.example.com",
				"/v1/completions",
				"/v1/models",
				"direct_response",
				"403",
				"cdn.example.com",
			},
		},
		"MITM filter chain with certs": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "cdn.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			certsDir: "/etc/terrarium/certs",
			want: []string{
				"mitm_forward_proxy_cluster",
				"DownstreamTlsContext",
				"/etc/terrarium/certs/api.example.com/cert.pem",
				"/etc/terrarium/certs/api.example.com/key.pem",
				"UpstreamTlsContext",
				"mitm_api.example.com",
				"dynamic_forward_proxy_cluster",
				"alpn_protocols",
				"h2",
				"http/1.1",
				"use_downstream_protocol_config",
				"HttpProtocolOptions",
			},
		},
		"no MITM without certsDir": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{
					Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
					Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
				}},
			})},
			certsDir: "",
			notWant:  []string{"DownstreamTlsContext", "mitm_api.example.com"},
		},
		"no MITM cluster without path rules": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			notWant: []string{"mitm_forward_proxy_cluster", "UpstreamTlsContext"},
		},
		"method-only restriction": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Method: "GET"}}},
					}},
				},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "cdn.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			want: []string{
				"restricted_api.example.com",
				":method",
				"regex: ^GET$",
				"direct_response",
				"403",
				"cdn.example.com",
			},
		},
		"paths and methods paired not cross-producted": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{
					Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
					Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
						{Path: "/v1/", Method: "GET"},
						{Path: "/v1/", Method: "POST"},
					}},
				}},
			})},
			want: []string{
				"restricted_api.example.com",
				"regex: /v1/",
				":method",
				"regex: ^GET$",
				"regex: ^POST$",
				"direct_response",
				"403",
			},
			notWant: []string{
				"^(GET|POST)$",
			},
		},
		"MITM triggered by methods-only rule": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{
					Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
					Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Method: "GET"}}},
				}},
			})},
			certsDir: "/etc/terrarium/certs",
			want: []string{
				"mitm_forward_proxy_cluster",
				"DownstreamTlsContext",
				"/etc/terrarium/certs/api.example.com/cert.pem",
				"mitm_api.example.com",
				":method",
				"use_downstream_protocol_config",
				"HttpProtocolOptions",
			},
		},
		"no method restriction has no method header": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			notWant: []string{":method"},
		},
		"host-only restriction": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{
					Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
					Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
						{Host: "api.example.com"},
					}},
				}},
			})},
			want: []string{
				"restricted_api.example.com",
				":authority",
				"regex: ^api.example.com(:[0-9]+)?$",
				"direct_response",
				"403",
			},
			notWant: []string{":method"},
		},
		"host and method combined": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{
					Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
					Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
						{Method: "GET", Host: "api.example.com"},
					}},
				}},
			})},
			want: []string{
				":method",
				"regex: ^GET$",
				":authority",
				"regex: ^api.example.com(:[0-9]+)?$",
			},
		},
		"no host restriction has no authority header": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{
					Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
					Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
						{Method: "GET"},
					}},
				}},
			})},
			want:    []string{":method"},
			notWant: []string{":authority"},
		},
		"per-port domain scoping": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "always.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{
						{Port: "443"}, {Port: "80"}, {Port: "8080"},
					}}},
				},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "only8080.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080"}}}},
				},
			)},
			want: []string{
				"tls_passthrough_8080",
				"only8080.com",
				"always.com",
			},
		},
		"open port gets catch-all TLS chain": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "github.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				},
				terrarium.EgressRule{ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080"}}}}},
			)},
			want: []string{
				"tls_passthrough_8080",
				"tls_passthrough_8080_open",
			},
		},
		"open port 80 gets catch-all HTTP vhost": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "github.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				},
				terrarium.EgressRule{ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "80"}}}}},
			)},
			want: []string{
				"name: open",
				`- "*"`,
			},
		},
		"open port overrides L7 restrictions": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/", Method: "GET"}}},
					}},
				},
				terrarium.EgressRule{ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{
					{Port: "443"}, {Port: "80"},
				}}}},
			)},
			certsDir: "/etc/terrarium/certs",
			want: []string{
				"api.example.com",
				"tls_passthrough",
				"http_forward",
			},
			notWant: []string{
				"restricted_",
				"direct_response",
				"403",
				"mitm_api.example.com",
				"DownstreamTlsContext",
			},
		},
		"bare wildcard TLS catch-all passthrough": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
			})},
			want: []string{
				"tls_passthrough",
				"tls_passthrough_open",
			},
			notWant: []string{
				`server_names`,
			},
		},
		"bare wildcard HTTP catch-all vhost": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "80"}}}},
			})},
			want: []string{
				"http_forward",
				`- "*"`,
			},
		},
		"bare wildcard HTTP no duplicate open vhost": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "80"}}}},
				},
				terrarium.EgressRule{ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "80"}}}}},
			)},
			want: []string{
				"http_forward",
				`- "*"`,
			},
			notWant: []string{
				"name: open",
			},
		},
		// New mode tests.
		"nil egress produces minimal config": {
			cfg:     &terrarium.Config{},
			notWant: []string{"tls_passthrough", "http_forward", "dynamic_forward_proxy_cluster"},
		},
		"empty egress produces minimal config": {
			cfg:     &terrarium.Config{Egress: egressRules()},
			notWant: []string{"tls_passthrough", "http_forward", "dynamic_forward_proxy_cluster"},
		},
		"nil egress with tcp forwards": {
			cfg: &terrarium.Config{
				TCPForwards: []terrarium.TCPForward{{Port: 22, Host: "github.com"}},
			},
			want:    []string{"tcp_forward_22", "github.com", "STRICT_DNS"},
			notWant: []string{"tls_passthrough", "http_forward", "dynamic_forward_proxy_cluster"},
		},
		"empty rule with FQDN+L7 generates FQDN listeners": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				},
			)},
			certsDir: "/etc/terrarium/certs",
			want: []string{
				"tls_passthrough",
				"http_forward",
				"restricted_api.example.com",
				"mitm_api.example.com",
				"DownstreamTlsContext",
				"/v1/",
				"403",
				"dynamic_forward_proxy_cluster",
			},
		},
		"empty HTTP produces passthrough not MITM": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{
					Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
					Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{}},
				}},
			})},
			certsDir: "/etc/terrarium/certs",
			want: []string{
				"api.example.com",
				"tls_passthrough",
				"http_forward",
			},
			notWant: []string{
				"restricted_api.example.com",
				"direct_response",
				"mitm_forward_proxy_cluster",
				"DownstreamTlsContext",
			},
		},
		"wildcard gets RBAC filter": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			want: []string{
				"envoy.filters.network.rbac",
				"ALLOW",
				`^[-a-zA-Z0-9_]+\\.example\\.com$`,
			},
		},
		"double-star wildcard gets multi-label RBAC regex": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "**.example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			want: []string{
				"envoy.filters.network.rbac",
				"ALLOW",
				`^[-a-zA-Z0-9_]+(\\.[-a-zA-Z0-9_]+)*\\.example\\.com$`,
				"*.example.com",
				// HTTP RBAC also present with multi-label regex + port suffix:
				"envoy.filters.http.rbac",
				`^[-a-zA-Z0-9_]+(\\.[-a-zA-Z0-9_]+)*\\.example\\.com(:\\d+)?$`,
			},
			notWant: []string{
				"**.example.com",
			},
		},
		"exact domain no RBAC": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			want:    []string{"example.com"},
			notWant: []string{"envoy.filters.network.rbac"},
		},
		"mixed wildcard and exact": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "github.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			want: []string{
				"github.com",
				"*.example.com",
				"envoy.filters.network.rbac",
				`^[-a-zA-Z0-9_]+\\.example\\.com$`,
			},
		},
		"multiple wildcards": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{
					{MatchPattern: "*.a.com"},
					{MatchPattern: "*.b.com"},
				},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			want: []string{
				`^[-a-zA-Z0-9_]+\\.a\\.com$`,
				`^[-a-zA-Z0-9_]+\\.b\\.com$`,
				"envoy.filters.network.rbac",
			},
		},
		"wildcard on extra port": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080"}}}},
			})},
			want: []string{
				"tls_passthrough_8080",
				"envoy.filters.network.rbac",
				`^[-a-zA-Z0-9_]+\\.example\\.com$`,
			},
		},
		"MITM on extra port": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{
					Ports: []terrarium.Port{{Port: "8080"}},
					Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
				}},
			})},
			certsDir: "/etc/terrarium/certs",
			want: []string{
				"tls_passthrough_8080",
				"mitm_api.example.com",
				"/etc/terrarium/certs/api.example.com/cert.pem",
				"DownstreamTlsContext",
			},
		},
		"wildcard HTTP gets RBAC filter on :authority": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
			})},
			want: []string{
				"envoy.filters.http.rbac",
				":authority",
				`^[-a-zA-Z0-9_]+\\.example\\.com(:\\d+)?$`,
				// TLS RBAC also present:
				"envoy.filters.network.rbac",
				`^[-a-zA-Z0-9_]+\\.example\\.com$`,
			},
		},
		"exact domain HTTP no RBAC": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "80"}}}},
			})},
			notWant: []string{"envoy.filters.http.rbac"},
		},
		"mixed wildcard and exact HTTP RBAC includes both": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "github.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "80"}}}},
				},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "80"}}}},
				},
			)},
			want: []string{
				"envoy.filters.http.rbac",
				`^[-a-zA-Z0-9_]+\\.example\\.com(:\\d+)?$`,
				`^github\\.com(:\\d+)?$`,
			},
		},
		"open port 80 no HTTP RBAC despite wildcards": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "80"}}}},
				},
				terrarium.EgressRule{ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "80"}}}}},
			)},
			notWant: []string{"envoy.filters.http.rbac"},
		},
		"bare wildcard HTTP no RBAC": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "80"}}}},
			})},
			notWant: []string{"envoy.filters.http.rbac"},
		},
		"double-star wildcard HTTP gets multi-label RBAC regex": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "**.example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "80"}}}},
			})},
			want: []string{
				"envoy.filters.http.rbac",
				":authority",
				`^[-a-zA-Z0-9_]+(\\.[-a-zA-Z0-9_]+)*\\.example\\.com(:\\d+)?$`,
			},
		},
		"multiple wildcards HTTP RBAC": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{
					{MatchPattern: "*.a.com"},
					{MatchPattern: "*.b.com"},
				},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "80"}}}},
			})},
			want: []string{
				"envoy.filters.http.rbac",
				`^[-a-zA-Z0-9_]+\\.a\\.com(:\\d+)?$`,
				`^[-a-zA-Z0-9_]+\\.b\\.com(:\\d+)?$`,
			},
		},
		"HTTP forward listener has path normalization": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "80"}}}},
			})},
			want: []string{
				"normalize_path: true",
				"merge_slashes: true",
				"path_with_escaped_slashes_action: UNESCAPE_AND_REDIRECT",
			},
		},
		"MITM listener has path normalization": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{
					Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
					Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
				}},
			})},
			certsDir: "/etc/terrarium/certs",
			want: []string{
				"mitm_api.example.com",
				"normalize_path: true",
				"merge_slashes: true",
				"path_with_escaped_slashes_action: UNESCAPE_AND_REDIRECT",
			},
		},
		"MITM-only config (no HTTP forward) has path normalization": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{
					Ports: []terrarium.Port{{Port: "443"}},
					Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
				}},
			})},
			certsDir: "/etc/terrarium/certs",
			want: []string{
				"mitm_api.example.com",
				"normalize_path: true",
				"merge_slashes: true",
				"path_with_escaped_slashes_action: UNESCAPE_AND_REDIRECT",
			},
			notWant: []string{
				"http_forward",
			},
		},
		"passthrough-only config has no normalization fields": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
			})},
			notWant: []string{
				"normalize_path",
				"merge_slashes",
				"UNESCAPE_AND_REDIRECT",
			},
		},
		"headers presence check": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{
					Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
					Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
						{Headers: []string{"X-Custom", "Authorization"}},
					}},
				}},
			})},
			certsDir: "/etc/terrarium/certs",
			want: []string{
				"restricted_api.example.com",
				"present_match: true",
				"name: X-Custom",
				"name: Authorization",
				"direct_response",
				"403",
			},
		},
		"headerMatches value check": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{
					Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
					Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
						{HeaderMatches: []terrarium.HeaderMatch{{Name: "X-Token", Value: "secret"}}},
					}},
				}},
			})},
			certsDir: "/etc/terrarium/certs",
			want: []string{
				"restricted_api.example.com",
				"name: X-Token",
				"exact: secret",
				"direct_response",
				"403",
			},
			notWant: []string{"present_match"},
		},
		"headers combined with method and path": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{
					Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
					Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
						{Method: "GET", Path: "/v1/", Headers: []string{"X-Custom"}},
					}},
				}},
			})},
			certsDir: "/etc/terrarium/certs",
			want: []string{
				"restricted_api.example.com",
				":method",
				"regex: ^GET$",
				"regex: /v1/",
				"name: X-Custom",
				"present_match: true",
			},
		},
		"separate FQDN and CIDR generates Envoy for FQDN only": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				},
				terrarium.EgressRule{
					ToCIDR:  []string{"10.0.0.0/8"},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			want: []string{
				"tls_passthrough", "http_forward",
				"api.example.com",
				"dynamic_forward_proxy_cluster",
			},
			notWant: []string{
				"10.0.0.0",
			},
		},
		"route actions have request timeout": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "cdn.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			want: []string{
				"timeout: 3600s",
			},
		},
		"HCMs have stream idle timeout": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			want: []string{
				"stream_idle_timeout: 300s",
			},
		},
		"HCMs set UseRemoteAddress and SkipXffAppend": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			want: []string{
				"use_remote_address: true",
				"skip_xff_append: true",
			},
		},
		"gRPC route match and timeout handling": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				},
			)},
			want: []string{
				"grpc: {}",
				"grpc_timeout_header_max: 0s",
			},
		},
		"TLS listener has default filter chain for missing SNI": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
			})},
			want: []string{
				"default_filter_chain:",
				"missing_sni_blackhole",
				"tls_passthrough_no_sni",
				"missing_sni src=%DOWNSTREAM_REMOTE_ADDRESS% dst=%DOWNSTREAM_LOCAL_ADDRESS%",
			},
		},
		"TLS filter chains have transport_protocol tls": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "cdn.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				},
				terrarium.EgressRule{ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080"}}}}},
			)},
			certsDir: "/etc/terrarium/certs",
			want: []string{
				"transport_protocol: tls",
			},
		},
		"clusters have connect timeout": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Method: "GET", Path: "/v1/"}}},
					}},
				}),
				TCPForwards: []terrarium.TCPForward{{Port: 22, Host: "github.com"}},
			},
			want: []string{
				"connect_timeout: 5s",
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			conf, err := terrarium.GenerateEnvoyConfig(tt.cfg, tt.certsDir, "")
			require.NoError(t, err)

			for _, s := range tt.want {
				assert.Contains(t, conf, s)
			}

			for _, s := range tt.notWant {
				assert.NotContains(t, conf, s)
			}
		})
	}
}
