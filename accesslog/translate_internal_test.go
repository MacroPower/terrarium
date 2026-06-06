package accesslog

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	alsdata "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"

	"go.jacobcolvin.com/terrarium/envoy"
	"go.jacobcolvin.com/terrarium/eventstore"
)

func TestHTTPEntryToEvent(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		entry        *alsdata.HTTPAccessLogEntry
		wantDecision eventstore.Decision
		wantDomain   string
		wantStatus   int
	}{
		"plain 200 with authority": {
			entry: &alsdata.HTTPAccessLogEntry{
				CommonProperties: &alsdata.AccessLogCommon{},
				Request: &alsdata.HTTPRequestProperties{
					Authority:     "example.com",
					Path:          "/",
					RequestMethod: corev3.RequestMethod_GET,
				},
				Response: &alsdata.HTTPResponseProperties{
					ResponseCode: wrapperspb.UInt32(200),
				},
			},
			wantDecision: eventstore.DecisionAllow,
			wantDomain:   "example.com",
			wantStatus:   200,
		},
		"403 rbac_access_denied is deny": {
			entry: &alsdata.HTTPAccessLogEntry{
				CommonProperties: &alsdata.AccessLogCommon{},
				Request: &alsdata.HTTPRequestProperties{
					Authority: "blocked.example",
				},
				Response: &alsdata.HTTPResponseProperties{
					ResponseCode:        wrapperspb.UInt32(403),
					ResponseCodeDetails: "rbac_access_denied_matched_policy[deny_all]",
				},
			},
			wantDecision: eventstore.DecisionDeny,
			wantDomain:   "blocked.example",
			wantStatus:   403,
		},
		"403 direct_response is deny": {
			entry: &alsdata.HTTPAccessLogEntry{
				CommonProperties: &alsdata.AccessLogCommon{},
				Request: &alsdata.HTTPRequestProperties{
					Authority: "blocked.example",
				},
				Response: &alsdata.HTTPResponseProperties{
					ResponseCode:        wrapperspb.UInt32(403),
					ResponseCodeDetails: "direct_response",
				},
			},
			wantDecision: eventstore.DecisionDeny,
		},
		"5xx is error": {
			entry: &alsdata.HTTPAccessLogEntry{
				CommonProperties: &alsdata.AccessLogCommon{},
				Request: &alsdata.HTTPRequestProperties{
					Authority: "broken.example",
				},
				Response: &alsdata.HTTPResponseProperties{
					ResponseCode: wrapperspb.UInt32(503),
				},
			},
			wantDecision: eventstore.DecisionError,
		},
		"authority empty falls back to upstream cluster": {
			entry: &alsdata.HTTPAccessLogEntry{
				CommonProperties: &alsdata.AccessLogCommon{
					UpstreamCluster: "fallback_cluster",
				},
				Request: &alsdata.HTTPRequestProperties{},
				Response: &alsdata.HTTPResponseProperties{
					ResponseCode: wrapperspb.UInt32(200),
				},
			},
			wantDecision: eventstore.DecisionAllow,
			wantDomain:   "fallback_cluster",
			wantStatus:   200,
		},
		"authority strips port": {
			entry: &alsdata.HTTPAccessLogEntry{
				CommonProperties: &alsdata.AccessLogCommon{},
				Request: &alsdata.HTTPRequestProperties{
					Authority: "host.example:8080",
				},
				Response: &alsdata.HTTPResponseProperties{
					ResponseCode: wrapperspb.UInt32(200),
				},
			},
			wantDecision: eventstore.DecisionAllow,
			wantDomain:   "host.example",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ev := httpEntryToEvent(tt.entry)
			assert.Equal(t, eventstore.SourceEnvoy, ev.Source)
			assert.Equal(t, tt.wantDecision, ev.Decision)

			if tt.wantDomain != "" {
				assert.Equal(t, tt.wantDomain, ev.Domain)
			}

			if tt.wantStatus != 0 {
				assert.Equal(t, tt.wantStatus, ev.HTTPStatus)
			}

			assert.Equal(t, eventstore.ProtocolHTTP, ev.Protocol)
		})
	}
}

func TestTCPEntryToEvent(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		entry        *alsdata.TCPAccessLogEntry
		wantDecision eventstore.Decision
		wantDomain   string
	}{
		"plain TCP allow with bytes": {
			entry: &alsdata.TCPAccessLogEntry{
				CommonProperties: &alsdata.AccessLogCommon{
					UpstreamCluster: "tls_passthrough",
					TlsProperties: &alsdata.TLSProperties{
						TlsSniHostname: "example.com",
					},
				},
				ConnectionProperties: &alsdata.ConnectionProperties{
					SentBytes:     1024,
					ReceivedBytes: 512,
				},
			},
			wantDecision: eventstore.DecisionAllow,
			wantDomain:   "example.com",
		},
		"missing-sni blackhole NH is deny": {
			entry: &alsdata.TCPAccessLogEntry{
				CommonProperties: &alsdata.AccessLogCommon{
					UpstreamCluster: envoy.MissingSNIBlackholeCluster,
					ResponseFlags: &alsdata.ResponseFlags{
						NoHealthyUpstream: true,
					},
				},
			},
			wantDecision: eventstore.DecisionDeny,
		},
		"network-rbac termination details is deny": {
			entry: &alsdata.TCPAccessLogEntry{
				CommonProperties: &alsdata.AccessLogCommon{
					ConnectionTerminationDetails: "network_rbac_access_denied",
				},
			},
			wantDecision: eventstore.DecisionDeny,
		},
		"sni populated takes priority over upstream cluster": {
			entry: &alsdata.TCPAccessLogEntry{
				CommonProperties: &alsdata.AccessLogCommon{
					UpstreamCluster: "tls_passthrough",
					TlsProperties: &alsdata.TLSProperties{
						TlsSniHostname: "specific.example",
					},
				},
				ConnectionProperties: &alsdata.ConnectionProperties{
					SentBytes: 10,
				},
			},
			wantDecision: eventstore.DecisionAllow,
			wantDomain:   "specific.example",
		},
		"no sni falls back to upstream cluster": {
			entry: &alsdata.TCPAccessLogEntry{
				CommonProperties: &alsdata.AccessLogCommon{
					UpstreamCluster: "catch_all_tcp",
				},
				ConnectionProperties: &alsdata.ConnectionProperties{
					SentBytes: 10,
				},
			},
			wantDecision: eventstore.DecisionAllow,
			wantDomain:   "catch_all_tcp",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ev := tcpEntryToEvent(tt.entry)
			assert.Equal(t, eventstore.SourceEnvoy, ev.Source)
			assert.Equal(t, tt.wantDecision, ev.Decision)

			if tt.wantDomain != "" {
				assert.Equal(t, tt.wantDomain, ev.Domain)
			}

			assert.Equal(t, eventstore.ProtocolTCP, ev.Protocol)
		})
	}
}

func TestHTTPEntryDuration(t *testing.T) {
	t.Parallel()

	entry := &alsdata.HTTPAccessLogEntry{
		CommonProperties: &alsdata.AccessLogCommon{
			StartTime: timestamppb.New(time.Now()),
			Duration:  durationpb.New(250 * time.Millisecond),
		},
		Request: &alsdata.HTTPRequestProperties{
			Authority: "host.example",
		},
		Response: &alsdata.HTTPResponseProperties{
			ResponseCode: wrapperspb.UInt32(200),
		},
	}

	ev := httpEntryToEvent(entry)
	assert.Equal(t, int64(250), ev.DurationMS)
}

func TestStripPort(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"host":           "host",
		"host:80":        "host",
		"host.tld":       "host.tld",
		"host.tld:443":   "host.tld",
		"[::1]":          "[::1]",
		"[::1]:80":       "::1",
		"[fd00::1]:443":  "fd00::1",
		"v6:literal:foo": "v6:literal:foo",
	}

	for in, want := range tests {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, want, stripPort(in))
		})
	}
}
