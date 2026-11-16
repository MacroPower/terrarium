package accesslog

import (
	"net/netip"
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

// socketAddress returns the Envoy address of an IP address and a
// port.
func socketAddress(ip string, port uint32) *corev3.Address {
	return &corev3.Address{
		Address: &corev3.Address_SocketAddress{
			SocketAddress: &corev3.SocketAddress{
				Address:       ip,
				PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: port},
			},
		},
	}
}

func TestCommonDstIP(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		common *alsdata.AccessLogCommon
		want   netip.Addr
	}{
		"nil entry": {},
		"no upstream address": {
			common: &alsdata.AccessLogCommon{UpstreamCluster: "cluster"},
		},
		"IPv4 upstream": {
			common: &alsdata.AccessLogCommon{UpstreamRemoteAddress: socketAddress("192.0.2.7", 443)},
			want:   netip.MustParseAddr("192.0.2.7"),
		},
		"IPv6 upstream": {
			common: &alsdata.AccessLogCommon{UpstreamRemoteAddress: socketAddress("2001:db8::7", 443)},
			want:   netip.MustParseAddr("2001:db8::7"),
		},
		"IPv4-mapped IPv6 upstream": {
			common: &alsdata.AccessLogCommon{UpstreamRemoteAddress: socketAddress("::ffff:192.0.2.7", 443)},
			want:   netip.MustParseAddr("192.0.2.7"),
		},
		"upstream address that is not an IP address": {
			common: &alsdata.AccessLogCommon{UpstreamRemoteAddress: socketAddress("upstream.example", 443)},
		},
		"pipe upstream": {
			common: &alsdata.AccessLogCommon{
				UpstreamRemoteAddress: &corev3.Address{
					Address: &corev3.Address_Pipe{Pipe: &corev3.Pipe{Path: "/run/upstream.sock"}},
				},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, commonDstIP(tt.common))
		})
	}
}

func TestHTTPPort(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		req    *alsdata.HTTPRequestProperties
		common *alsdata.AccessLogCommon
		want   int
	}{
		"nil entry": {},
		"no authority": {
			req: &alsdata.HTTPRequestProperties{RequestMethod: corev3.RequestMethod_GET},
		},
		"upstream port": {
			req:    &alsdata.HTTPRequestProperties{Authority: "example.com"},
			common: &alsdata.AccessLogCommon{UpstreamRemoteAddress: socketAddress("192.0.2.7", 8080)},
			want:   8080,
		},
		"upstream port takes precedence over the authority": {
			req:    &alsdata.HTTPRequestProperties{Authority: "example.com:9090"},
			common: &alsdata.AccessLogCommon{UpstreamRemoteAddress: socketAddress("192.0.2.7", 8080)},
			want:   8080,
		},
		"upstream without a port": {
			req: &alsdata.HTTPRequestProperties{
				Authority:     "example.com:8443",
				RequestMethod: corev3.RequestMethod_CONNECT,
			},
			common: &alsdata.AccessLogCommon{
				UpstreamRemoteAddress: &corev3.Address{
					Address: &corev3.Address_EnvoyInternalAddress{
						EnvoyInternalAddress: &corev3.EnvoyInternalAddress{
							AddressNameSpecifier: &corev3.EnvoyInternalAddress_ServerListenerName{
								ServerListenerName: "tls_internal_8443",
							},
						},
					},
				},
			},
			want: 8443,
		},
		"CONNECT authority": {
			req: &alsdata.HTTPRequestProperties{
				Authority:     "example.com:8443",
				RequestMethod: corev3.RequestMethod_CONNECT,
			},
			want: 8443,
		},
		"CONNECT authority with an IPv6 address": {
			req: &alsdata.HTTPRequestProperties{
				Authority:     "[2001:db8::7]:8443",
				RequestMethod: corev3.RequestMethod_CONNECT,
			},
			want: 8443,
		},
		"CONNECT authority without a port": {
			req: &alsdata.HTTPRequestProperties{
				Authority:     "example.com",
				RequestMethod: corev3.RequestMethod_CONNECT,
			},
		},
		"plain HTTP authority with a port": {
			req: &alsdata.HTTPRequestProperties{
				Authority:     "example.com:8080",
				RequestMethod: corev3.RequestMethod_GET,
			},
			want: 8080,
		},
		"plain HTTP authority without a port": {
			req: &alsdata.HTTPRequestProperties{
				Authority:     "example.com",
				RequestMethod: corev3.RequestMethod_GET,
			},
			want: 80,
		},
		"plaintext request with the https scheme": {
			req: &alsdata.HTTPRequestProperties{
				Authority:     "example.com",
				Scheme:        "https",
				RequestMethod: corev3.RequestMethod_GET,
			},
			want: 80,
		},
		"plain HTTP authority with an empty port": {
			req: &alsdata.HTTPRequestProperties{
				Authority:     "example.com:",
				RequestMethod: corev3.RequestMethod_GET,
			},
			want: 80,
		},
		"plain HTTP authority with an IPv6 address": {
			req: &alsdata.HTTPRequestProperties{
				Authority:     "[2001:db8::7]",
				RequestMethod: corev3.RequestMethod_GET,
			},
			want: 80,
		},
		"TLS authority with a port": {
			req: &alsdata.HTTPRequestProperties{
				Authority:     "example.com:8443",
				RequestMethod: corev3.RequestMethod_GET,
			},
			common: &alsdata.AccessLogCommon{TlsProperties: &alsdata.TLSProperties{}},
			want:   8443,
		},
		"TLS authority without a port": {
			req: &alsdata.HTTPRequestProperties{
				Authority:     "example.com",
				RequestMethod: corev3.RequestMethod_GET,
			},
			common: &alsdata.AccessLogCommon{TlsProperties: &alsdata.TLSProperties{}},
		},
		"port that is not a number": {
			req: &alsdata.HTTPRequestProperties{
				Authority:     "example.com:http",
				RequestMethod: corev3.RequestMethod_GET,
			},
		},
		"port greater than 65535": {
			req: &alsdata.HTTPRequestProperties{
				Authority:     "example.com:65536",
				RequestMethod: corev3.RequestMethod_GET,
			},
		},
		"negative port": {
			req: &alsdata.HTTPRequestProperties{
				Authority:     "example.com:-1",
				RequestMethod: corev3.RequestMethod_GET,
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, httpPort(tt.req, tt.common))
		})
	}
}

func TestHTTPEntryToEvent(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		entry        *alsdata.HTTPAccessLogEntry
		wantDecision eventstore.Decision
		wantDomain   string
		// wantDstIP is the zero address for an entry without an
		// upstream address.
		wantDstIP  netip.Addr
		wantPort   int
		wantStatus int
	}{
		"plain 200 with authority": {
			entry: &alsdata.HTTPAccessLogEntry{
				CommonProperties: &alsdata.AccessLogCommon{
					UpstreamRemoteAddress: socketAddress("192.0.2.7", 443),
				},
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
			wantDstIP:    netip.MustParseAddr("192.0.2.7"),
			wantPort:     443,
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
			wantPort:     80,
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
			wantPort:     80,
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
			wantPort:     80,
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
			wantPort:     8080,
		},
		"denied CONNECT holds the port of its authority": {
			entry: &alsdata.HTTPAccessLogEntry{
				CommonProperties: &alsdata.AccessLogCommon{},
				Request: &alsdata.HTTPRequestProperties{
					Authority:     "blocked.example:8443",
					RequestMethod: corev3.RequestMethod_CONNECT,
				},
				Response: &alsdata.HTTPResponseProperties{
					ResponseCode:        wrapperspb.UInt32(403),
					ResponseCodeDetails: "direct_response",
				},
			},
			wantDecision: eventstore.DecisionDeny,
			wantDomain:   "blocked.example",
			wantPort:     8443,
			wantStatus:   403,
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

			assert.Equal(t, tt.wantDstIP, ev.DstIP)
			assert.Equal(t, tt.wantPort, ev.Port)
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
		// wantDstIP is the zero address for an entry without an
		// upstream address.
		wantDstIP netip.Addr
		wantPort  int
	}{
		"plain TCP allow with bytes": {
			entry: &alsdata.TCPAccessLogEntry{
				CommonProperties: &alsdata.AccessLogCommon{
					UpstreamCluster:       "tls_passthrough",
					UpstreamRemoteAddress: socketAddress("2001:db8::7", 8443),
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
			wantDstIP:    netip.MustParseAddr("2001:db8::7"),
			wantPort:     8443,
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
		"sni reject tag is deny": {
			entry: &alsdata.TCPAccessLogEntry{
				CommonProperties: &alsdata.AccessLogCommon{
					ResponseFlags: &alsdata.ResponseFlags{
						NoHealthyUpstream: true,
					},
					TlsProperties: &alsdata.TLSProperties{
						TlsSniHostname: "denied.example",
					},
					CustomTags: map[string]string{envoy.SNIRejectTag: "true"},
				},
			},
			wantDecision: eventstore.DecisionDeny,
			wantDomain:   "denied.example",
		},
		"no healthy upstream without the sni reject tag is error": {
			entry: &alsdata.TCPAccessLogEntry{
				CommonProperties: &alsdata.AccessLogCommon{
					ResponseFlags: &alsdata.ResponseFlags{
						NoHealthyUpstream: true,
					},
				},
			},
			wantDecision: eventstore.DecisionError,
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

			assert.Equal(t, tt.wantDstIP, ev.DstIP)
			assert.Equal(t, tt.wantPort, ev.Port)
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
