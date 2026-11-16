package envoy

import (
	"fmt"
	"slices"
	"time"
)

// AccessLogClusterName is the static-resource cluster name Envoy
// uses to talk to terrarium's gRPC AccessLog Service. Listeners
// reference it via [BuildHTTPGrpcAccessLog] or [BuildTCPGrpcAccessLog].
// Bootstrap config registers it via [BuildAccessLogCluster].
const AccessLogClusterName = "terrarium_accesslog"

// SNIRejectTag is the custom tag that the gRPC access loggers of the
// default filter chain of a TLS listener add to each entry. That chain
// closes each connection whose SNI no rule of the port allows, so the
// tag marks the entry as a policy denial. Envoy records no upstream
// cluster for such a connection, so the entry does not name
// [MissingSNIBlackholeCluster].
const SNIRejectTag = "terrarium.sni_reject"

// withSNIRejectTag returns a copy of logs in which every TCP gRPC
// access logger adds [SNIRejectTag] to its entries. It returns the
// other access loggers unchanged.
func withSNIRejectTag(logs []AccessLog) []AccessLog {
	out := make([]AccessLog, 0, len(logs))

	for _, l := range logs {
		if cfg, ok := l.TypedConfig.(tcpGrpcAccessLogConfig); ok {
			cfg.CommonConfig.CustomTags = append(slices.Clone(cfg.CommonConfig.CustomTags), customTag{
				Tag:     SNIRejectTag,
				Literal: customTagLiteral{Value: "true"},
			})
			l.TypedConfig = cfg
		}

		out = append(out, l)
	}

	return out
}

// commonGrpcConfig builds the shared CommonGrpcAccessLogConfig used by
// the HTTP and TCP gRPC access loggers. The logName identifies the
// listener; bufBytes and flushMs control client-side buffering before
// the gRPC stream flushes.
func commonGrpcConfig(logName string, bufBytes, flushMs uint32) commonGrpcAccessLogConfig {
	return commonGrpcAccessLogConfig{
		LogName: logName,
		GrpcService: grpcServiceConfig{
			EnvoyGrpc: envoyGrpcConfig{
				ClusterName: AccessLogClusterName,
			},
		},
		BufferSizeBytes:     bufBytes,
		BufferFlushInterval: durationString(time.Duration(flushMs) * time.Millisecond),
	}
}

// BuildHTTPGrpcAccessLog returns an [AccessLog] entry configured as
// Envoy's HttpGrpcAccessLog for HTTP listeners. The cluster reference
// is hardcoded to [AccessLogClusterName]; the matching upstream socket
// comes from [BuildAccessLogCluster].
func BuildHTTPGrpcAccessLog(logName string, bufBytes, flushMs uint32) []AccessLog {
	return []AccessLog{{
		Name: "envoy.access_loggers.http_grpc",
		TypedConfig: httpGrpcAccessLogConfig{
			AtType:       "type.googleapis.com/envoy.extensions.access_loggers.grpc.v3.HttpGrpcAccessLogConfig",
			CommonConfig: commonGrpcConfig(logName, bufBytes, flushMs),
		},
	}}
}

// BuildTCPGrpcAccessLog returns an [AccessLog] entry configured as
// Envoy's TcpGrpcAccessLog for TCP listeners. The cluster reference
// is hardcoded to [AccessLogClusterName]; the matching upstream socket
// comes from [BuildAccessLogCluster].
func BuildTCPGrpcAccessLog(logName string, bufBytes, flushMs uint32) []AccessLog {
	return []AccessLog{{
		Name: "envoy.access_loggers.tcp_grpc",
		TypedConfig: tcpGrpcAccessLogConfig{
			AtType:       "type.googleapis.com/envoy.extensions.access_loggers.grpc.v3.TcpGrpcAccessLogConfig",
			CommonConfig: commonGrpcConfig(logName, bufBytes, flushMs),
		},
	}}
}

// durationString formats d as an Envoy-compatible Duration string
// ("1.500s", "0.500s") that survives proto3 google.protobuf.Duration
// decoding. Zero returns the empty string so the YAML omitempty tag
// elides the field.
func durationString(d time.Duration) string {
	if d <= 0 {
		return ""
	}

	return fmt.Sprintf("%.3fs", d.Seconds())
}

// BuildAccessLogCluster returns the static [cluster] entry that the
// gRPC ALS access loggers reference. Traffic is routed to a single
// Unix pipe endpoint at socket. HTTP/2 is enabled because gRPC
// requires it. The connect timeout is generous so a slow init does
// not drop early access log batches.
func BuildAccessLogCluster(socket string) cluster {
	return cluster{
		Name:           AccessLogClusterName,
		Type:           clusterTypeStatic,
		LBPolicy:       lbPolicyRoundRobin,
		ConnectTimeout: "1s",
		TypedExtensionProtocolOptions: map[string]any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": httpProtocolOptions{
				AtType: "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
				ExplicitHTTPConfig: &explicitHTTPConfig{
					HTTP2Options: &http2Options{},
				},
			},
		},
		LoadAssignment: &loadAssignment{
			ClusterName: AccessLogClusterName,
			Endpoints: []endpoint{{
				LBEndpoints: []lbEndpoint{{
					Endpoint: endpointAddress{
						Address: address{
							Pipe: &pipeAddress{Path: socket},
						},
					},
				}},
			}},
		},
	}
}
