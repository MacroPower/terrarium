package accesslog

import (
	"net"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	alsdata "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"

	"go.jacobcolvin.com/terrarium/envoy"
	"go.jacobcolvin.com/terrarium/eventstore"
)

// httpResponseDetailRBAC and httpResponseDetailDirect are the
// response_code_details prefixes Envoy emits on a 403 from the RBAC
// filter or a configured direct response, respectively. Both indicate
// a policy-driven HTTP deny.
const (
	httpResponseDetailRBAC   = "rbac_access_denied"
	httpResponseDetailDirect = "direct_response"
)

// httpEntryToEvent converts an Envoy HTTPAccessLogEntry into an
// [eventstore.Event]. The response_code and response_code_details
// mapping is in [httpDecision].
func httpEntryToEvent(entry *alsdata.HTTPAccessLogEntry) eventstore.Event {
	common := entry.GetCommonProperties()
	req := entry.GetRequest()
	resp := entry.GetResponse()
	status := resp.GetResponseCode().GetValue()

	ev := eventstore.Event{
		Source:   eventstore.SourceEnvoy,
		Time:     extractTime(common),
		Domain:   httpDomain(req, common),
		Port:     commonPort(common),
		Protocol: eventstore.ProtocolHTTP,
	}

	if status > 0 {
		ev.HTTPStatus = int(status)
	}

	if method := req.GetRequestMethod(); method != corev3.RequestMethod_METHOD_UNSPECIFIED {
		ev.HTTPMethod = method.String()
	}

	if path := req.GetPath(); path != "" {
		ev.HTTPPath = path
	}

	if flags := flagsString(common); flags != "" {
		ev.Flags = flags
	}

	ev.BytesRx = int64(common.GetUpstreamWireBytesReceived()) + int64(common.GetDownstreamWireBytesReceived())
	ev.BytesTx = int64(common.GetUpstreamWireBytesSent()) + int64(common.GetDownstreamWireBytesSent())

	if d := common.GetDuration(); d != nil {
		ev.DurationMS = int64(d.AsDuration() / time.Millisecond)
	}

	ev.Decision = httpDecision(status, resp.GetResponseCodeDetails())

	return ev
}

// tcpEntryToEvent converts an Envoy TCPAccessLogEntry into an
// [eventstore.Event]. Domain selection tries SNI first (TLS), then
// upstream cluster, then upstream remote address. Protobuf getters
// are nil-safe, so a missing ConnectionProperties yields zero bytes.
func tcpEntryToEvent(entry *alsdata.TCPAccessLogEntry) eventstore.Event {
	common := entry.GetCommonProperties()
	conn := entry.GetConnectionProperties()

	ev := eventstore.Event{
		Source:   eventstore.SourceEnvoy,
		Time:     extractTime(common),
		Domain:   tcpDomain(common),
		Port:     commonPort(common),
		Protocol: eventstore.ProtocolTCP,
		BytesRx:  int64(conn.GetReceivedBytes()),
		BytesTx:  int64(conn.GetSentBytes()),
	}

	if flags := flagsString(common); flags != "" {
		ev.Flags = flags
	}

	if d := common.GetDuration(); d != nil {
		ev.DurationMS = int64(d.AsDuration() / time.Millisecond)
	}

	ev.Decision = tcpDecision(common, conn)

	return ev
}

// httpDomain selects the canonical domain for an HTTP entry. The
// :authority header is preferred. The upstream cluster is the
// fallback when authority is empty (e.g. requests rejected before
// the HTTP filter chain consumes the headers).
func httpDomain(req *alsdata.HTTPRequestProperties, common *alsdata.AccessLogCommon) string {
	if a := req.GetAuthority(); a != "" {
		return stripPort(a)
	}

	return common.GetUpstreamCluster()
}

// commonPort returns the destination port from the upstream remote
// address on an HTTP or TCP entry's [alsdata.AccessLogCommon], or 0
// if the address is missing.
func commonPort(common *alsdata.AccessLogCommon) int {
	return int(common.GetUpstreamRemoteAddress().GetSocketAddress().GetPortValue())
}

// tcpDomain selects the canonical domain for a TCP entry. SNI takes
// priority because the :authority header is absent on TCP. The
// upstream cluster is the second fallback. The IP from
// upstream_remote_address is the last resort.
func tcpDomain(common *alsdata.AccessLogCommon) string {
	if sni := common.GetTlsProperties().GetTlsSniHostname(); sni != "" {
		return sni
	}

	if cluster := common.GetUpstreamCluster(); cluster != "" {
		return cluster
	}

	return common.GetUpstreamRemoteAddress().GetSocketAddress().GetAddress()
}

// httpDecision implements the HTTP-row mapping. 403 with
// response_code_details starting with rbac_access_denied or
// direct_response is a deny. 2xx/3xx without a terminal flag is an
// allow. Anything else (5xx, network errors, missing status) is an
// error.
func httpDecision(status uint32, details string) eventstore.Decision {
	if status == 403 && (strings.HasPrefix(details, httpResponseDetailRBAC) ||
		strings.HasPrefix(details, httpResponseDetailDirect)) {
		return eventstore.DecisionDeny
	}

	if status >= 200 && status < 400 {
		return eventstore.DecisionAllow
	}

	return eventstore.DecisionError
}

// tcpDecision implements the TCP row of the decision table. NH on a
// missing-SNI blackhole route is a deny. Non-empty
// connection_termination_details signals a network-RBAC deny. Bytes
// flowing in either direction without a terminal flag is an allow.
// Anything else is an error.
func tcpDecision(common *alsdata.AccessLogCommon, conn *alsdata.ConnectionProperties) eventstore.Decision {
	if common.GetResponseFlags().GetNoHealthyUpstream() &&
		common.GetUpstreamCluster() == envoy.MissingSNIBlackholeCluster {
		return eventstore.DecisionDeny
	}

	if details := common.GetConnectionTerminationDetails(); details != "" {
		return eventstore.DecisionDeny
	}

	if conn.GetSentBytes() > 0 || conn.GetReceivedBytes() > 0 {
		return eventstore.DecisionAllow
	}

	return eventstore.DecisionError
}

// extractTime returns the start time recorded on the AccessLogCommon,
// falling back to time.Now() when missing or when common is nil.
func extractTime(common *alsdata.AccessLogCommon) time.Time {
	if t := common.GetStartTime(); t != nil {
		return t.AsTime()
	}

	return time.Now()
}

// responseFlagMap pairs each [alsdata.ResponseFlags] getter with the
// short label Envoy emits in `%RESPONSE_FLAGS%` access-log
// substitutions. Iteration order matches the slice order.
var responseFlagMap = []struct {
	get   func(*alsdata.ResponseFlags) bool
	label string
}{
	{(*alsdata.ResponseFlags).GetNoHealthyUpstream, "NH"},
	{(*alsdata.ResponseFlags).GetUpstreamConnectionFailure, "UF"},
	{(*alsdata.ResponseFlags).GetUpstreamConnectionTermination, "UC"},
	{(*alsdata.ResponseFlags).GetUpstreamOverflow, "UO"},
	{(*alsdata.ResponseFlags).GetNoRouteFound, "NR"},
	{(*alsdata.ResponseFlags).GetUpstreamRequestTimeout, "UT"},
	{(*alsdata.ResponseFlags).GetDownstreamConnectionTermination, "DC"},
	{(*alsdata.ResponseFlags).GetUpstreamRetryLimitExceeded, "URX"},
	{(*alsdata.ResponseFlags).GetStreamIdleTimeout, "SI"},
	{(*alsdata.ResponseFlags).GetInvalidEnvoyRequestHeaders, "IH"},
	{(*alsdata.ResponseFlags).GetDownstreamProtocolError, "DPE"},
	{(*alsdata.ResponseFlags).GetUpstreamMaxStreamDurationReached, "UMSDR"},
	{(*alsdata.ResponseFlags).GetResponseFromCacheFilter, "RFCF"},
	{(*alsdata.ResponseFlags).GetNoFilterConfigFound, "NFCF"},
	{(*alsdata.ResponseFlags).GetDurationTimeout, "DT"},
	{(*alsdata.ResponseFlags).GetUpstreamProtocolError, "UPE"},
	{(*alsdata.ResponseFlags).GetNoClusterFound, "NC"},
	{(*alsdata.ResponseFlags).GetOverloadManager, "OM"},
	{(*alsdata.ResponseFlags).GetDnsResolutionFailure, "DF"},
}

// flagsString returns the canonical RESPONSE_FLAGS short string used
// by Envoy access log substitutions. Only the common flags are
// surfaced; the schema leaves room for raw flag fields so the mapping
// can grow without a migration. A nil common or response_flags
// message yields an empty string.
func flagsString(common *alsdata.AccessLogCommon) string {
	flags := common.GetResponseFlags()
	if flags == nil {
		return ""
	}

	var parts []string

	for _, f := range responseFlagMap {
		if f.get(flags) {
			parts = append(parts, f.label)
		}
	}

	return strings.Join(parts, ",")
}

// stripPort drops any :port suffix from a Host/authority value. The
// stats CLI groups by hostname, so port noise would blow out
// cardinality.
func stripPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}

	return h
}
