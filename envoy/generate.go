package envoy

import "go.jacobcolvin.com/terrarium/config"

// accessLogFormat extends Envoy's default access log format with
// %REQUESTED_SERVER_NAME% so that the TLS SNI is visible for TCP
// proxy and TLS passthrough connections, where standard HTTP fields
// (method, path, authority) are empty.
const accessLogFormat = `[%START_TIME%] "%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%" ` +
	`%RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION% ` +
	`%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)% "%REQ(X-FORWARDED-FOR)%" "%REQ(USER-AGENT)%" ` +
	`"%REQ(X-REQUEST-ID)%" "%REQ(:AUTHORITY)%" "%UPSTREAM_HOST%" "%REQUESTED_SERVER_NAME%"` + "\n"

// BuildAccessLog returns Envoy stderr access log config when logging is
// enabled, or nil when disabled.
func BuildAccessLog(logging bool) []AccessLog {
	if !logging {
		return nil
	}

	return []AccessLog{{
		Name: "envoy.access_loggers.stderr",
		TypedConfig: stderrAccessLogConfig{
			AtType: "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StderrAccessLog",
			LogFormat: &substitutionFormatString{
				TextFormatSource: dataSource{
					InlineString: accessLogFormat,
				},
			},
		},
	}}
}

// StripL7Restrictions converts restricted rules to passthrough by
// clearing their HTTPRules. This implements Cilium's OR semantics
// between open port rules and FQDN+L7 rules on the same port: the
// open port allows ALL traffic, overriding any L7 restrictions.
func StripL7Restrictions(rules []config.ResolvedRule) []config.ResolvedRule {
	result := make([]config.ResolvedRule, len(rules))
	for i, r := range rules {
		result[i] = config.ResolvedRule{Domain: r.Domain}
	}

	return result
}
