package envoy

import "go.jacobcolvin.com/terrarium/config"

// accessLogFormat uses logfmt key=value pairs for structured, grep-friendly
// access logs. Values that may contain spaces are quoted. The format includes
// %REQUESTED_SERVER_NAME% so that the TLS SNI is visible for TCP proxy and
// TLS passthrough connections, where standard HTTP fields are empty.
const accessLogFormat = `time=%START_TIME% method=%REQ(:METHOD)% ` +
	`path="%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%" protocol=%PROTOCOL% ` +
	`status=%RESPONSE_CODE% flags=%RESPONSE_FLAGS% ` +
	`rx_bytes=%BYTES_RECEIVED% tx_bytes=%BYTES_SENT% duration=%DURATION% ` +
	`upstream_time=%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)% ` +
	`forwarded_for="%REQ(X-FORWARDED-FOR)%" ` +
	`user_agent="%REQ(USER-AGENT)%" ` +
	`request_id="%REQ(X-REQUEST-ID)%" ` +
	`authority="%REQ(:AUTHORITY)%" ` +
	`upstream=%UPSTREAM_HOST% sni="%REQUESTED_SERVER_NAME%"` + "\n"

// BuildAccessLog returns Envoy file access log config when logging is
// enabled, or nil when disabled. The path specifies the output file
// for access log entries.
func BuildAccessLog(logging bool, path string) []AccessLog {
	if !logging {
		return nil
	}

	return []AccessLog{{
		Name: "envoy.access_loggers.file",
		TypedConfig: fileAccessLogConfig{
			AtType: "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog",
			Path:   path,
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
