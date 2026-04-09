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

// accessLogJSONFields provides the same fields as [accessLogFormat] in
// a structured JSON format for Envoy's json_format access log output.
var accessLogJSONFields = map[string]string{
	"time":          "%START_TIME%",
	"method":        "%REQ(:METHOD)%",
	"path":          "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%",
	"protocol":      "%PROTOCOL%",
	"status":        "%RESPONSE_CODE%",
	"flags":         "%RESPONSE_FLAGS%",
	"rx_bytes":      "%BYTES_RECEIVED%",
	"tx_bytes":      "%BYTES_SENT%",
	"duration":      "%DURATION%",
	"upstream_time": "%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%",
	"forwarded_for": "%REQ(X-FORWARDED-FOR)%",
	"user_agent":    "%REQ(USER-AGENT)%",
	"request_id":    "%REQ(X-REQUEST-ID)%",
	"authority":     "%REQ(:AUTHORITY)%",
	"upstream":      "%UPSTREAM_HOST%",
	"sni":           "%REQUESTED_SERVER_NAME%",
}

// BuildAccessLog returns Envoy file access log config when enabled,
// or nil when disabled. Format controls the output structure: "logfmt"
// uses key=value pairs, "json" uses Envoy's json_format. The path
// specifies the output file for access log entries.
func BuildAccessLog(enabled bool, format, path string) []AccessLog {
	if !enabled {
		return nil
	}

	logFormat := &substitutionFormatString{}

	switch format {
	case "json":
		logFormat.JsonFormat = accessLogJSONFields
	default:
		logFormat.TextFormatSource = &dataSource{
			InlineString: accessLogFormat,
		}
	}

	return []AccessLog{{
		Name: "envoy.access_loggers.file",
		TypedConfig: fileAccessLogConfig{
			AtType:    "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog",
			Path:      path,
			LogFormat: logFormat,
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
