package envoy

import (
	"math/bits"
	"slices"
	"strings"

	"go.jacobcolvin.com/terrarium/config"
)

func buildHTTPVirtualHosts(rules []config.ResolvedRule, cluster string) ([]virtualHost, []string, []string) {
	var (
		restricted   []config.ResolvedRule
		unrestricted []string
	)

	// Classify domains for RBAC filter generation using the original
	// domain pattern (before WildcardServerName conversion) so that
	// ** patterns produce multi-label regexes via WildcardToHostRegex.
	// Restricted domains may include suffix wildcards ("*.example.com",
	// "**.example.com") since those are allowed with L7 rules; only
	// bare wildcards ("*", "**") are rejected by validation.
	var wildcardDomains, exactDomains []string

	for _, r := range rules {
		if r.IsRestricted() {
			restricted = append(restricted, r)
		} else {
			unrestricted = append(unrestricted, WildcardServerName(r.Domain))
			// Use the original r.Domain (not the WildcardServerName-converted
			// value) so that ** patterns retain their multi-label semantics
			// through WildcardToHostRegex.
			if r.Domain != "*" && IsWildcardDomain(r.Domain) {
				wildcardDomains = append(wildcardDomains, r.Domain)
			} else if r.Domain != "*" {
				exactDomains = append(exactDomains, r.Domain)
			}
		}
	}

	// Restricted domains are exact names; include them so the RBAC
	// filter's ALLOW policy permits their traffic through.
	for _, r := range restricted {
		exactDomains = append(exactDomains, r.Domain)
	}

	var vhosts []virtualHost

	// One virtual host per restricted domain. Each HTTPRule is an
	// independent match (OR'd), not a cross-product.
	for _, r := range restricted {
		var routes []route

		for _, hr := range r.HTTPRules {
			match := routeMatch{Prefix: "/"}
			if hr.Path != "" {
				// The path value from the CiliumNetworkPolicy HTTPRule
				// becomes a safe_regex path_specifier on the Envoy
				// RouteMatch. This uses RE2::FullMatch semantics (see
				// the routeMatch doc comment), so the regex must
				// match the entire path. A path like "/v1/" only
				// matches the literal string "/v1/", not "/v1/foo".
				match = routeMatch{SafeRegex: &safeRegex{Regex: hr.Path}}
			}

			if hr.Method != "" {
				match.Headers = buildMethodHeaderMatcher([]string{hr.Method})
			}

			if hr.Host != "" {
				match.Headers = append(match.Headers, buildHostHeaderMatcher(hr.Host)...)
			}

			for _, hdr := range hr.Headers {
				match.Headers = append(match.Headers, headerMatcher{
					Name:         hdr,
					PresentMatch: boolPtr(true),
				})
			}

			// Split headerMatches into deny-semantics (no mismatch
			// action) and mismatch-action groups.
			var actionMatches []config.HeaderMatch

			for _, hm := range hr.HeaderMatches {
				switch {
				case hm.Mismatch == "":
					match.Headers = append(match.Headers, headerMatchMatcher(hm))

				case hm.Mismatch == config.MismatchDELETE && hm.Value == "":
					// The entry matches each request that holds the
					// header, and a request that mismatches has no
					// header to remove. The entry therefore changes
					// no request, as in Cilium.

				default:
					actionMatches = append(actionMatches, hm)
				}
			}

			if len(actionMatches) > 0 {
				routes = append(routes, headerMismatchRoutes(match, actionMatches, cluster)...)
			} else {
				httpRoute := route{
					Match: match,
					Route: &routeAction{
						Cluster: cluster,
						Timeout: routeTimeout1h,
					},
				}
				routes = append(routes, grpcRouteVariant(httpRoute), httpRoute)
			}
		}

		// Catch-all denies everything else.
		routes = append(routes, route{
			Match: routeMatch{Prefix: "/"},
			DirectResponse: &directResponseAction{
				Status: 403,
				Body:   &dataSource{InlineString: accessDeniedBody},
			},
		})
		vhosts = append(vhosts, virtualHost{
			Name:    "restricted_" + r.Domain,
			Domains: []string{WildcardServerName(r.Domain)},
			Routes:  routes,
		})
	}

	// All unrestricted domains share one virtual host.
	if len(unrestricted) > 0 {
		allowRoute := route{
			Match: routeMatch{Prefix: "/"},
			Route: &routeAction{
				Cluster: cluster,
				Timeout: routeTimeout1h,
			},
		}
		vhosts = append(vhosts, virtualHost{
			Name:    "allowed",
			Domains: unrestricted,
			Routes:  []route{grpcRouteVariant(allowRoute), allowRoute},
		})
	}

	return vhosts, wildcardDomains, exactDomains
}

// grpcRouteVariant creates a gRPC-specific copy of a forwarding route.
// The copy adds GrpcRouteMatchOptions to the match (restricting it to
// gRPC requests) and MaxStreamDuration.GrpcTimeoutHeaderMax to the
// action (honoring the grpc-timeout request header). Cilium creates
// these dedicated gRPC routes before each regular route so that gRPC
// streaming RPCs get proper timeout handling.
func grpcRouteVariant(r route) route {
	grpcMatch := r.Match
	grpcMatch.Grpc = &grpcRouteMatchOptions{}

	return route{
		Match: grpcMatch,
		Route: &routeAction{
			MaxStreamDuration: &maxStreamDuration{GrpcTimeoutHeaderMax: "0s"},
			Cluster:           r.Route.Cluster,
			Timeout:           r.Route.Timeout,
		},
		RequestHeadersToAdd:    r.RequestHeadersToAdd,
		RequestHeadersToRemove: r.RequestHeadersToRemove,
		Metadata:               r.Metadata,
	}
}

// buildMethodHeaderMatcher builds an Envoy header matcher that
// restricts the :method pseudo-header to the given HTTP methods using
// a safe_regex StringMatcher.
//
// The generated regex uses explicit ^ and $ anchors (e.g. "^GET$" or
// "^(GET|POST)$"). These anchors are technically redundant: Envoy's
// StringMatcher with safe_regex uses re2::RE2::FullMatch, which
// inherently matches the entire input string without requiring
// anchors. See Envoy source/common/common/matchers.cc
// (CompiledGoogleReMatcher::match calls RE2::FullMatch). A regex of
// just "GET" under FullMatch semantics would NOT match "GETTER" or
// "GE" -- the entire string must match.
//
// Cilium passes method regexes to Envoy without anchors (e.g. just
// "GET" not "^GET$"), relying on the FullMatch semantics described
// above. Both approaches produce identical behavior: "GE" does NOT
// match "GET" in either system.
//
// We keep the anchors because they are harmless (RE2 optimizes them
// away under FullMatch) and they make the full-match intent explicit
// when reading the generated Envoy config. This was audited and
// confirmed to produce identical matching behavior to Cilium's
// unanchored method regexes.
func buildMethodHeaderMatcher(methods []string) []headerMatcher {
	if len(methods) == 0 {
		return nil
	}

	hm := headerMatcher{Name: ":method"}
	if len(methods) == 1 {
		hm.StringMatch = &stringMatch{SafeRegex: &safeRegex{Regex: "^" + methods[0] + "$"}}
	} else {
		regex := "^(" + strings.Join(methods, "|") + ")$"
		hm.StringMatch = &stringMatch{SafeRegex: &safeRegex{Regex: regex}}
	}

	return []headerMatcher{hm}
}

// buildHostHeaderMatcher creates an Envoy header matcher for the
// :authority pseudo-header using the given host regex. Envoy
// normalizes HTTP/1.1 Host into :authority for route matching. The
// regex is anchored with ^ and $ so it uses RE2::FullMatch semantics,
// matching Cilium's extended POSIX regex behavior.
//
// An optional port suffix (:\d+) is allowed after the host pattern
// because HTTP/1.1 clients may include the port in the Host header
// (e.g. "api.example.com:8443"), and Envoy preserves it in
// :authority. Cilium's Go extension strips the port before matching,
// but raw Envoy route matchers see the full value.
//
// Leading ^ and trailing $ anchors in the user-provided pattern are
// stripped before wrapping, since Terrarium adds its own anchors.
// Without this, a user-provided trailing $ would land before the port
// suffix and prevent it from matching.
func buildHostHeaderMatcher(host string) []headerMatcher {
	if host == "" {
		return nil
	}

	host = strings.TrimLeft(host, "^")
	host = strings.TrimRight(host, "$")

	return []headerMatcher{{
		Name:        authorityHeader,
		StringMatch: &stringMatch{SafeRegex: &safeRegex{Regex: "^" + host + `(:[0-9]+)?$`}},
	}}
}

// headerMismatchRoutes builds the routes of an HTTP rule whose
// headerMatches carry a mismatch action. The base match holds every
// other condition of the rule, and each route forwards to cluster.
//
// Envoy takes the first route that matches a request, and it applies
// the header changes of that route to the request. The first route
// matches when every header of matches holds its value, and it changes
// nothing. Every later route applies each REPLACE action of matches,
// because a REPLACE action leaves a header that holds its value as it
// is. The header of an entry without a value counts as a header that
// holds its value when the request has the header, see
// [headerMatchMatcher].
//
// An ADD action appends a value, a DELETE action removes the header
// whatever its value, and a LOG action logs the request. A route must
// therefore not apply one of these actions to a header that holds its
// value. The later routes cover each combination of the ADD, DELETE,
// and LOG headers that hold their value. Such a route matches on those
// headers, and it applies the action of each other ADD, DELETE, and
// LOG header. The routes that match on more of these headers come
// first. A request that a route takes therefore mismatches on each
// ADD, DELETE, and LOG header that the route does not match on. A
// route applies its LOG actions through its metadata, see
// [mismatchLogMetadata].
//
// The number of these routes doubles with each ADD, DELETE, and LOG
// header. [config.Config.Validate] limits these headers of one HTTP
// rule for that reason.
func headerMismatchRoutes(match routeMatch, matches []config.HeaderMatch, cluster string) []route {
	forward := func(matched, apply []config.HeaderMatch) []route {
		m := match
		m.Headers = append(append([]headerMatcher{}, match.Headers...), mismatchHeaderMatchers(matched)...)

		r := route{
			Match:                  m,
			RequestHeadersToAdd:    mismatchHeadersToAdd(apply),
			RequestHeadersToRemove: mismatchHeadersToRemove(apply),
			Metadata:               mismatchLogMetadata(apply),
			Route: &routeAction{
				Cluster: cluster,
				Timeout: routeTimeout1h,
			},
		}

		return []route{grpcRouteVariant(r), r}
	}

	routes := forward(matches, nil)

	// Combined reports whether hm takes one bit of each combination.
	combined := func(hm config.HeaderMatch) bool {
		switch hm.Mismatch {
		case config.MismatchADD, config.MismatchDELETE, config.MismatchLOG:
			return true
		default:
			return false
		}
	}

	count := 0

	for _, hm := range matches {
		if combined(hm) {
			count++
		}
	}

	// Each bit of a combination stands for one ADD, DELETE, or LOG
	// header, in the order of matches. A set bit means that the header
	// holds its value.
	combinations := make([]uint, 1<<count)
	for i := range combinations {
		combinations[i] = uint(i)
	}

	slices.SortStableFunc(combinations, func(a, b uint) int {
		return bits.OnesCount(b) - bits.OnesCount(a)
	})

	for _, combination := range combinations {
		var matched, apply []config.HeaderMatch

		bit := 0

		for _, hm := range matches {
			if !combined(hm) {
				apply = append(apply, hm)

				continue
			}

			if combination&(1<<bit) != 0 {
				matched = append(matched, hm)
			} else {
				apply = append(apply, hm)
			}

			bit++
		}

		// Without an action to apply, every header of matches holds
		// its value, and the first route takes those requests.
		if len(apply) == 0 {
			continue
		}

		routes = append(routes, forward(matched, apply)...)
	}

	return routes
}

// headerMatchMatcher builds the Envoy header matcher for hm. The
// matcher passes when the header holds the value of hm. When hm has no
// value, the matcher passes when the request has the header, with any
// value, as in Cilium.
//
// Envoy rejects a string matcher without a pattern, so an entry
// without a value cannot use an exact match on the empty string.
func headerMatchMatcher(hm config.HeaderMatch) headerMatcher {
	if hm.Value == "" {
		return headerMatcher{Name: hm.Name, PresentMatch: boolPtr(true)}
	}

	return headerMatcher{
		Name:        hm.Name,
		StringMatch: &stringMatch{Exact: hm.Value},
	}
}

// mismatchHeaderMatchers builds one Envoy header matcher for each
// entry of matches, see [headerMatchMatcher].
func mismatchHeaderMatchers(matches []config.HeaderMatch) []headerMatcher {
	var result []headerMatcher

	for _, hm := range matches {
		result = append(result, headerMatchMatcher(hm))
	}

	return result
}

// mismatchHeadersToAdd builds request_headers_to_add entries for
// headerMatches with ADD or REPLACE mismatch actions. An ADD entry
// adds its value as one more value of the header and keeps the values
// that the request already holds, as Cilium does. A REPLACE entry
// removes those values.
//
// An ADD or REPLACE entry without a value mismatches only on a request
// that lacks the header. Cilium gives that request the header with an
// empty value, so the entry adds the empty header only when the header
// is absent. A route can apply a REPLACE entry to a request that has
// the header, and that header keeps its values.
func mismatchHeadersToAdd(matches []config.HeaderMatch) []headerValueOption {
	var result []headerValueOption

	for _, hm := range matches {
		if hm.Value == "" && (hm.Mismatch == config.MismatchADD || hm.Mismatch == config.MismatchREPLACE) {
			result = append(result, headerValueOption{
				Header:         headerValue{Key: hm.Name},
				AppendAction:   "ADD_IF_ABSENT",
				KeepEmptyValue: true,
			})

			continue
		}

		switch hm.Mismatch {
		case config.MismatchADD:
			result = append(result, headerValueOption{
				Header:       headerValue{Key: hm.Name, Value: hm.Value},
				AppendAction: "APPEND_IF_EXISTS_OR_ADD",
			})

		case config.MismatchREPLACE:
			result = append(result, headerValueOption{
				Header:       headerValue{Key: hm.Name, Value: hm.Value},
				AppendAction: "OVERWRITE_IF_EXISTS_OR_ADD",
			})

		case config.MismatchLOG, config.MismatchDELETE:
			// LOG and DELETE do not add headers.
		}
	}

	return result
}

// mismatchHeadersToRemove builds request_headers_to_remove entries for
// headerMatches with DELETE mismatch actions.
func mismatchHeadersToRemove(matches []config.HeaderMatch) []string {
	var result []string

	for _, hm := range matches {
		if hm.Mismatch == config.MismatchDELETE {
			result = append(result, hm.Name)
		}
	}

	return result
}

// mismatchLogMetadata builds the metadata of a route that applies
// matches. The metadata holds the names of the headers with a LOG
// action. The names are the value of [mismatchLogHeadersKey] in the
// namespace [mismatchMetadataNamespace]. The result is nil when no
// entry of matches has a LOG action.
//
// The Envoy router filter does not accept a config for one route, so a
// route cannot carry an access logger of its own. The metadata marks
// the route for the logger of [withMismatchAccessLog] instead.
func mismatchLogMetadata(matches []config.HeaderMatch) *metadata {
	var logHeaders []string

	for _, hm := range matches {
		if hm.Mismatch == config.MismatchLOG {
			logHeaders = append(logHeaders, hm.Name)
		}
	}

	if len(logHeaders) == 0 {
		return nil
	}

	return &metadata{
		FilterMetadata: map[string]map[string]string{
			mismatchMetadataNamespace: {
				mismatchLogHeadersKey: strings.Join(logHeaders, ","),
			},
		},
	}
}

// withMismatchAccessLog returns the access loggers of an HTTP
// connection manager that serves vhosts. The result is accessLog, plus
// one more logger when a route of vhosts has the metadata of
// [mismatchLogMetadata].
//
// That logger writes one HEADER_MISMATCH line to the stderr of Envoy
// for each request that such a route takes. The line names the headers
// of the metadata, the method, the authority, the path, and the
// response code of the request. The authority is the one that the
// upstream receives. The logger reads the header names from the
// metadata, so that a "%" in a name is not part of the format.
//
// The filter of the logger is a Common Expression Language (CEL)
// expression, because the other access log filters of Envoy cannot
// read the metadata of a route.
func withMismatchAccessLog(accessLog []AccessLog, vhosts []virtualHost) []AccessLog {
	logs := slices.ContainsFunc(vhosts, func(vh virtualHost) bool {
		return slices.ContainsFunc(vh.Routes, func(r route) bool {
			if r.Metadata == nil {
				return false
			}

			_, marked := r.Metadata.FilterMetadata[mismatchMetadataNamespace]

			return marked
		})
	})
	if !logs {
		return accessLog
	}

	format := "[%START_TIME%] HEADER_MISMATCH" +
		" headers=%METADATA(ROUTE:" + mismatchMetadataNamespace + ":" + mismatchLogHeadersKey + ")%" +
		" %REQ(:METHOD)% %REQ(:AUTHORITY)%%REQ(:PATH)% %RESPONSE_CODE%\n"

	return append(slices.Clone(accessLog), AccessLog{
		Name: "envoy.access_loggers.stderr",
		Filter: &accessLogFilter{
			ExtensionFilter: &typedExtensionConfig{
				Name: "envoy.access_loggers.extension_filters.cel",
				TypedConfig: celAccessLogFilterConfig{
					AtType:     "type.googleapis.com/envoy.extensions.access_loggers.filters.cel.v3.ExpressionFilter",
					Expression: "'" + mismatchMetadataNamespace + "' in xds.route_metadata.filter_metadata",
				},
			},
		},
		TypedConfig: stderrAccessLogConfig{
			AtType: "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StderrAccessLog",
			LogFormat: &substitutionFormatString{
				TextFormatSource: &dataSource{
					InlineString: format,
				},
			},
		},
	})
}
