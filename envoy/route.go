package envoy

import (
	"fmt"
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
					match = withHeaderMatch(match, hm)

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
// [withHeaderMatch].
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
//
// Envoy does not load a route that adds or removes the Host header or
// a header whose name starts with ":". [config.Config.Validate] rejects
// each entry that asks for such a change, so matches must not hold one.
func headerMismatchRoutes(match routeMatch, matches []config.HeaderMatch, cluster string) []route {
	forward := func(matched, apply []config.HeaderMatch) []route {
		m := match
		for _, hm := range matched {
			m = withHeaderMatch(m, hm)
		}

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

// withHeaderMatch returns a copy of match that also requires the
// header of hm to hold the value of hm. A header that the request
// repeats holds the values of all its fields, joined with commas, as
// in Cilium. The request "X-A: 1" and "X-A: 2" therefore holds the
// value "1,2", and it does not hold the value "1".
//
// In Envoy 1.39 and later, an Envoy header matcher compares each field
// of a repeated header on its own. The matcher passes when one field
// holds the value. The copy therefore compares the value of hm with the
// filter state object that the filter of [headerValueFilter] stores
// for the header. That comparison gives the same result in Envoy 1.38
// and earlier, where a header matcher compares the joined values. A
// request that lacks the header has no such object, and the copy does
// not match it.
//
// When hm has no value, the copy matches each request that has the
// header, with any value, as in Cilium. Envoy rejects a string matcher
// without a pattern, so an entry without a value cannot use an exact
// match on the empty string.
//
// The copy does not share a slice with match, so the caller can derive
// more than one route match from match.
func withHeaderMatch(match routeMatch, hm config.HeaderMatch) routeMatch {
	if hm.Value == "" {
		match.Headers = append(slices.Clone(match.Headers), headerMatcher{
			Name:         hm.Name,
			PresentMatch: boolPtr(true),
		})

		return match
	}

	match.FilterState = append(slices.Clone(match.FilterState), filterStateMatcher{
		Key:         headerValueStateKey(hm.Name),
		StringMatch: stringMatch{Exact: hm.Value},
	})

	return match
}

// headerValueStateKey returns the filter state key of the object that
// holds the value of the request header name. Header names do not
// depend on case, so the key holds name in lowercase.
func headerValueStateKey(name string) string {
	return headerValueStatePrefix + strings.ToLower(name)
}

// headerValueFilter builds the HTTP filter that stores the header
// values that the routes of rules compare, see [withHeaderMatch]. The
// result is false when no headerMatches entry of rules has a value,
// because the routes then compare no header value.
//
// For each header of such an entry, the filter stores one string
// object in the filter state of each request that has the header. The
// object holds the values of all fields of the header, joined with
// commas. Its key is the result of [headerValueStateKey]. The filter
// stores no object for a header that the request lacks, and none for
// a header whose joined value is empty.
//
// Envoy selects the route of a request before the HTTP filters run,
// when the filter state does not hold the objects yet. The filter
// therefore clears that route after it stored the objects, and Envoy
// selects the route again for the next HTTP filter that reads it. The
// filter must come before every HTTP filter that reads the route.
//
// Envoy answers some requests before the HTTP filters run, such as a
// request for an upgrade that the connection manager does not allow.
// Such a request keeps the route that Envoy selected without the
// objects. The filter therefore also stores one object under
// [headerValuesStoredStateKey] in each request, which marks the
// requests whose route Envoy selected with the objects.
func headerValueFilter(rules []config.ResolvedRule) (filter, bool) {
	var values []filterStateValue

	seen := make(map[string]bool)

	for _, r := range rules {
		if !r.IsRestricted() {
			continue
		}

		for _, hr := range r.HTTPRules {
			for _, hm := range hr.HeaderMatches {
				key := headerValueStateKey(hm.Name)
				if hm.Value == "" || seen[key] {
					continue
				}

				seen[key] = true

				// The Common Expression Language (CEL) reads a
				// repeated header as the joined values of its fields.
				// The REQ operator reads the first field only.
				expr := "request.headers[" + celStringLiteral(strings.ToLower(hm.Name)) + "]"

				values = append(values, filterStateValue{
					ObjectKey:  key,
					FactoryKey: stringFilterStateFactory,
					FormatString: substitutionFormatString{
						TextFormatSource: &dataSource{InlineString: "%CEL(" + expr + ")%"},
						// The expression has no result for a request
						// that lacks the header, and Envoy formats a
						// missing result as "-" by default.
						OmitEmptyValues: true,
					},
					SkipIfEmpty: true,
				})
			}
		}
	}

	if len(values) == 0 {
		return filter{}, false
	}

	values = append(values, filterStateValue{
		ObjectKey:  headerValuesStoredStateKey,
		FactoryKey: stringFilterStateFactory,
		FormatString: substitutionFormatString{
			TextFormatSource: &dataSource{InlineString: "true"},
		},
	})

	return filter{
		Name: httpSetFilterStateFilterName,
		TypedConfig: setFilterStateConfig{
			AtType:           httpSetFilterStateTypeURL,
			OnRequestHeaders: values,
			ClearRouteCache:  true,
		},
	}, true
}

// celStringLiteral returns the string literal of the Common Expression
// Language (CEL) that holds s. The literal holds each character other
// than an ASCII letter, an ASCII digit, "-", and "_" as an escape
// sequence. The caller can therefore put the literal into an Envoy
// format string, where "%" and ")" end an operator.
func celStringLiteral(s string) string {
	var b strings.Builder

	b.WriteByte('\'')

	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}

	b.WriteByte('\'')

	return b.String()
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
//
// The stored argument reports whether the connection manager holds the
// filter of [headerValueFilter]. The logger then writes no line for a
// request that this filter did not handle. Envoy selected the route of
// such a request without the header values, so the route does not
// tell whether a header of the request mismatches.
func withMismatchAccessLog(accessLog []AccessLog, vhosts []virtualHost, stored bool) []AccessLog {
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

	expression := "'" + mismatchMetadataNamespace + "' in xds.route_metadata.filter_metadata"
	if stored {
		expression += " && '" + headerValuesStoredStateKey + "' in filter_state"
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
					Expression: expression,
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
