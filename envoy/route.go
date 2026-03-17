package envoy

import (
	"fmt"
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
				if hm.Mismatch == "" {
					match.Headers = append(match.Headers, headerMatcher{
						Name:        hm.Name,
						StringMatch: &stringMatch{Exact: hm.Value},
					})
				} else {
					actionMatches = append(actionMatches, hm)
				}
			}

			if len(actionMatches) > 0 {
				// Route 1: all action headers match -> forward
				// normally (no transforms needed).
				fullMatch := match
				fullMatch.Headers = append(
					append([]headerMatcher{}, match.Headers...),
					mismatchHeaderMatchers(actionMatches)...,
				)

				matchRoute := route{
					Match: fullMatch,
					Route: &routeAction{
						Cluster:         cluster,
						AutoHostRewrite: true,
						Timeout:         "3600s",
					},
				}
				routes = append(routes, grpcRouteVariant(matchRoute), matchRoute)

				// Route 2: base match only (some action header
				// doesn't match) -> forward with transforms.
				mismatchRoute := route{
					Match:                  match,
					RequestHeadersToAdd:    mismatchHeadersToAdd(actionMatches),
					RequestHeadersToRemove: mismatchHeadersToRemove(actionMatches),
					Route: &routeAction{
						Cluster:         cluster,
						AutoHostRewrite: true,
						Timeout:         "3600s",
					},
				}

				if logConfig := mismatchLogConfig(actionMatches); logConfig != nil {
					mismatchRoute.TypedPerFilterConfig = logConfig
				}

				routes = append(routes, grpcRouteVariant(mismatchRoute), mismatchRoute)
			} else {
				httpRoute := route{
					Match: match,
					Route: &routeAction{
						Cluster:         cluster,
						AutoHostRewrite: true,
						Timeout:         "3600s",
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
				Body:   &dataSource{InlineString: "Access denied"},
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
				Cluster:         cluster,
				AutoHostRewrite: true,
				Timeout:         "3600s",
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
			AutoHostRewrite:   r.Route.AutoHostRewrite,
		},
		RequestHeadersToAdd:    r.RequestHeadersToAdd,
		RequestHeadersToRemove: r.RequestHeadersToRemove,
		TypedPerFilterConfig:   r.TypedPerFilterConfig,
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
func buildHostHeaderMatcher(host string) []headerMatcher {
	if host == "" {
		return nil
	}

	return []headerMatcher{{
		Name:        ":authority",
		StringMatch: &stringMatch{SafeRegex: &safeRegex{Regex: "^" + host + `(:[0-9]+)?$`}},
	}}
}

// mismatchHeaderMatchers builds Envoy header matchers for the "full
// match" route where all mismatch-action headers match their expected
// values. This route fires first; when all headers match, no
// transforms are needed.
func mismatchHeaderMatchers(matches []config.HeaderMatch) []headerMatcher {
	var result []headerMatcher
	for _, hm := range matches {
		result = append(result, headerMatcher{
			Name:        hm.Name,
			StringMatch: &stringMatch{Exact: hm.Value},
		})
	}

	return result
}

// mismatchHeadersToAdd builds request_headers_to_add entries for
// headerMatches with ADD or REPLACE mismatch actions.
func mismatchHeadersToAdd(matches []config.HeaderMatch) []headerValueOption {
	var result []headerValueOption
	for _, hm := range matches {
		switch hm.Mismatch {
		case config.MismatchADD:
			result = append(result, headerValueOption{
				Header:       headerValue{Key: hm.Name, Value: hm.Value},
				AppendAction: "ADD_IF_ABSENT",
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

// mismatchLogConfig builds a typed_per_filter_config map for the
// mismatch route when any headerMatch has a LOG action. The config
// overrides the HTTP router filter to add upstream access logging
// with a format that identifies the mismatched headers.
func mismatchLogConfig(matches []config.HeaderMatch) map[string]any {
	var logHeaders []string
	for _, hm := range matches {
		if hm.Mismatch == config.MismatchLOG {
			logHeaders = append(logHeaders, hm.Name)
		}
	}

	if len(logHeaders) == 0 {
		return nil
	}

	format := fmt.Sprintf(
		"[%%START_TIME%%] HEADER_MISMATCH headers=%s %%REQ(:METHOD)%% %%REQ(:AUTHORITY)%%%%REQ(:PATH)%% %%RESPONSE_CODE%%\n",
		strings.Join(logHeaders, ","),
	)

	return map[string]any{
		"envoy.filters.http.router": routerFilterConfig{
			AtType: "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
			UpstreamLog: []AccessLog{{
				Name: "envoy.access_loggers.stderr",
				TypedConfig: stderrAccessLogConfig{
					AtType: "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StderrAccessLog",
					LogFormat: &substitutionFormatString{
						TextFormat: format,
					},
				},
			}},
		},
	}
}
