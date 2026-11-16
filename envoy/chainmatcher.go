package envoy

import (
	"cmp"
	"math"
	"slices"
	"strings"
)

const (
	// The transport protocol that the TLS inspector listener filter
	// sets on a connection that starts with a TLS ClientHello.
	tlsTransportProtocol = "tls"

	transportProtocolInputName    = "envoy.matching.inputs.transport_protocol"
	transportProtocolInputTypeURL = "type.googleapis.com/envoy.extensions.matching.common_inputs.network.v3.TransportProtocolInput"

	serverNameInputName    = "envoy.matching.inputs.server_name"
	serverNameInputTypeURL = "type.googleapis.com/envoy.extensions.matching.common_inputs.network.v3.ServerNameInput"

	stringValueTypeURL = "type.googleapis.com/google.protobuf.StringValue"
)

// serverNameRoute names the filter chain for the TLS connections whose
// SNI matches one domain of the policy.
type serverNameRoute struct {
	// The domain field is an exact server name or a wildcard pattern
	// such as "*.example.com" or "**.example.com".
	domain string

	// The chain field is the name of the filter chain.
	chain string

	// The mitm field reports whether the chain terminates TLS.
	mitm bool
}

// specificity orders the routes of a matcher. An exact server name has
// a higher value than every wildcard pattern. A wildcard pattern has
// the number of labels after its last wildcard label, so the value of
// "*.api.example.com" is higher than the value of "**.example.com".
func (r serverNameRoute) specificity() int {
	if !IsWildcardDomain(r.domain) {
		return math.MaxInt
	}

	return strings.Count(WildcardServerName(r.domain), ".")
}

// buildTLSFilterChainMatcher builds the filter chain matcher of a TLS
// listener. The matcher selects the chain of each TLS connection by
// the SNI of the connection, before a network filter of a chain runs.
//
// The matcher checks the routes in this order and selects the chain of
// the first route whose domain matches the SNI:
//
//  1. Each route with an exact server name.
//  2. Each route with a wildcard pattern. A pattern with more labels
//     after its last wildcard label comes first.
//
// When two routes are equal in this order, a route to a passthrough
// chain comes before a route to a MITM chain. For example, the rules
// of "*.example.com" with L7 restrictions and of "**.example.com"
// without them both match "a.example.com". The matcher then selects
// the passthrough chain, so the connection has no L7 restriction.
//
// An exact server name matches only an SNI that equals it. A wildcard
// pattern matches an SNI with the regular expression of
// [WildcardToSNIRegex]. So "*.example.com" matches one label before
// "example.com", and "**.example.com" matches one or more labels. This
// rule is the meaning of matchPattern in a CiliumNetworkPolicy.
//
// A TLS connection whose SNI matches no route, or that has no SNI,
// uses the chain openChain. When openChain is empty, the matcher gives
// that connection no chain. The matcher also gives no chain to a
// connection that is not TLS. Envoy handles a connection without a
// chain in the default filter chain of the listener, which resolves no
// name and connects to no upstream.
//
// It returns nil when routes is empty and openChain is empty. Every
// connection of the listener then uses the default filter chain.
func buildTLSFilterChainMatcher(routes []serverNameRoute, openChain string) *matcher {
	routes = slices.Clone(routes)
	slices.SortStableFunc(routes, func(a, b serverNameRoute) int {
		return cmp.Or(
			cmp.Compare(b.specificity(), a.specificity()),
			cmp.Compare(boolRank(a.mitm), boolRank(b.mitm)),
		)
	})

	var fallback *onMatch

	if openChain != "" {
		fallback = &onMatch{Action: filterChainAction(openChain)}
	}

	onTLS := fallback

	if len(routes) > 0 {
		entries := make([]fieldMatcher, 0, len(routes))
		seen := make(map[serverNameRoute]bool, len(routes))

		for _, r := range routes {
			if seen[r] {
				continue
			}

			seen[r] = true

			entries = append(entries, fieldMatcher{
				Predicate: matcherPredicate{SinglePredicate: singlePredicate{
					Input: typedExtensionConfig{
						Name:        serverNameInputName,
						TypedConfig: typeOnly{AtType: serverNameInputTypeURL},
					},
					ValueMatch: serverNameMatch(r.domain),
				}},
				OnMatch: onMatch{Action: filterChainAction(r.chain)},
			})
		}

		onTLS = &onMatch{Matcher: &matcher{
			MatcherList: &matcherList{Matchers: entries},
			OnNoMatch:   fallback,
		}}
	}

	if onTLS == nil {
		return nil
	}

	return &matcher{
		MatcherTree: &matcherTree{
			Input: typedExtensionConfig{
				Name:        transportProtocolInputName,
				TypedConfig: typeOnly{AtType: transportProtocolInputTypeURL},
			},
			ExactMatchMap: matchMap{Map: map[string]onMatch{tlsTransportProtocol: *onTLS}},
		},
	}
}

// serverNameMatch returns the string matcher for the SNI of a
// connection and domain, which is an exact server name or a wildcard
// pattern.
func serverNameMatch(domain string) xdsStringMatch {
	if IsWildcardDomain(domain) {
		return xdsStringMatch{SafeRegex: &xdsSafeRegex{Regex: WildcardToSNIRegex(domain)}}
	}

	return xdsStringMatch{Exact: domain}
}

// filterChainAction returns the matcher action that selects the filter
// chain with the name name.
func filterChainAction(name string) *typedExtensionConfig {
	return &typedExtensionConfig{
		Name:        name,
		TypedConfig: stringValue{AtType: stringValueTypeURL, Value: name},
	}
}

// boolRank returns 0 for false and 1 for true.
func boolRank(b bool) int {
	if b {
		return 1
	}

	return 0
}
