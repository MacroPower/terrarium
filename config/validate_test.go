package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg *config.Config
		err error
	}{
		"valid with forwards": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
				TCPForwards: []config.TCPForward{{Port: 22, Host: "github.com"}},
			},
		},
		"valid no forwards": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
		"valid FQDN with L7 paths": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Path: "/v1/"},
							{Path: "/v2/"},
						}},
					}},
				}),
			},
		},
		"FQDN selector empty": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{}},
				}),
			},
			err: config.ErrFQDNSelectorEmpty,
		},
		"FQDN without toPorts rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				}),
			},
			err: config.ErrFQDNRequiresPorts,
		},
		"FQDN with empty Ports list rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: config.ErrFQDNRequiresPorts,
		},
		"FQDN with wildcard port 0 rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "0"}},
					}},
				}),
			},
			err: config.ErrFQDNWildcardPort,
		},
		"empty egress rule is valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{}),
			},
		},
		"nil egress is valid": {
			cfg: &config.Config{},
		},
		"empty egress slice is valid": {
			cfg: &config.Config{
				Egress: egressRules(),
			},
		},
		"invalid path regex": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Path: "[unclosed"},
						}},
					}},
				}),
			},
			err: config.ErrPathInvalidRegex,
		},
		"valid regex paths": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Path: "/v1/.*"},
							{Path: "/api/v[12]/.*"},
						}},
					}},
				}),
			},
		},
		"duplicate forward port": {
			cfg: &config.Config{
				TCPForwards: []config.TCPForward{
					{Port: 22, Host: "github.com"},
					{Port: 22, Host: "gitlab.com"},
				},
			},
			err: config.ErrDuplicateTCPForwardPort,
		},
		"forward port conflicts with resolved port": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080"}}}},
				}),
				TCPForwards: []config.TCPForward{{Port: 8080, Host: "example.com"}},
			},
			err: config.ErrTCPForwardPortConflict,
		},
		"invalid zero port": {
			cfg: &config.Config{
				TCPForwards: []config.TCPForward{{Port: 0, Host: "example.com"}},
			},
			err: config.ErrInvalidTCPForward,
		},
		"invalid negative port": {
			cfg: &config.Config{
				TCPForwards: []config.TCPForward{{Port: -1, Host: "example.com"}},
			},
			err: config.ErrInvalidTCPForward,
		},
		"invalid empty host": {
			cfg: &config.Config{
				TCPForwards: []config.TCPForward{{Port: 22, Host: ""}},
			},
			err: config.ErrInvalidTCPForward,
		},
		"tcp forwards with blocked egress": {
			cfg: &config.Config{
				Egress:      egressRules(config.EgressRule{}),
				TCPForwards: []config.TCPForward{{Port: 22, Host: "github.com"}},
			},
			err: config.ErrTCPForwardRequiresEgress,
		},
		"port exceeds proxy range": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "50536"}}}},
				}),
			},
			err: config.ErrPortExceedsProxyRange,
		},
		"tcp forward port exceeds proxy range": {
			cfg: &config.Config{
				TCPForwards: []config.TCPForward{{Port: 50536, Host: "example.com"}},
			},
			err: config.ErrPortExceedsProxyRange,
		},
		"valid methods": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Method: "GET"},
							{Method: "POST"},
						}},
					}},
				}),
			},
		},
		"lowercase method is valid regex": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Method: "get"},
						}},
					}},
				}),
			},
		},
		"custom method is valid regex": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Method: "FOOBAR"},
						}},
					}},
				}),
			},
		},
		"method regex pattern": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Method: "GET|POST"},
						}},
					}},
				}),
			},
		},
		"invalid method regex": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Method: "[unclosed"},
						}},
					}},
				}),
			},
			err: config.ErrMethodInvalidRegex,
		},
		"invalid empty method string": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Method: ""},
						}},
					}},
				}),
			},
			// Empty method is allowed (means "all methods").
		},
		"FQDN with toCIDR rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					ToCIDR:  []string{"10.0.0.0/8"},
				}),
			},
			err: config.ErrFQDNWithCIDR,
		},
		"toCIDR with toCIDRSet rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDR:    []string{"10.0.0.0/8"},
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
				}),
			},
			err: config.ErrCIDRAndCIDRSetMixed,
		},
		"toCIDR and toCIDRSet in separate rules valid": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{ToCIDR: []string{"10.0.0.0/8"}},
					config.EgressRule{ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}}},
				),
			},
		},
		"FQDN with toCIDR and L7 rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToCIDR:  []string{"10.0.0.0/8"},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: config.ErrFQDNWithCIDR,
		},
		"FQDN with toCIDRSet rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs:   []config.FQDNSelector{{MatchName: "example.com"}},
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: config.ErrFQDNWithCIDR,
		},
		"FQDN selector both matchName and matchPattern": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com", MatchPattern: "*.example.com"}},
				}),
			},
			err: config.ErrFQDNSelectorAmbiguous,
		},
		"deep wildcard accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "**.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
		"triple star wildcard accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "***.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
		"bare double star accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "**"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
		"mid-pattern double star accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "test.**.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
		"bare wildcard accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
		"bare wildcard with specific ports": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				}),
			},
		},
		"partial wildcard mid-label rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "api.*-staging.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			err: config.ErrFQDNPatternPartialWildcard,
		},
		"partial wildcard suffix rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "example.com.*"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			err: config.ErrFQDNPatternPartialWildcard,
		},
		"multiple wildcards rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.*.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			err: config.ErrFQDNPatternPartialWildcard,
		},
		"valid leading wildcard prefix": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
		"valid toCIDR": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDR: []string{"10.0.0.0/8"},
				}),
			},
		},
		"bare IPv4 in toCIDR accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDR: []string{"10.0.0.1"},
				}),
			},
		},
		"bare IPv6 in toCIDR accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDR: []string{"fd00::1"},
				}),
			},
		},
		"bare IPv4-mapped IPv6 in toCIDR rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDR: []string{"::ffff:10.0.0.1"},
				}),
			},
			err: config.ErrCIDRIPv4MappedIPv6,
		},
		"IPv4-mapped IPv6 CIDR in toCIDR rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDR: []string{"::ffff:10.0.0.0/104"},
				}),
			},
			err: config.ErrCIDRIPv4MappedIPv6,
		},
		"IPv4-mapped IPv6 parent in toCIDRSet rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "::ffff:10.0.0.0/104"}},
				}),
			},
			err: config.ErrCIDRIPv4MappedIPv6,
		},
		"IPv4-mapped IPv6 except entry rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{
						CIDR:   "fd00::/8",
						Except: []string{"::ffff:10.0.0.0/104"},
					}},
				}),
			},
			err: config.ErrCIDRIPv4MappedIPv6,
		},
		"cross-family except IPv4 parent IPv6 except rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{
						CIDR:   "10.0.0.0/8",
						Except: []string{"fd00::/16"},
					}},
				}),
			},
			err: config.ErrExceptAddressFamilyMismatch,
		},
		"cross-family except IPv6 parent IPv4 except rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{
						CIDR:   "fd00::/8",
						Except: []string{"10.0.0.0/16"},
					}},
				}),
			},
			err: config.ErrExceptAddressFamilyMismatch,
		},
		"invalid toCIDR": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDR: []string{"not-a-cidr"},
				}),
			},
			err: config.ErrCIDRInvalid,
		},
		"valid protocol TCP/UDP/ANY": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{
						{Port: "80", Protocol: "TCP"},
						{Port: "53", Protocol: "UDP"},
						{Port: "443", Protocol: "ANY"},
					}}},
				}),
			},
		},
		"SCTP protocol": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "80", Protocol: "SCTP"}}}},
				}),
			},
		},
		"invalid protocol": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "80", Protocol: "ICMP"}}}},
				}),
			},
			err: config.ErrProtocolInvalid,
		},
		"valid endPort": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "8000", EndPort: 9000}}}},
				}),
			},
		},
		"endPort less than port": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "9000", EndPort: 8000}}}},
				}),
			},
			err: config.ErrEndPortInvalid,
		},
		"endPort with toFQDNs valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8000", EndPort: 9000}}}},
				}),
			},
		},
		"invalid CIDR": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "not-a-cidr"}},
				}),
			},
			err: config.ErrCIDRInvalid,
		},
		"invalid CIDR except": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0", Except: []string{"bad"}}},
				}),
			},
			err: config.ErrCIDRInvalid,
		},
		"valid CIDR rule": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{
						CIDR:   "0.0.0.0/0",
						Except: []string{"10.0.0.0/8", "172.16.0.0/12"},
					}},
				}),
			},
		},
		"port empty string": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: ""}}}},
				}),
			},
			err: config.ErrPortEmpty,
		},
		"port invalid string": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "abc"}}}},
				}),
			},
			err: config.ErrPortInvalid,
		},
		"except not subnet of parent": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{
						CIDR:   "10.0.0.0/8",
						Except: []string{"192.168.0.0/16"},
					}},
				}),
			},
			err: config.ErrExceptNotSubnet,
		},
		"except subnet valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{
						CIDR:   "10.0.0.0/8",
						Except: []string{"10.1.0.0/16"},
					}},
				}),
			},
		},
		"except equal to parent valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{
						CIDR:   "10.0.0.0/8",
						Except: []string{"10.0.0.0/8"},
					}},
				}),
			},
		},
		"except broader than parent": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{
						CIDR:   "10.0.0.0/16",
						Except: []string{"10.0.0.0/8"},
					}},
				}),
			},
			err: config.ErrExceptNotSubnet,
		},
		"except different address family": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{
						CIDR:   "10.0.0.0/8",
						Except: []string{"fd00::/8"},
					}},
				}),
			},
			err: config.ErrExceptAddressFamilyMismatch,
		},
		"L7 on toPorts-only rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: config.ErrL7RequiresL3,
		},
		"L7 with toCIDR valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDR: []string{"10.0.0.0/8"},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "80"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/api/"}}},
					}},
				}),
			},
		},
		"L7 with toCIDRSet valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "10.0.0.0/8"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "80"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Method: "GET"}}},
					}},
				}),
			},
		},
		"L7 with toCIDR and serverNames rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDR: []string{"10.0.0.0/8"},
					ToPorts: []config.PortRule{{
						Ports:       []config.Port{{Port: "443"}},
						ServerNames: []string{"api.internal.example.com"},
						Rules:       &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: config.ErrCIDRL7WithServerNames,
		},
		"empty HTTP on toPorts-only valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{}},
					}},
				}),
			},
		},
		"toPorts-only without L7 valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080"}}}},
				}),
			},
		},
		"empty ports on non-FQDN rule valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToPorts: []config.PortRule{{}},
				}),
			},
		},
		"empty ports with CIDR valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{}},
				}),
			},
		},
		"wildcard matchPattern with L7 rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: config.ErrWildcardWithL7,
		},
		"wildcard matchPattern without L7 allowed": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
		"path regex too long rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Path: strings.Repeat("a", 1001)},
						}},
					}},
				}),
			},
			err: config.ErrPathInvalidRegex,
		},
		"except CIDR with host bits uses network base": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{
						CIDR:   "10.0.0.0/8",
						Except: []string{"10.1.2.3/16"},
					}},
				}),
			},
		},
		"lowercase protocol tcp normalized": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "TCP"}}}},
				}),
			},
		},
		"mixed case protocol Tcp normalized": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "Tcp"}}}},
				}),
			},
		},
		"matchName case normalized": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "GitHub.COM"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
		"matchName trailing dot stripped": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com."}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
		"matchPattern case normalized": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.Example.COM"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
		"matchPattern trailing dot stripped": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com."}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
		"matchName only dot rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "."}},
				}),
			},
			err: config.ErrFQDNSelectorEmpty,
		},
		"HTTP host field accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Path: "/v1/", Host: "api\\.example\\.com"},
						}},
					}},
				}),
			},
		},
		"host invalid regex rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Host: "["},
						}},
					}},
				}),
			},
			err: config.ErrHostInvalidRegex,
		},
		"HTTP headers valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Path: "/v1/", Headers: []string{"X-Custom"}},
						}},
					}},
				}),
			},
		},
		"HTTP headers empty name rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Path: "/v1/", Headers: []string{""}},
						}},
					}},
				}),
			},
			err: config.ErrHTTPHeaderEmpty,
		},
		"headerMatches valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{HeaderMatches: []config.HeaderMatch{{Name: "X-Token", Value: "secret"}}},
						}},
					}},
				}),
			},
		},
		"headerMatches empty name rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{HeaderMatches: []config.HeaderMatch{{Name: ""}}},
						}},
					}},
				}),
			},
			err: config.ErrHeaderMatchNameEmpty,
		},
		"headerMatches mismatch action rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{HeaderMatches: []config.HeaderMatch{
								{Name: "X-Token", Mismatch: config.MismatchLOG},
							}},
						}},
					}},
				}),
			},
			err: config.ErrHeaderMatchMismatchAction,
		},
		"L7 on port 8443 valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "8443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
		},
		"L7 on port 80 valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "80"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
		},
		"L7 with UDP protocol rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443", Protocol: "UDP"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: config.ErrL7RequiresTCP,
		},
		"L7 with SCTP protocol rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "80", Protocol: "SCTP"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: config.ErrL7RequiresTCP,
		},
		"L7 with ANY protocol rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443", Protocol: "ANY"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: config.ErrL7RequiresTCP,
		},
		"L7 with explicit TCP protocol valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443", Protocol: "TCP"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
		},
		"L7 with empty protocol valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
		},
		"L7 with mixed TCP and UDP ports rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{
							{Port: "80", Protocol: "TCP"},
							{Port: "443", Protocol: "UDP"},
						},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: config.ErrL7RequiresTCP,
		},
		"L7 with lowercase udp normalized then rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443", Protocol: "UDP"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: config.ErrL7RequiresTCP,
		},
		"empty HTTP rules with UDP protocol valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443", Protocol: "UDP"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{}},
					}},
				}),
			},
		},
		"matchName with spaces rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example .com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			err: config.ErrFQDNNameInvalidChars,
		},
		"matchName with colon rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example:8080.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			err: config.ErrFQDNNameInvalidChars,
		},
		"matchName with slash rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com/path"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			err: config.ErrFQDNNameInvalidChars,
		},
		"matchName with semicolon rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example;.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			err: config.ErrFQDNNameInvalidChars,
		},
		"matchPattern with spaces rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example .com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			err: config.ErrFQDNPatternInvalidChars,
		},
		"matchPattern with semicolon rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example;.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			err: config.ErrFQDNPatternInvalidChars,
		},
		"matchPattern with colon rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example:8080.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			err: config.ErrFQDNPatternInvalidChars,
		},
		"matchPattern with slash rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com/path"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			err: config.ErrFQDNPatternInvalidChars,
		},
		"matchName exceeding 255 chars rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: strings.Repeat("a", 256)}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			err: config.ErrFQDNTooLong,
		},
		"matchPattern exceeding 255 chars rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*." + strings.Repeat("a", 254)}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			err: config.ErrFQDNTooLong,
		},
		"matchName at exactly 255 chars valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: strings.Repeat("a", 255)}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
		"matchName with underscore valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "_dmarc.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
		"matchName with hyphen valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "my-service.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
		"punycode IDN matchName valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "xn--n3h.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
		"raw unicode matchName rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "\u2603.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			err: config.ErrFQDNNameInvalidChars,
		},
		"port 0 without L7 accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "0"}}}},
				}),
			},
		},
		"port 0 with FQDN rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "0"}}}},
				}),
			},
			err: config.ErrFQDNWildcardPort,
		},
		"port 0 with FQDN and L7 rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "0"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: config.ErrFQDNWildcardPort,
		},
		"empty ports with L7 rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{
						{Ports: []config.Port{{Port: "443"}}},
						{Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}}},
					},
				}),
			},
			err: config.ErrL7WithWildcardPort,
		},
		"port 0 with endPort silently ignored": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "0", EndPort: 443}}}},
				}),
			},
		},
		"port 0 with UDP accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "0", Protocol: "UDP"}}}},
				}),
			},
		},
		"negative endPort rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "443", EndPort: -1}}}},
				}),
			},
			err: config.ErrEndPortNegative,
		},
		"more than 40 ports rejected": {
			cfg: &config.Config{
				Egress: egressRules(func() config.EgressRule {
					ports := make([]config.Port, 41)
					for i := range ports {
						ports[i] = config.Port{Port: "443"}
					}

					return config.EgressRule{
						ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
						ToPorts:   []config.PortRule{{Ports: ports}},
					}
				}()),
			},
			err: config.ErrPortsTooMany,
		},
		"exactly 40 ports accepted": {
			cfg: &config.Config{
				Egress: egressRules(func() config.EgressRule {
					ports := make([]config.Port, 40)
					for i := range ports {
						ports[i] = config.Port{Port: "443"}
					}

					return config.EgressRule{
						ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
						ToPorts:   []config.PortRule{{Ports: ports}},
					}
				}()),
			},
		},
		"valid envoy settings": {
			cfg: &config.Config{
				Envoy: &config.EnvoySettings{
					LogLevel:                 "debug",
					DrainTimeout:             config.Duration{Duration: 10 * time.Second},
					StartupTimeout:           config.Duration{Duration: 30 * time.Second},
					MaxDownstreamConnections: 1024,
				},
			},
		},
		"nil envoy settings": {
			cfg: &config.Config{},
		},
		"envoy log level normalized": {
			cfg: &config.Config{
				Envoy: &config.EnvoySettings{LogLevel: "WARNING"},
			},
		},
		"invalid envoy log level": {
			cfg: &config.Config{
				Envoy: &config.EnvoySettings{LogLevel: "verbose"},
			},
			err: config.ErrInvalidEnvoyLogLevel,
		},
		"negative drain timeout": {
			cfg: &config.Config{
				Envoy: &config.EnvoySettings{DrainTimeout: config.Duration{Duration: -1 * time.Second}},
			},
			err: config.ErrInvalidEnvoyDrainTimeout,
		},
		"negative startup timeout": {
			cfg: &config.Config{
				Envoy: &config.EnvoySettings{StartupTimeout: config.Duration{Duration: -1 * time.Second}},
			},
			err: config.ErrInvalidEnvoyStartupTimeout,
		},
		"negative max connections": {
			cfg: &config.Config{
				Envoy: &config.EnvoySettings{MaxDownstreamConnections: -1},
			},
			err: config.ErrInvalidEnvoyMaxConnections,
		},
		"valid DNS rule on port 53": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "dns.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "53"}},
						Rules: &config.L7Rules{DNS: []config.DNSRule{
							{MatchName: "example.com"},
						}},
					}},
				}),
			},
		},
		"valid DNS rule with matchPattern on port 53": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "dns.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "53"}},
						Rules: &config.L7Rules{DNS: []config.DNSRule{
							{MatchPattern: "*.example.com"},
						}},
					}},
				}),
			},
		},
		"DNS rule on non-53 port rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "dns.example.com"}},
					ToPorts: []config.PortRule{
						{Ports: []config.Port{{Port: "443"}}},
						{
							Ports: []config.Port{{Port: "8053"}},
							Rules: &config.L7Rules{DNS: []config.DNSRule{
								{MatchName: "example.com"},
							}},
						},
					},
				}),
			},
			err: config.ErrDNSRuleRequiresPort53,
		},
		"DNS rule empty selector rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "dns.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "53"}},
						Rules: &config.L7Rules{DNS: []config.DNSRule{
							{},
						}},
					}},
				}),
			},
			err: config.ErrDNSRuleSelectorEmpty,
		},
		"DNS rule ambiguous selector rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "dns.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "53"}},
						Rules: &config.L7Rules{DNS: []config.DNSRule{
							{MatchName: "example.com", MatchPattern: "*.example.com"},
						}},
					}},
				}),
			},
			err: config.ErrDNSRuleSelectorAmbiguous,
		},
		"DNS rule invalid matchName chars rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "dns.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "53"}},
						Rules: &config.L7Rules{DNS: []config.DNSRule{
							{MatchName: "exam ple.com"},
						}},
					}},
				}),
			},
			err: config.ErrFQDNNameInvalidChars,
		},
		"DNS rule invalid matchPattern chars rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "dns.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "53"}},
						Rules: &config.L7Rules{DNS: []config.DNSRule{
							{MatchPattern: "*.exam ple.com"},
						}},
					}},
				}),
			},
			err: config.ErrFQDNPatternInvalidChars,
		},
		"DNS rule partial wildcard rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "dns.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "53"}},
						Rules: &config.L7Rules{DNS: []config.DNSRule{
							{MatchPattern: "api.*-staging.example.com"},
						}},
					}},
				}),
			},
			err: config.ErrFQDNPatternPartialWildcard,
		},
		"DNS rule normalized uppercase and trailing dot": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "dns.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "53"}},
						Rules: &config.L7Rules{DNS: []config.DNSRule{
							{MatchName: "Example.COM."},
						}},
					}},
				}),
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.Validate()
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestNamedPortValidation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg *config.Config
		err error
	}{
		"named port https accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "https"}}}},
				}),
			},
		},
		"named port http accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "http"}}}},
				}),
			},
		},
		"named port dns accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "dns"}}}},
				}),
			},
		},
		"named port domain accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "domain"}}}},
				}),
			},
		},
		"unknown named port rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "redis"}}}},
				}),
			},
			err: config.ErrPortInvalid,
		},
		"invalid syntax rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "abc!!"}}}},
				}),
			},
			err: config.ErrPortInvalid,
		},
		"negative port rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "-1"}}}},
				}),
			},
			err: config.ErrPortInvalid,
		},
		"endPort with named port silently ignored": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "https", EndPort: 500}}}},
				}),
			},
		},
		"L7 on named port http accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "http"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
		},
		"L7 on named port https accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "https"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
		},
		"L7 on named port dns valid": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "dns.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "dns"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
		},
		"uppercase named port normalized": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "HTTPS"}}}},
				}),
			},
		},
		"port 65536 rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "65536"}}}},
				}),
			},
			err: config.ErrPortInvalid,
		},
		"port 70000 rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "70000"}}}},
				}),
			},
			err: config.ErrPortInvalid,
		},
		"port 65535 accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "65535"}}}},
				}),
			},
		},
		"endPort 70000 rejected": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "443", EndPort: 70000}}}},
				}),
			},
			err: config.ErrEndPortInvalid,
		},
		"port 0 accepted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "0"}}}},
				}),
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.Validate()
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestUnsupportedSelectors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err       error
		yaml      string
		wantRules int
	}{
		"toEndpoints rejected": {
			yaml: `
egress:
  - toEndpoints:
      - matchLabels:
          role: backend
    toPorts:
      - ports:
          - port: "443"
`,
			err: config.ErrUnsupportedSelector,
		},
		"toEntities world expanded to CIDRs": {
			yaml: `
egress:
  - toEntities:
      - world
`,
			wantRules: 1,
		},
		"toEntities host rejected": {
			yaml: `
egress:
  - toEntities:
      - host
`,
			err: config.ErrUnsupportedEntity,
		},
		"toEntities mixed world and host rejected": {
			yaml: `
egress:
  - toEntities:
      - world
      - host
`,
			err: config.ErrUnsupportedEntity,
		},
		"toServices rejected": {
			yaml: `
egress:
  - toServices:
      - k8sService:
          serviceName: my-svc
          namespace: default
`,
			err: config.ErrUnsupportedSelector,
		},
		"toNodes rejected": {
			yaml: `
egress:
  - toNodes:
      - matchLabels:
          node-role: worker
`,
			err: config.ErrUnsupportedSelector,
		},
		"toGroups rejected": {
			yaml: `
egress:
  - toGroups:
      - aws:
          securityGroupsIds:
            - sg-123
`,
			err: config.ErrUnsupportedSelector,
		},
		"toRequires rejected": {
			yaml: `
egress:
  - toRequires:
      - something
`,
			err: config.ErrUnsupportedSelector,
		},
		"icmps valid": {
			yaml: `
egress:
  - icmps:
      - fields:
          - type: 8
`,
			wantRules: 1,
		},
		"authentication rejected": {
			yaml: `
egress:
  - authentication:
      mode: required
`,
			err: config.ErrUnsupportedSelector,
		},
		"empty toEntities not rejected": {
			yaml: `
egress:
  - toEntities: []
    toCIDR:
      - 10.0.0.0/8
`,
			wantRules: 1,
		},
		"null toEntities not rejected": {
			yaml: `
egress:
  - toEntities: null
    toCIDR:
      - 10.0.0.0/8
`,
			wantRules: 1,
		},
		"absent toEntities not rejected": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
`,
			wantRules: 1,
		},
		"error message includes field name and rule index": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
  - toEndpoints:
      - matchLabels:
          role: backend
`,
			err: config.ErrUnsupportedSelector,
		},
		"unknown field rejected at parse time": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
    someFutureField: true
`,
		},
		"unknown top-level field rejected": {
			yaml: `
egressPolicy:
  - toFQDNs:
      - matchName: example.com
`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.ParseConfig(t.Context(), []byte(tt.yaml))
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}

			if tt.wantRules > 0 {
				require.NoError(t, err)
				assert.Len(t, cfg.EgressRules(), tt.wantRules)

				return
			}

			// Unknown field cases: expect a parse error (not a sentinel)
			require.Error(t, err)
		})
	}

	// Verify the error message format includes field name and rule index.
	t.Run("error format", func(t *testing.T) {
		t.Parallel()

		_, err := config.ParseConfig(t.Context(), []byte(`
egress:
  - toCIDR:
      - 10.0.0.0/8
  - toEndpoints:
      - matchLabels:
          role: backend
`))
		require.ErrorIs(t, err, config.ErrUnsupportedSelector)
		assert.ErrorContains(t, err, "rule 1 has toEndpoints")
	})
}

func TestToEntitiesWorldExpansion(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		yaml     string
		err      error
		wantCIDR []string
	}{
		"world expands to dual-stack CIDRs": {
			yaml: `
egress:
  - toEntities:
      - world
`,
			wantCIDR: []string{"0.0.0.0/0", "::/0"},
		},
		"world with toPorts preserved": {
			yaml: `
egress:
  - toEntities:
      - world
    toPorts:
      - ports:
          - port: "443"
`,
			wantCIDR: []string{"0.0.0.0/0", "::/0"},
		},
		"world with toCIDR rejected (mutual exclusivity)": {
			yaml: `
egress:
  - toEntities:
      - world
    toCIDR:
      - 10.0.0.0/8
`,
			err: config.ErrEntitiesMixedL3,
		},
		"world with toCIDRSet rejected (mutual exclusivity)": {
			yaml: `
egress:
  - toEntities:
      - world
    toCIDRSet:
      - cidr: 10.0.0.0/8
`,
			err: config.ErrEntitiesMixedL3,
		},
		"world with toFQDNs rejected (mutual exclusivity)": {
			yaml: `
egress:
  - toEntities:
      - world
    toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
`,
			err: config.ErrEntitiesMixedL3,
		},
		"world case-insensitive": {
			yaml: `
egress:
  - toEntities:
      - World
`,
			wantCIDR: []string{"0.0.0.0/0", "::/0"},
		},
		"toEntities all expanded to dual-stack CIDRs": {
			yaml: `
egress:
  - toEntities:
      - all
`,
			wantCIDR: []string{"0.0.0.0/0", "::/0"},
		},
		"toEntities all with toPorts": {
			yaml: `
egress:
  - toEntities:
      - all
    toPorts:
      - ports:
          - port: "443"
`,
			wantCIDR: []string{"0.0.0.0/0", "::/0"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.ParseConfig(t.Context(), []byte(tt.yaml))
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)

				return
			}

			require.NoError(t, err)

			rules := cfg.EgressRules()
			require.Len(t, rules, 1)
			assert.Equal(t, tt.wantCIDR, rules[0].ToCIDR)
			assert.Empty(t, rules[0].ToEntities)
		})
	}
}

func TestUnsupportedFeatures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		yaml string
	}{
		"terminatingTLS rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        terminatingTLS:
          secret:
            name: my-secret
`,
			err: config.ErrUnsupportedFeature,
		},
		"originatingTLS rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        originatingTLS:
          secret:
            name: my-secret
`,
			err: config.ErrUnsupportedFeature,
		},
		"serverNames on FQDN rejected (requires CIDR)": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        serverNames:
          - example.com
`,
			err: config.ErrServerNamesRequiresCIDR,
		},
		"listener rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        listener:
          envoyConfig:
            name: my-listener
`,
			err: config.ErrUnsupportedFeature,
		},
		"cidrGroupRef rejected": {
			yaml: `
egress:
  - toCIDRSet:
      - cidr: 10.0.0.0/8
        cidrGroupRef: my-cidr-group
`,
			err: config.ErrUnsupportedFeature,
		},
		"cidrGroupSelector rejected": {
			yaml: `
egress:
  - toCIDRSet:
      - cidr: 10.0.0.0/8
        cidrGroupSelector:
          matchLabels:
            env: prod
`,
			err: config.ErrUnsupportedFeature,
		},
		"kafka L7 rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: kafka.example.com
    toPorts:
      - ports:
          - port: "9092"
        rules:
          kafka:
            - topic: my-topic
`,
			err: config.ErrUnsupportedFeature,
		},
		"dns L7 on port 53 accepted": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: dns.example.com
    toPorts:
      - ports:
          - port: "53"
        rules:
          dns:
            - matchPattern: "*.example.com"
`,
		},
		"l7proto rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        rules:
          l7proto: envoy.filters.network.my_filter
`,
			err: config.ErrUnsupportedFeature,
		},
		"l7 generic rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        rules:
          l7:
            - action: allow
`,
			err: config.ErrUnsupportedFeature,
		},
		"empty serverNames not rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        serverNames: []
`,
		},
		"null terminatingTLS not rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        terminatingTLS: null
`,
		},
		"empty kafka not rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        rules:
          kafka: []
`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := config.ParseConfig(t.Context(), []byte(tt.yaml))
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)

				return
			}

			require.NoError(t, err)
		})
	}

	// Verify the error message format includes field name and rule index.
	t.Run("error format includes context", func(t *testing.T) {
		t.Parallel()

		_, err := config.ParseConfig(t.Context(), []byte(`
egress:
  - toCIDR:
      - 10.0.0.0/8
  - toCIDRSet:
      - cidr: 10.0.0.0/8
        cidrGroupRef: my-group
`))
		require.ErrorIs(t, err, config.ErrUnsupportedFeature)
		require.ErrorContains(t, err, "rule 1")
		require.ErrorContains(t, err, "cidrGroupRef")
	})
}

func TestEgressDenyRules(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		yaml string
	}{
		"valid deny CIDR": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
egressDeny:
  - toCIDR:
      - 10.1.0.0/16
`,
		},
		"valid deny CIDRSet": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
egressDeny:
  - toCIDRSet:
      - cidr: 10.0.0.0/8
        except:
          - 10.1.0.0/16
`,
		},
		"valid deny with toPorts": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
egressDeny:
  - toCIDR:
      - 10.1.0.0/16
    toPorts:
      - ports:
          - port: "443"
`,
		},
		"deny with L7 rejected": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
egressDeny:
  - toCIDR:
      - 10.1.0.0/16
    toPorts:
      - ports:
          - port: "443"
        rules:
          http:
            - path: /secret
`,
			err: config.ErrDenyRuleL7,
		},
		"deny empty rule rejected": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
egressDeny:
  - {}
`,
			err: config.ErrDenyRuleEmpty,
		},
		"deny invalid CIDR rejected": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
egressDeny:
  - toCIDR:
      - not-a-cidr
`,
			err: config.ErrCIDRInvalid,
		},
		"deny toCIDR and toCIDRSet mixed rejected": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
egressDeny:
  - toCIDR:
      - 10.1.0.0/16
    toCIDRSet:
      - cidr: 10.2.0.0/16
`,
			err: config.ErrCIDRAndCIDRSetMixed,
		},
		"deny-only config with no allow rules is valid": {
			yaml: `
egressDeny:
  - toCIDR:
      - 10.0.0.0/8
`,
		},
		"egressDeny toEntities world expanded": {
			yaml: `
egressDeny:
  - toEntities:
      - world
`,
		},
		"egressDeny toEntities all expanded": {
			yaml: `
egressDeny:
  - toEntities:
      - all
`,
		},
		"egressDeny toEntities with toPorts": {
			yaml: `
egressDeny:
  - toEntities:
      - world
    toPorts:
      - ports:
          - port: "443"
`,
		},
		"egressDeny toEntities mixed with toCIDR rejected": {
			yaml: `
egressDeny:
  - toEntities:
      - world
    toCIDR:
      - 10.0.0.0/8
`,
			err: config.ErrDenyEntitiesMixedL3,
		},
		"egressDeny toEntities unsupported rejected": {
			yaml: `
egressDeny:
  - toEntities:
      - host
`,
			err: config.ErrUnsupportedEntity,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := config.ParseConfig(t.Context(), []byte(tt.yaml))
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestServerNames(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		yaml string
	}{
		"valid serverNames on CIDR rule": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
    toPorts:
      - ports:
          - port: "443"
        serverNames:
          - api.internal.example.com
`,
		},
		"valid serverNames on CIDRSet rule": {
			yaml: `
egress:
  - toCIDRSet:
      - cidr: 10.0.0.0/8
    toPorts:
      - ports:
          - port: "443"
        serverNames:
          - api.internal.example.com
`,
		},
		"serverNames requires CIDR": {
			yaml: `
egress:
  - toPorts:
      - ports:
          - port: "443"
        serverNames:
          - api.internal.example.com
`,
			err: config.ErrServerNamesRequiresCIDR,
		},
		"serverNames requires TCP": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
    toPorts:
      - ports:
          - port: "443"
            protocol: UDP
        serverNames:
          - api.internal.example.com
`,
			err: config.ErrServerNamesRequiresTCP,
		},
		"serverNames invalid hostname": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
    toPorts:
      - ports:
          - port: "443"
        serverNames:
          - "api.example.com/path"
`,
			err: config.ErrServerNamesInvalidHostname,
		},
		"serverNames empty protocol ok (defaults to TCP)": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
    toPorts:
      - ports:
          - port: "443"
        serverNames:
          - api.internal.example.com
`,
		},
		"serverNames wildcard *.example.com accepted": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
    toPorts:
      - ports:
          - port: "443"
        serverNames:
          - "*.example.com"
`,
		},
		"serverNames wildcard **.example.com accepted": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
    toPorts:
      - ports:
          - port: "443"
        serverNames:
          - "**.example.com"
`,
		},
		"serverNames partial wildcard rejected": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
    toPorts:
      - ports:
          - port: "443"
        serverNames:
          - "api.*.example.com"
`,
			err: config.ErrServerNamesInvalidWildcard,
		},
		"serverNames bare wildcard rejected": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
    toPorts:
      - ports:
          - port: "443"
        serverNames:
          - "*"
`,
			err: config.ErrServerNamesInvalidWildcard,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := config.ParseConfig(t.Context(), []byte(tt.yaml))
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestICMPRules(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		yaml string
	}{
		"valid numeric IPv4 type": {
			yaml: `
egress:
  - icmps:
      - fields:
          - type: "8"
`,
		},
		"valid CamelCase IPv4 type": {
			yaml: `
egress:
  - icmps:
      - fields:
          - type: EchoRequest
`,
		},
		"valid numeric IPv6 type": {
			yaml: `
egress:
  - icmps:
      - fields:
          - family: IPv6
            type: "128"
`,
		},
		"valid CamelCase IPv6 type": {
			yaml: `
egress:
  - icmps:
      - fields:
          - family: IPv6
            type: EchoRequest
`,
		},
		"family case-insensitive": {
			yaml: `
egress:
  - icmps:
      - fields:
          - family: ipv6
            type: "128"
`,
		},
		"empty type rejected": {
			yaml: `
egress:
  - icmps:
      - fields:
          - family: IPv4
`,
			err: config.ErrICMPTypeRequired,
		},
		"invalid type name rejected": {
			yaml: `
egress:
  - icmps:
      - fields:
          - type: NotARealType
`,
			err: config.ErrICMPInvalidType,
		},
		"out of range type rejected": {
			yaml: `
egress:
  - icmps:
      - fields:
          - type: "256"
`,
			err: config.ErrICMPInvalidType,
		},
		"invalid family rejected": {
			yaml: `
egress:
  - icmps:
      - fields:
          - family: IPv5
            type: "8"
`,
			err: config.ErrICMPInvalidFamily,
		},
		"icmps with toPorts rejected": {
			yaml: `
egress:
  - icmps:
      - fields:
          - type: "8"
    toPorts:
      - ports:
          - port: "443"
`,
			err: config.ErrICMPWithToPorts,
		},
		"too many fields rejected": {
			yaml: `
egress:
  - icmps:
      - fields:` + generateICMPFields(41) + `
`,
			err: config.ErrICMPFieldsTooMany,
		},
		"icmps coexists with toCIDR": {
			yaml: `
egress:
  - icmps:
      - fields:
          - type: "8"
    toCIDR:
      - 10.0.0.0/8
`,
		},
		"icmps coexists with toEntities": {
			yaml: `
egress:
  - icmps:
      - fields:
          - type: "8"
    toEntities:
      - world
`,
		},
		"icmps-only rule not blocked": {
			yaml: `
egress:
  - icmps:
      - fields:
          - type: "8"
`,
		},
		"deny rule with icmps valid": {
			yaml: `
egressDeny:
  - icmps:
      - fields:
          - type: "8"
`,
		},
		"deny rule with icmps and toPorts rejected": {
			yaml: `
egressDeny:
  - icmps:
      - fields:
          - type: "8"
    toPorts:
      - ports:
          - port: "443"
`,
			err: config.ErrICMPWithToPorts,
		},
		"wrong family name for type rejected": {
			yaml: `
egress:
  - icmps:
      - fields:
          - family: IPv6
            type: Photuris
`,
			err: config.ErrICMPInvalidType,
		},
		"multiple fields in one rule": {
			yaml: `
egress:
  - icmps:
      - fields:
          - type: EchoRequest
          - type: EchoReply
          - family: IPv6
            type: EchoRequest
`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := config.ParseConfig(t.Context(), []byte(tt.yaml))
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestICMPIsEgressBlocked(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ICMPs: []config.ICMPRule{{
				Fields: []config.ICMPField{{Type: "8"}},
			}},
		}),
	}
	assert.False(t, cfg.IsEgressBlocked())
}

func TestEgressDenyUnsupportedSelectors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		yaml string
	}{
		"deny toEndpoints rejected": {
			yaml: `
egressDeny:
  - toEndpoints:
      - matchLabels:
          role: backend
`,
			err: config.ErrUnsupportedSelector,
		},
		"deny toServices rejected": {
			yaml: `
egressDeny:
  - toServices:
      - k8sService:
          serviceName: my-svc
`,
			err: config.ErrUnsupportedSelector,
		},
		"deny toNodes rejected": {
			yaml: `
egressDeny:
  - toNodes:
      - matchLabels:
          role: worker
`,
			err: config.ErrUnsupportedSelector,
		},
		"deny toGroups rejected": {
			yaml: `
egressDeny:
  - toGroups:
      - aws:
          securityGroupsIds: ["sg-123"]
`,
			err: config.ErrUnsupportedSelector,
		},
		"deny toRequires rejected": {
			yaml: `
egressDeny:
  - toRequires:
      - something
`,
			err: config.ErrUnsupportedSelector,
		},
		"deny authentication rejected": {
			yaml: `
egressDeny:
  - toCIDR:
      - 10.0.0.0/8
    authentication:
      mode: required
`,
			err: config.ErrUnsupportedSelector,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := config.ParseConfig(t.Context(), []byte(tt.yaml))
			require.ErrorIs(t, err, tt.err)
		})
	}
}

// generateICMPFields returns a YAML snippet with n ICMP field entries.
func generateICMPFields(n int) string {
	var b strings.Builder
	for range n {
		b.WriteString("\n          - type: \"8\"")
	}

	return b.String()
}
