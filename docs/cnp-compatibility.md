# CiliumNetworkPolicy Compatibility

## Overview

Terrarium adopts CiliumNetworkPolicy syntax for egress policy configuration,
letting operators reuse existing policy expertise in a standalone container
context. This document describes the supported subset, intentional divergences,
and features that require cluster infrastructure and are therefore unsupported.

Terrarium supports L3 selectors (toFQDNs, toCIDR, toCIDRSet, and a subset of
toEntities), L4 selectors (toPorts with port ranges), L7 rules (HTTP route
matching, DNS filtering, SNI filtering via serverNames), and ICMP rules.

Features that depend on Kubernetes or cloud-provider APIs (pod/service/node
selectors, Secret references, CRD-based CIDR groups, deprecated protocols) are
unsupported; see the N/A section below for the full list.

The standalone Envoy+nftables enforcement model introduces constraints that do
not exist in Cilium: proxy port arithmetic limits, explicit port requirements
for DNS and L7 rules, mandatory L3 selectors for L7 inspection, and others. The
Intentional Divergence section documents each constraint with its rationale.

## Example

The following config exercises every supported field. Inline comments call out
where Terrarium diverges from CiliumNetworkPolicy; each comment maps to a
bullet in the Intentional Divergence section below.

```yaml
egress:
  # FQDN rule with L7 HTTP filtering.
  - toFQDNs:
      - matchName: "api.example.com"
      - matchPattern: "*.cdn.example.com"
      # Non-leading wildcards (e.g. "api.*.example.com") are rejected when
      # L7 HTTP rules are present. Only "*.suffix" and "**.suffix" forms allowed.
    toPorts:
      # toPorts entries with L7 HTTP rules require a non-empty ports list.
      - ports:
          # Ports above 50535 are rejected on Envoy-proxied rules (proxy port overflow).
          - port: "443"
            # Empty protocol on L7 HTTP entries is treated as TCP.
          - port: "8443"
            endPort: 8500
            # endPort range capped at 100 ports for toFQDNs.
            protocol: TCP
        rules:
          # L7 HTTP rules require an L3 selector (toFQDNs or toCIDR/toCIDRSet).
          http:
            # Path and method regex capped at 1000 characters.
            - method: "GET|POST"
              path: "/v1/.*"
              host: "api\\.example\\.com"
              headers:
                - "X-Request-Id"
              headerMatches:
                # Secret references on headerMatches are rejected.
                - name: "X-Api-Key"
                  value: "expected-value"
                - name: "X-Trace"
                  mismatch: ADD
                  value: "injected"
                - name: "X-Strip"
                  mismatch: DELETE

  # FQDN rule with DNS L7 filtering.
  - toFQDNs:
      - matchName: "internal.example.com"
      - matchPattern: "*.internal.example.com"
    toPorts:
      - ports:
          # DNS rules require port 53 in toPorts.
          - port: "53"
            protocol: UDP
          - port: "53"
            protocol: TCP
        rules:
          dns:
            - matchName: "internal.example.com"
            - matchPattern: "*.internal.example.com"
      - ports:
          - port: "443"
            protocol: TCP

  # CIDR rule with serverNames (SNI filtering).
  - toCIDR:
      - "10.0.0.0/8"
    toPorts:
      - ports:
          # serverNames requires TCP protocol on all ports.
          - port: "443"
            protocol: TCP
        # One of toCIDR/toCIDRSet/toFQDNs is required when serverNames is present.
        # serverNames on toFQDNs replaces FQDN domains as the Envoy SNI allowlist.
        # L7 HTTP + serverNames is rejected, since terminatingTLS is not supported.
        serverNames:
          - "db.internal.example.com"
          - "*.internal.example.com"
          # Bare wildcards ("*", "**") are silently removed.

  # CIDRSet rule with port range.
  - toCIDRSet:
      - cidr: "0.0.0.0/0"
        except:
          - "10.0.0.0/8"
          - "127.0.0.0/8"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
          - port: "80"
            protocol: TCP

  # toEntities rule.
  - toEntities:
      # Only "world", "all", "world-ipv4", and "world-ipv6" are supported.
      # Other entities (host, cluster, kube-apiserver, etc.) are rejected.
      # Supported entities expand to CIDRs (0.0.0.0/0, ::/0).
      - world
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP

  # ICMP rule.
  - icmps:
      - fields:
          - type: EchoRequest
            family: IPv4
          - type: EchoRequest
            family: IPv6

  # ICMP rule scoped to FQDNs.
  - toFQDNs:
      - matchName: "ping-target.example.com"
    icmps:
      - fields:
          - type: EchoRequest
            family: IPv4

egressDeny:
  # Deny rules do not support toFQDNs, L7 rules, or serverNames.
  - toCIDR:
      - "192.168.0.0/16"
    toPorts:
      - ports:
          - port: "22"
            protocol: TCP
  - toCIDRSet:
      - cidr: "172.16.0.0/12"
        except:
          - "172.16.1.0/24"
    toPorts:
      - ports:
          - port: "3306"
            protocol: TCP
  - toEntities:
      - world
    icmps:
      - fields:
          - type: EchoRequest
            family: IPv4

tcpForwards:
  - port: 22
    host: "github.com"
```

## Intentional Divergence

### DNS rules require port 53 in toPorts

Terrarium requires that port 53 appear in the toPorts entry carrying DNS L7
rules. Cilium only checks `len(ports) == 0`, meaning any port passes. A DNS
rule on port 80 without port 53 passes Cilium but fails Terrarium. Terrarium
redirects DNS traffic to its built-in proxy via nftables DNAT on port 53; a
DNS rule targeting another port has no path to the proxy and would have no
practical effect.

### ServerNames constraints

Terrarium routes SNI filtering through Envoy, which imposes several
constraints on how serverNames is used.

When serverNames is present on a toFQDNs rule, Terrarium uses the serverNames
as the Envoy SNI allowlist instead of the FQDN matchName/matchPattern values.
DNS resolution still uses the FQDN domains to build IP sets. This aligns with
Cilium's treatment of serverNames as a restriction: resolve these FQDNs for
IPs, but only allow TLS connections matching the specified SNIs. If another
PortRule on the same port has no restrictions (plain L4), serverNames is
skipped and the FQDN domains are used as unrestricted entries.

Terrarium requires toCIDR, toCIDRSet, or toFQDNs when serverNames is present.
Cilium allows serverNames without any L3 selector (the SNI filter applies to
all destinations). Terrarium needs L3 context for Envoy filter chain routing.

All ports in a toPorts entry with serverNames must use TCP (or empty
protocol). Cilium does not explicitly check protocol for serverNames. SNI
inspection is inherently TLS/TCP, so non-TCP protocols with serverNames have
no meaningful semantics.

Bare wildcard serverNames entries (`*`, `**`) are normalized away during
preprocessing. A bare wildcard matches every SNI, which is identical to having
no SNI restriction at all; keeping it would generate a no-op Envoy filter
chain. Cilium accepts bare wildcards and they match all SNIs.

Cilium rejects serverNames combined with any L7 rule type (HTTP, DNS, or
L7Proto) unless terminatingTLS is also set. Terrarium only enforces this
restriction for L7 HTTP rules; serverNames with DNS L7 rules passes
validation. In practice, the combination is unlikely: DNS rules require port
53, and SNI filtering has no meaningful effect on unencrypted DNS traffic.
A DNS rule with serverNames on port 53/TCP would pass Terrarium but fail
Cilium.

Cilium allows L7 HTTP rules with serverNames when terminatingTLS is set.
Terrarium rejects this combination unconditionally since terminatingTLS is not
supported (see N/A section). A Cilium policy using L7 HTTP + serverNames +
terminatingTLS will fail Terrarium validation.

### L7 HTTP rule constraints

Terrarium's L7 HTTP inspection is routed through Envoy, which requires
explicit port and destination context that Cilium infers from its datapath.

Empty (omitted) protocol on toPorts entries with L7 HTTP rules is treated as
TCP. Cilium normalizes empty protocol to ANY, then rejects `ANY != TCP` with
"L7 rules can only apply to TCP". A policy with L7 HTTP rules and no
`protocol: TCP` passes Terrarium but fails Cilium. This is an intentional
convenience.

toPorts entries that carry L7 HTTP rules must have a non-empty Ports list.
Cilium allows empty Ports, treating it as "all TCP ports" and redirecting
matching traffic through its proxy. Terrarium requires explicit port numbers
because each destination port maps to a dedicated Envoy listener.

An L3 selector (toFQDNs, toCIDR/toCIDRSet, or toEntities) is required when
L7 HTTP rules are present. toEntities satisfies this requirement because
entities are expanded to CIDRs before L7 validation runs. Cilium allows L7
rules without any L3 selector (they apply to all destinations). Terrarium
needs L3 context because L7 inspection requires either FQDN-based MITM or
CIDR-scoped HTTP filtering.

matchPattern selectors with wildcards in non-leading positions (e.g.,
`api.*.example.com`, `*.ci*.io`, bare `*`) are rejected when L7 HTTP rules
are present. Cilium allows any valid pattern with L7. MITM certificate
generation requires a wildcard-free suffix for the SAN (RFC 6125 only supports
`*.suffix` form).

HTTP path and method regex patterns are capped at 1000 characters. Cilium has
no explicit length limit. These regexes compile into RE2 matchers in Envoy's
route config; bounding prevents denial-of-service from pathological regexes.

### Proxy port and range limits

Terrarium allocates Envoy proxy listeners by adding ProxyPortBase (15000) to
the destination port, which imposes two arithmetic constraints.

Destination ports above 50535 are rejected when they require an Envoy proxy
listener (toFQDNs rules with TCP ports, rules with L7 or serverNames, and
tcpForwards). Values above 50535 overflow uint16. Plain CIDR or open-port
rules that bypass Envoy are not subject to this limit. Cilium does not have
this constraint since its proxy port allocation works differently.

endPort ranges on toFQDNs rules are limited to 100 ports. Each port in a
range with L7 rules requires a separate Envoy listener, and large ranges risk
exhausting the proxy port space. The cap is applied uniformly to all toFQDNs
port ranges (with or without L7) for consistency. Cilium has no equivalent
limit.

### egressDeny constraints

Deny rules are enforced in nftables before traffic reaches Envoy, so they
require explicit port matches and cannot use features that depend on L7
inspection.

serverNames on egressDeny toPorts entries is rejected. SNI is a TLS-layer
concept not visible at the nftables stage; serverNames on deny rules would be
silently ignored. Cilium's EgressDenyRule does not structurally have
serverNames, so the scenario does not arise there.

### Port resolution

Cilium resolves named ports dynamically from Kubernetes pod specs
(containerPort.name). Terrarium resolves named ports via the system's
/etc/services file, which covers the full IANA Service Name registry.
Container images without /etc/services (e.g. scratch) must use numeric
ports. As a fallback, `dns` and `dns-tcp` are recognized as Kubernetes
conventions for port 53 even when /etc/services is absent (the IANA name
is `domain`).

## Terrarium Extensions

### tcpForwards

tcpForwards is a Terrarium-only feature with no CiliumNetworkPolicy
equivalent. Each entry creates a plain TCP proxy listener in Envoy with
STRICT_DNS routing to a single upstream host. This is useful for
non-TLS TCP services (e.g. SSH to github.com) that cannot be expressed
as FQDN-based egress rules since they lack TLS SNI for destination
filtering. Ports are subject to the same proxy port ceiling (50535) as
other Envoy-proxied rules.

## N/A (requires cluster infrastructure)

These Cilium features are intentionally unsupported because they depend on
Kubernetes or cloud-provider APIs that do not exist in a standalone container:

- toEndpoints (pod identity matching)
- toServices (Kubernetes service discovery)
- toNodes (node label matching)
- toGroups (cloud provider security groups)
- toRequires (deprecated)
- authentication (SPIFFE mutual TLS)
- HeaderMatch secret references (Kubernetes Secret injection for header values)
- terminatingTLS / originatingTLS (Kubernetes Secret references)
- listener (CiliumEnvoyConfig CRD references)
- cidrGroupRef / cidrGroupSelector (CiliumCIDRGroup CRD)
- Kafka L7 rules (deprecated in Cilium)
- Generic L7 rules / l7proto (custom Envoy protocol parsers)
- Entities: host, cluster, init, ingress, unmanaged, remote-node, health,
  kube-apiserver, none (all require cluster identity or node context)
- Extended IP protocols: VRRP, IGMP, GRE, IPIP, ESP, AH (gated behind
  EnableExtendedIPProtocols flag; niche protocols without transport ports)
