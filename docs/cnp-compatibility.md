# CiliumNetworkPolicy Compatibility

## Intentional Divergence

- **DNS rules require port 53 in toPorts**: Terrarium requires that port 53
  appear in the toPorts entry carrying DNS L7 rules. Cilium only checks
  `len(ports) == 0`, meaning any port passes. A DNS rule on port 80 without
  port 53 passes Cilium but fails Terrarium. This is because the Terrarium
  DNS proxy listens on port 53, and a DNS rule without it has no practical effect.

- **ServerNames on FQDN rules**: Terrarium accepts but ignores serverNames
  when toFQDNs is present. Cilium treats these as orthogonal fields with no
  interaction at the validation level.

- **L7 HTTP with empty protocol**: Terrarium accepts empty (omitted)
  protocol on toPorts entries with L7 HTTP rules, treating it as TCP
  Cilium normalizes empty protocol to ANY, then rejects `ANY != TCP`
  with "L7 rules can only apply to TCP". A policy with L7 HTTP rules
  and no `protocol: TCP` passes Terrarium but fails Cilium. This is an
  intentional convenience.

## N/A (requires cluster infrastructure)

These Cilium features are intentionally unsupported because they depend on
Kubernetes or cloud-provider APIs that do not exist in a standalone container:

- toEndpoints (pod identity matching)
- toServices (Kubernetes service discovery)
- toNodes (node label matching)
- toGroups (cloud provider security groups)
- toRequires (deprecated)
- authentication (SPIFFE mutual TLS)
- terminatingTLS / originatingTLS (Kubernetes Secret references)
- listener (CiliumEnvoyConfig CRD references)
- cidrGroupRef / cidrGroupSelector (CiliumCIDRGroup CRD)
- Kafka L7 rules (deprecated in Cilium)
- Generic L7 rules / l7proto (custom Envoy protocol parsers)
- Entities: host, cluster, init, ingress, unmanaged, remote-node, health,
  kube-apiserver, none (all require cluster identity or node context)
- Extended IP protocols: VRRP, IGMP, GRE, IPIP, ESP, AH (gated behind
  EnableExtendedIPProtocols flag; niche protocols without transport ports)
