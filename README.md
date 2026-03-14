# Terrarium

Terrarium is a secure sandbox that uses [Envoy](https://www.envoyproxy.io/) as an L7 egress gateway,
configured via familiar [Cilium](https://cilium.io/) network policy semantics.

It is particularly useful for running fully autonomous AI agents.
Terrarium allows you to declare policies that balance security and functionality,
based on your risk tolerance, environment, and use cases.

## Examples

- Allow GET requests to repos in your own GitHub organization, deny all other traffic.
- Allow access to your package registry, deny access to public registries.
- Allow access to the internet, deny access to your internal network, or vice versa.
