<p align="center">
  <h1 align="center">Terrarium</h1>
</p>

<p align="center">
  <a href="https://pkg.go.dev/go.jacobcolvin.com/terrarium"><img alt="Go Reference" src="https://pkg.go.dev/badge/go.jacobcolvin.com/terrarium.svg"></a>
  <a href="https://goreportcard.com/report/go.jacobcolvin.com/terrarium"><img alt="Go Report Card" src="https://goreportcard.com/badge/go.jacobcolvin.com/terrarium"></a>
  <a href="https://codecov.io/gh/macropower/terrarium"><img src="https://codecov.io/gh/macropower/terrarium/graph/badge.svg?token=4TNYTL2WXV"/></a>
  <a href="#-installation"><img alt="Latest tag" src="https://img.shields.io/github/v/tag/macropower/terrarium?label=version&sort=semver"></a>
  <a href="https://github.com/macropower/terrarium/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/github/license/macropower/terrarium"></a>
</p>

Terrarium is a secure container environment that uses [Envoy](https://www.envoyproxy.io/) as an L7 egress gateway,
configured via familiar [Cilium](https://cilium.io/) network policy semantics.

It is particularly useful for running fully autonomous AI agents.
Terrarium allows you to declare policies that balance security and functionality,
based on your risk tolerance, environment, and use cases.

## Examples

Allow GET requests to repos in your own GitHub organization, deny all other traffic:

```yaml
egress:
  - toFQDNs:
      - matchName: "github.com"
      - matchPattern: "*.github.com"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
        rules:
          http:
            - method: "GET"
              path: "/my-org/.*"
```

Allow access to your package registry, deny access to public registries:

```yaml
egress:
  - toFQDNs:
      - matchName: "registry.internal.com"
      - matchPattern: "*.registry.internal.com"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
          - port: "80"
            protocol: TCP
```

Allow access to the internet, deny access to your internal network:

```yaml
egress:
  - toCIDRSet:
      - cidr: "0.0.0.0/0"
        except:
          - "10.0.0.0/8"
          - "172.16.0.0/12"
          - "192.168.0.0/16"
```

Or vice versa -- allow internal, deny internet:

```yaml
egress:
  - toCIDR:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
```
