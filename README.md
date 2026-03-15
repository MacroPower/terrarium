# Terrarium

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
