# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Terrarium is a secure container environment that uses Envoy as an L7 egress gateway.

It is designed to closely align with CiliumNetworkPolicy semantics.

## Build & Test Commands

```bash
task format # Format and lint
task lint   # Lint only
task test   # Run all tests
```

## Architecture

Three security modes drive the design: unrestricted (nil/empty egress rules), blocked (deny-all via `egress: [{}]`), and filtered (rules with FQDN/CIDR/L7 matchers).

The data flow is: YAML config -> `config` (parse, validate, normalize, resolve) -> `firewall` (nftables rules) + `envoy` (bootstrap config) + `certs` (MITM CA/leaf for L7-restricted rules). The `dnsproxy` package handles FQDN resolution and updates nftables IP sets in real-time with per-element TTLs.

- **cmd/terrarium**: CLI with `generate` (config + certs + Envoy bootstrap) and `init` (firewall + DNS proxy + Envoy + privilege drop + exec) commands. Uses cobra + charmbracelet/fang for arg parsing.
- **config**: Policy engine. Parses Cilium-compatible YAML, validates, normalizes (lowercase FQDNs, uppercase protocols), and resolves into firewall/envoy-ready structures. Extensive typed errors with per-rule context.
- **firewall**: nftables rule generation via google/nftables netlink backend. Per-rule chain isolation for OR semantics across egress rules. FQDN IP sets with TTLs.
- **envoy**: Models a subset of Envoy v3 API for bootstrap config generation. SNI-based filter chains, HTTP connection manager with route matching, RBAC for header/SNI validation.
- **dnsproxy**: DNS proxy using miekg/dns that resolves FQDNs and updates firewall IP sets dynamically.
- **dnstest**: Shared test helper (`StartServer(t, ip)`) for spinning up test DNS servers.
- **certs**: MITM certificate generation (CA + leaf) for L7-restricted TLS rules.

## Code Style

### Go Conventions

- Document all exported items with doc comments.
- Package documentation in `doc.go` files.
- Wrap errors with `fmt.Errorf("context: %w", err)`, or `fmt.Errorf("%w: %w", ErrSentinel, err)`.
- Avoid using "failed" or "error" in library error messages.
- Use global error variables for common errors.
- Use constructors with functional options.
- Accept interfaces, return concrete types.
- Prefer consistency over performance, avoid "fast paths" that could lead to unpredictable behavior.

### Documentation

- Use `[Name]` syntax for Go doc links. Use `[*Name]` for pointer types.
- Constructors should always begin: `// NewThing creates a new [Thing].`
- Types with constructors should always note: `// Create instances with [NewThing].`
- Interfaces should note: `// See [Thing] for an implementation.`
- Interfaces should have sensible names: `type Builder interface { Build() Thing } // Builder builds [Thing]s.`
- Functional option types should have a list linking to all functions of that type.
- Functional options should always have a link to their type.
- Package docs should explain concepts and usage patterns; **do not enumerate exports**.

### Testing

- Use `github.com/stretchr/testify/assert` and `require`.
- Table-driven tests with `map[string]struct{}` format.
- Field names: prefer `want` for expected output, `err` for expected errors.
- For inputs, use clear contextual names (e.g., `before`/`after` for diffs, `line`/`col` for positions).
- Always use `t.Parallel()` in all tests.
- Create test packages (`package foo_test`) testing public API.
- Use `require.ErrorIs` for sentinel error checking.
- Use `require.ErrorAs` for error type extraction.
