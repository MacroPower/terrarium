# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Terrarium is a secure container environment that uses Envoy as an L7 egress gateway.

It is designed to closely align with CiliumNetworkPolicy semantics.

## Build & Test Commands

```bash
task format    # Format and tidy code, run generators, update the Lima vendorHash and the go.sum of the Dagger modules
task lint      # golangci-lint, go mod tidy check, Lima vendorHash check, Dagger module go.sum check, prettier
task test      # Run all tests (unit + integration)
task check     # Local gate: lint + test (tools on the devbox PATH, no Dagger)
task check:all # Everything CI runs (adds security + GitHub config + releaser, via Dagger)
```

Devbox provides all required tools on PATH automatically.

CI runs these same tasks inside the devbox environment via the `ci` Dagger
toolchain (`dagger call ci <task>`), so local and CI execute identical commands.
The `ci` module composes the shared toolchains from github.com/MacroPower/x
(devbox, goreleaser, security, zizmor), pinned in `ci/dagger.json` and the root
`dagger.json`; the `dagger` CLI must be on PATH and match the pinned
`engineVersion`.

The `cmd/envoymanifest` tool maintains the Envoy pin in `envoybin/manifest.go`.
Run its commands from the root of the repository. They need internet access.

```bash
go run ./cmd/envoymanifest update            # Write the hashes of the pinned Envoy version into envoybin/manifest.go
go run ./cmd/envoymanifest verify [platform] # Check the provenance of the pinned Envoy build for the host
```

Run `update` after every change to `Version` in `envoybin/manifest.go`, so that
the version and the hashes change in one commit. Renovate runs `update` when it
bumps the pin, and the `envoy` workflow runs `verify` on one runner for each
platform of the manifest.

The `cmd/vendorhash` tool maintains the `vendorHash` in `lima/flake.nix`, which
is the hash of the vendor tree of the root Go module. Run its commands from the
root of the repository. They need each dependency of the root module in the
module cache, or internet access to download it.

```bash
go run ./cmd/vendorhash check  # Fail when the vendorHash in lima/flake.nix is not the hash of the vendor tree
go run ./cmd/vendorhash update # Write the hash of the vendor tree into lima/flake.nix
```

`task lint` runs `check`, and `task format` runs `update`. The vendor tree
changes with the dependencies in the root `go.mod` and with the packages that
the root module imports. Run `task format` after each of these changes, so that
the change and the hash land in one commit. Renovate runs `update` when it
changes a dependency in the root `go.mod`.

The `cmd/modsum` tool maintains `go.sum` in the Dagger modules in `ci` and
`ci/tests`. Those modules are outside the workspace of `go.work`, so `task lint`
does not run `go mod tidy -diff` there. Do not run `go mod tidy` in them. Dagger
generates part of their packages, git ignores the generated files, and `go mod
tidy` removes the requirements of the packages that it cannot find. Run the
commands of the tool from the root of the repository.

```bash
go run ./cmd/modsum check  # Fail when go.sum in ci or ci/tests does not match the requirements of go.mod
go run ./cmd/modsum update # Write the hashes that go.mod requires into go.sum in ci and ci/tests
```

`task lint` runs `check`, and `task format` runs `update`. Run `task format`
after each change to a requirement in `ci/go.mod` or `ci/tests/go.mod`, so that
the requirement and its hashes land in one commit. `update` runs `go mod
download`, so it needs each dependency of the two modules in the module cache,
or internet access to download it. Renovate runs `update` when it changes a
dependency in one of the two `go.mod` files.

## Architecture

Three security modes drive the design: unrestricted (nil/empty egress rules), blocked (deny-all via `egress: [{}]`), and filtered (rules with FQDN/CIDR/L7 matchers).

The data flow is: YAML config -> `config` (parse, validate, normalize, resolve) -> `firewall` (nftables rules) + `envoy` (bootstrap config) + `certs` (MITM CA/leaf for L7-restricted rules). The `dnsproxy` package handles FQDN resolution and updates nftables IP sets in real-time with per-element TTLs.

- **cmd/terrarium**: CLI with `generate` (config + certs + Envoy bootstrap), `init` (firewall + DNS proxy + Envoy + privilege drop + exec), and `mcp` (MCP server for the stats event store) commands. Uses cobra + charmbracelet/fang for arg parsing.
- **cmd/envoymanifest**: Maintains the Envoy pin of `envoybin`, which is `Version` and the SHA-256 hashes in `envoybin/manifest.go`. `update` downloads every build of the pinned version and replaces the hashes in that file. `verify` checks the hashes, the publisher's signature or build attestation, and the version commit of the build for the host platform. It is a separate module in `go.work`, so its OpenPGP dependency (`github.com/ProtonMail/go-crypto`) stays out of the root `go.mod`.
- **cmd/vendorhash**: Maintains the `vendorHash` of the Lima flake in `lima/flake.nix`. `check` creates the vendor tree of the root module with `go mod vendor` and computes the hash that Nix computes for the tree. It fails when the flake holds another hash. `update` writes that hash into the flake. The tool computes the hash in Go, so it does not need Nix.
- **cmd/modsum**: Maintains `go.sum` in the Dagger modules in `ci` and `ci/tests`, where `go mod tidy` cannot run. `check` reads `go.mod` and `go.sum` and fails when `go.sum` does not hold the two hashes of a required module version, or holds the hash of another version of a required module. `update` removes the hashes of those other versions and adds the missing hashes with `go mod download`.
- **config**: Policy engine. Parses Cilium-compatible YAML, validates, normalizes (lowercase FQDNs, uppercase protocols), and resolves into firewall/envoy-ready structures. Extensive typed errors with per-rule context.
- **firewall**: nftables rule generation via google/nftables netlink backend. Per-rule chain isolation for OR semantics across egress rules. FQDN IP sets with TTLs.
- **envoy**: Models a subset of Envoy v3 API for bootstrap config generation. SNI-based filter chains, HTTP connection manager with route matching, RBAC for header/SNI validation.
- **envoybin**: Installs the pinned Envoy binary for the host into the XDG data directory and checks its SHA-256 against a compiled-in manifest. Backs `terrarium envoy install` and the Envoy that `terrarium proxy` runs by default.
- **dnsproxy**: DNS proxy using miekg/dns that resolves FQDNs and updates firewall IP sets dynamically.
- **dnstest**: Shared test helpers that start a mock DNS server (`StartServer(t, ip)`) or a DNS proxy (`StartProxy(t, cfg, upstream)`) on a free loopback port. `Listen(t)` binds one port for UDP and TCP.
- **certs**: MITM certificate generation (CA + leaf) for L7-restricted TLS rules.
- **mcpserver**: Model Context Protocol (MCP) server on `github.com/modelcontextprotocol/go-sdk` that backs `terrarium mcp`. Its tools (`list_instances`, `summarize_events`, `top_events`, `list_events`, `get_health`, `get_policy`, `list_policies`) read the stats event store through `eventstore.Reader`, which each tool call opens read-only. No tool writes, takes SQL, or takes a file path. The server limits the rows of each result and truncates long strings. `get_policy` returns one policy snapshot as the stored YAML and as rule lists that hold each rule with its index. Clients can therefore pair the `rule_index` of an event with its rule. Event fields hold values that the sandboxed workload chooses, so the tools return them only as JSON field values.

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
