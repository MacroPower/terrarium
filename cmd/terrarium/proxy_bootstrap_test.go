package main

import (
	"errors"
	"maps"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/certs"
	"go.jacobcolvin.com/terrarium/envoy"
	"go.jacobcolvin.com/terrarium/envoybin"
)

// pinnedEnvoyDirEnv names the environment variable that turns on
// [TestPinnedEnvoyLoadsProxyBootstraps]. Its value is the directory
// that holds the managed Envoy builds of the test. The test installs
// the pinned build for the host there when the directory does not hold
// it.
//
// The envoy workflow in .github/workflows sets the variable and runs
// the test by its name. The tests of the envoybin package check the
// workflow against the two names, so change the workflow together with
// a name.
const pinnedEnvoyDirEnv = "TERRARIUM_TEST_ENVOY_DIR"

// loadProbeToken is the probe token of the bootstraps that the
// tests load into Envoy with [requireEnvoyLoadsBootstrap].
const loadProbeToken = "0123456789abcdef"

var (
	// extensionType matches the type URL of an Envoy extension config,
	// in Go source and in a bootstrap.
	extensionType = regexp.MustCompile(`type\.googleapis\.com/envoy\.[A-Za-z0-9_.]+`)

	// formatCommand matches the start of a command of an Envoy format
	// string, such as %CEL( or %START_TIME%, in Go source and in a
	// bootstrap. Some commands, such as CEL, come from an Envoy
	// extension, and no type URL names that extension.
	formatCommand = regexp.MustCompile(`%[A-Z][A-Z0-9_]+[(%]`)
)

// containerOnlyExtensionTypes returns the extension types that only the
// bootstrap of container mode names. A proxy bootstrap never names
// them, so the managed Envoy builds do not need them.
func containerOnlyExtensionTypes() []string {
	return []string{
		"type.googleapis.com/envoy.extensions.filters.listener.original_dst.v3.OriginalDst",
		"type.googleapis.com/envoy.extensions.filters.udp.udp_proxy.v3.Route",
		"type.googleapis.com/envoy.extensions.filters.udp.udp_proxy.v3.UdpProxyConfig",
	}
}

// proxyCoverageBootstraps returns the proxy bootstraps that the tests
// load into Envoy, by the name of their policy. The bootstraps together
// name every extension type and every format command that a proxy
// bootstrap can name. The [requireProxyExtensionCoverage] function
// checks that claim.
//
// The filtered policy has one rule for each kind of filter chain: TLS
// passthrough, TLS inspection, and plain HTTP. Each rule allows an
// exact name and a wildcard. Its HTTP rules use every matcher and every
// mismatch action of a headerMatches entry. The bootstrap of that
// policy also has the access loggers of an enabled stats block and the
// resolver of the --resolver flag.
//
// The bootstraps of the other policies leave out the resolver, the way
// that a proxy without the --resolver flag does. Their DNS caches name
// no resolver extension, so Envoy instantiates the default resolver of
// its platform, which is the Apple resolver on macOS.
func proxyCoverageBootstraps(t *testing.T) map[string]string {
	t.Helper()

	// The path of a Unix socket has a small length limit, and the
	// bootstrap leaves the access loggers out for a longer path.
	socket := filepath.Join(shortTempDir(t), "accesslog.sock")

	const l7Rules = "" +
		"        rules:\n" +
		"          http:\n" +
		"            - method: GET\n" +
		"              path: /v1/.*\n" +
		"              host: api.inspected.example\n" +
		"              headers:\n" +
		"                - X-Present\n" +
		"              headerMatches:\n" +
		"                - {name: X-Plain, value: plain}\n" +
		"                - {name: X-Log, value: log, mismatch: LOG}\n" +
		"                - {name: X-Add, value: add, mismatch: ADD}\n" +
		"                - {name: X-Delete, value: delete, mismatch: DELETE}\n" +
		"                - {name: X-Replace, value: replace, mismatch: REPLACE}\n"

	// The filtered policy names the resolver of the --resolver flag.
	resolver := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")}

	policies := map[string]struct {
		policy    string
		resolvers []netip.AddrPort
	}{
		"unrestricted": {policy: "stats:\n" +
			"  enabled: true\n" +
			"  socket: " + socket + "\n"},
		"blocked": {policy: "egress:\n" +
			"  - {}\n"},
		"filtered": {resolvers: resolver, policy: "stats:\n" +
			"  enabled: true\n" +
			"  socket: " + socket + "\n" +
			"egress:\n" +
			"  - toFQDNs:\n" +
			"      - matchName: passthrough.example\n" +
			"      - matchPattern: \"*.passthrough.example\"\n" +
			"    toPorts:\n" +
			"      - ports:\n" +
			"          - port: \"443\"\n" +
			"  - toFQDNs:\n" +
			"      - matchName: inspected.example\n" +
			"      - matchPattern: \"*.inspected.example\"\n" +
			"    toPorts:\n" +
			"      - ports:\n" +
			"          - port: \"443\"\n" +
			"          - port: \"8443\"\n" +
			l7Rules +
			"  - toFQDNs:\n" +
			"      - matchName: plain.example\n" +
			"      - matchPattern: \"*.plain.example\"\n" +
			"    toPorts:\n" +
			"      - ports:\n" +
			"          - port: \"80\"\n" +
			l7Rules},
	}

	// Envoy reads the certificate files that a bootstrap names, so the
	// test creates them the way that [GenerateProxy] does.
	caDir := t.TempDir()
	certsDir := t.TempDir()

	caPath, _, err := certs.GenerateCA(caDir)
	require.NoError(t, err)

	bootstraps := make(map[string]string, len(policies))

	for name, policy := range policies {
		cfg := parseProxyConfig(t, policy.policy)

		require.NoError(t, certs.GenerateLeaves(collectMITMRules(t.Context(), cfg), caDir, certsDir))

		bootstrap, err := GenerateProxyEnvoyFromConfig(
			t.Context(), cfg, certsDir, caPath, "127.0.0.1", 8080, policy.resolvers, loadProbeToken)
		require.NoError(t, err)

		bootstraps[name] = bootstrap
	}

	return bootstraps
}

// requireProxyExtensionCoverage fails the test when the bootstraps do
// not name every extension type and every format command that a proxy
// bootstrap can name.
//
// The extension types that terrarium can generate are the type URLs in
// the Go source of the envoy package and of this package. The format
// commands are the commands of the format strings in that source. The
// proxy bootstraps can name each of them, except for the types of
// [containerOnlyExtensionTypes]. A change that makes the generator name
// another extension type or format command therefore fails the test,
// until a policy of [proxyCoverageBootstraps] uses it.
//
// The function also fails the test when no bootstrap has a DNS cache
// without a resolver extension. Envoy instantiates the default resolver
// of its platform for such a cache, and no type URL names that
// resolver.
func requireProxyExtensionCoverage(t *testing.T, bootstraps map[string]string) {
	t.Helper()

	var sources []string

	for _, pattern := range []string{"*.go", "../../envoy/*.go"} {
		files, err := filepath.Glob(filepath.FromSlash(pattern))
		require.NoError(t, err)
		require.NotEmpty(t, files)

		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}

			src, err := os.ReadFile(file)
			require.NoError(t, err)

			sources = append(sources, string(src))
		}
	}

	containerOnly := containerOnlyExtensionTypes()

	generated := findAllSorted(extensionType, sources)

	// The generator must name each container-only type. A stale entry
	// is a sign that the list does not match the generator.
	assert.Subset(t, generated, containerOnly)

	want := slices.DeleteFunc(generated, func(typ string) bool {
		return slices.Contains(containerOnly, typ)
	})

	require.Equal(t, want, findAllSorted(extensionType, slices.Collect(maps.Values(bootstraps))),
		"the coverage bootstraps must name each extension type of a proxy bootstrap")

	require.Equal(t, findAllSorted(formatCommand, sources),
		findAllSorted(formatCommand, slices.Collect(maps.Values(bootstraps))),
		"the coverage bootstraps must use each format command of the generator")

	assert.True(t, slices.ContainsFunc(slices.Collect(maps.Values(bootstraps)), func(bootstrap string) bool {
		return strings.Contains(bootstrap, "dns_cache_config:") &&
			!strings.Contains(bootstrap, "typed_dns_resolver_config:")
	}), "a coverage bootstrap must use the default DNS resolver of the platform")
}

// findAllSorted returns the sorted matches of re in the texts, without
// duplicates.
func findAllSorted(re *regexp.Regexp, texts []string) []string {
	var found []string

	for _, text := range texts {
		found = append(found, re.FindAllString(text, -1)...)
	}

	slices.Sort(found)

	return slices.Compact(found)
}

// requireEnvoyLoadsBootstrap fails the test when an Envoy rejects the
// proxy bootstrap. The newCmd function returns a new command that runs
// that Envoy with the given arguments. Envoy validates the bootstrap
// and exits, so it does not open a listener.
//
// The arguments are those of a proxy, so the test also fails when the
// Envoy rejects one of them.
func requireEnvoyLoadsBootstrap(t *testing.T, bootstrap string, newCmd func(args ...string) *exec.Cmd) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "envoy-proxy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(bootstrap), 0o644))

	args := append(proxyEnvoyArgs(runtime.GOOS, path, "info", ""), "--mode", "validate")

	var (
		out []byte
		err error
	)

	// An install of the managed build that ended a moment ago can
	// leave the binary busy. See [startEnvoyWhenFree].
	for pause := busyStartPause; ; pause *= 2 {
		cmd := newCmd(args...)

		// Envoy rejects the bootstrap without the probe token variable.
		cmd.Env = append(os.Environ(), envoy.ProxyProbeTokenEnv+"="+loadProbeToken)

		out, err = cmd.CombinedOutput()
		if !errors.Is(err, syscall.ETXTBSY) || pause > time.Second {
			break
		}

		time.Sleep(pause)
	}

	require.NoError(t, err, string(out))
}

// TestProxyCoverageBootstraps checks that the bootstraps of
// [proxyCoverageBootstraps] name every extension type and every format
// command of a proxy bootstrap, and that the envoy on PATH loads each
// of them.
func TestProxyCoverageBootstraps(t *testing.T) {
	t.Parallel()

	bootstraps := proxyCoverageBootstraps(t)

	requireProxyExtensionCoverage(t, bootstraps)

	for name, bootstrap := range bootstraps {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			requireEnvoy(t)

			requireEnvoyLoadsBootstrap(t, bootstrap, func(args ...string) *exec.Cmd {
				return exec.CommandContext(t.Context(), envoyCommand, args...)
			})
		})
	}
}

// TestPinnedEnvoyLoadsProxyBootstraps checks that the managed Envoy
// build for the host loads the bootstraps of [proxyCoverageBootstraps].
// That build is the Envoy that a proxy runs by default. A build that
// lacks an extension of the bootstraps rejects them.
//
// The test runs only when the variable [pinnedEnvoyDirEnv] names a
// directory, because the install of the build needs internet access. It
// then never skips, so a host without a managed build fails it. The
// verify jobs of the envoy workflow run it on one runner for each
// platform of the manifest.
func TestPinnedEnvoyLoadsProxyBootstraps(t *testing.T) {
	t.Parallel()

	dir := os.Getenv(pinnedEnvoyDirEnv)
	if dir == "" {
		t.Skipf("%s names no directory for the managed Envoy build", pinnedEnvoyDirEnv)
	}

	// The proxy resolves its Envoy with the same call, so the test
	// runs the binary the way that the proxy runs it.
	bin, err := resolveEnvoy(t.Context(), envoybin.NewInstaller(dir), "")
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, bin.Close())
	})

	bootstraps := proxyCoverageBootstraps(t)

	requireProxyExtensionCoverage(t, bootstraps)

	for name, bootstrap := range bootstraps {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			requireEnvoyLoadsBootstrap(t, bootstrap, func(args ...string) *exec.Cmd {
				return bin.command(t.Context(), args...)
			})
		})
	}
}
