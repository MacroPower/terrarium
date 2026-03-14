package terrarium

import (
	"context"
	"fmt"
	"os"

	"go.jacobcolvin.com/terrarium/certs"
	"go.jacobcolvin.com/terrarium/config"
)

// CertsDir is the directory where MITM leaf certificates are stored.
const CertsDir = "/etc/terrarium/certs"

// CADir is the directory where terrarium CA cert and key are stored.
const CADir = "/etc/terrarium/ca"

// Generate reads terrarium YAML config at configPath, resolves domains
// and ports, generates MITM certs for path-restricted rules, and writes
// the Envoy config file to /etc. Firewall rules are applied directly
// via nftables netlink in [Init], not written to files. The parsed
// [*Config] is returned so callers can reuse it without re-parsing.
func Generate(ctx context.Context, configPath string) (*config.Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	cfg, err := config.ParseConfig(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Collect domains that need MITM certs (restricted on any TLS port).
	tlsPorts := []int{443}
	tlsPorts = append(tlsPorts, cfg.ExtraPorts()...)
	mitmSeen := make(map[string]bool)

	var mitmRules []config.ResolvedRule
	for _, port := range tlsPorts {
		portRules := cfg.ResolveRulesForPort(port)

		for _, r := range portRules {
			if r.IsRestricted() && !mitmSeen[r.Domain] {
				mitmSeen[r.Domain] = true
				mitmRules = append(mitmRules, r)
			}
		}
	}

	certsDir := ""
	if len(mitmRules) > 0 {
		err := certs.Generate(mitmRules, CADir, CertsDir)
		if err != nil {
			return nil, fmt.Errorf("generating certs: %w", err)
		}

		certsDir = CertsDir
	}

	caBundlePath := findCABundle()
	envoyConf, err := GenerateEnvoyConfig(cfg, certsDir, caBundlePath)
	if err != nil {
		return nil, fmt.Errorf("generating envoy config: %w", err)
	}

	err = os.WriteFile("/etc/envoy-terrarium.yaml", []byte(envoyConf), 0o644)
	if err != nil {
		return nil, fmt.Errorf("writing envoy config: %w", err)
	}

	return cfg, nil
}

// GenerateEnvoyFromConfig resolves rules from a [Config] and
// generates the Envoy bootstrap YAML. This is a convenience wrapper
// for callers outside terrarium package that cannot construct
// unexported [ResolvedRule] values directly.
func GenerateEnvoyFromConfig(cfg *config.Config, certsDir, caBundlePath string) (string, error) {
	return GenerateEnvoyConfig(cfg, certsDir, caBundlePath)
}

// findCABundle returns the path to the system CA certificate bundle.
// Checks SSL_CERT_FILE and NIX_SSL_CERT_FILE env vars first, then
// well-known filesystem paths.
func findCABundle() string {
	candidates := []string{
		os.Getenv("SSL_CERT_FILE"),
		os.Getenv("NIX_SSL_CERT_FILE"),
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/ssl/certs/ca-bundle.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}

		_, err := os.Stat(c) //nolint:gosec // G703: paths are hardcoded candidates.
		if err == nil {
			return c
		}
	}

	return ""
}
