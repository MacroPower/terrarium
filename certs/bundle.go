package certs

import (
	"fmt"
	"log/slog"
	"os"
)

// FindCABundle returns the path to the system CA certificate bundle.
// Checks SSL_CERT_FILE and NIX_SSL_CERT_FILE env vars first, then
// well-known filesystem paths.
func FindCABundle() string {
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

// InstallToBundle appends a CA certificate to the system CA bundle and
// ensures SSL_CERT_FILE points to the updated bundle. This handles systems
// without update-ca-certificates (e.g. NixOS where the bundle is a
// read-only symlink into the nix store and SSL_CERT_FILE may point there).
func InstallToBundle(caCertPath string) error {
	caData, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("reading CA cert: %w", err)
	}

	// Collect candidate bundle paths: SSL_CERT_FILE first (what TLS
	// clients actually use), then well-known system paths.
	var candidates []string
	if env := os.Getenv("SSL_CERT_FILE"); env != "" {
		candidates = append(candidates, env)
	}

	if env := os.Getenv("NIX_SSL_CERT_FILE"); env != "" {
		candidates = append(candidates, env)
	}

	candidates = append(candidates,
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/ssl/certs/ca-bundle.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
	)

	// Deduplicate while preserving order.
	seen := make(map[string]bool)

	var bundles []string
	for _, c := range candidates {
		if c != "" && !seen[c] {
			seen[c] = true
			bundles = append(bundles, c)
		}
	}

	for _, bundle := range bundles {
		_, statErr := os.Stat(bundle) //nolint:gosec // G703: paths from hardcoded candidates.
		if statErr != nil {
			continue
		}

		err := appendToBundle(bundle, caData)
		if err != nil {
			slog.Warn("appending CA to bundle", //nolint:gosec // G706: bundle path from hardcoded candidates.
				slog.String("bundle", bundle),
				slog.Any("err", err),
			)

			continue
		}

		// Point SSL_CERT_FILE to the writable bundle so child
		// processes (running as uid 1000) pick it up.
		envErr := os.Setenv("SSL_CERT_FILE", bundle)
		if envErr != nil {
			slog.Debug("setting SSL_CERT_FILE", slog.Any("err", envErr))
		}

		return nil
	}

	return fmt.Errorf("no system CA bundle found")
}

// appendToBundle appends caData to the bundle file. If the file is a
// symlink (e.g. into the read-only nix store), it is replaced with a
// writable copy first.
func appendToBundle(bundle string, caData []byte) error {
	fi, err := os.Lstat(bundle) //nolint:gosec // G703: path from caller.
	if err != nil {
		return fmt.Errorf("stat %s: %w", bundle, err)
	}

	// Replace symlinks with a writable copy.
	if fi.Mode()&os.ModeSymlink != 0 {
		existing, err := os.ReadFile(bundle) //nolint:gosec // G703: path from caller.
		if err != nil {
			return fmt.Errorf("reading %s: %w", bundle, err)
		}

		err = os.Remove(bundle) //nolint:gosec // G703: path from caller.
		if err != nil {
			return fmt.Errorf("removing symlink %s: %w", bundle, err)
		}

		err = os.WriteFile(bundle, existing, 0o644) //nolint:gosec // G703: replacing symlink with writable copy.
		if err != nil {
			return fmt.Errorf("writing %s: %w", bundle, err)
		}
	}

	f, err := os.OpenFile(bundle, os.O_APPEND|os.O_WRONLY, 0o644) //nolint:gosec // G703: path from caller.
	if err != nil {
		return fmt.Errorf("opening %s: %w", bundle, err)
	}

	_, err = f.Write(append([]byte("\n"), caData...))
	if err != nil {
		closeErr := f.Close()
		if closeErr != nil {
			//nolint:gosec // G706: bundle path from caller.
			slog.Debug("closing bundle file after write error",
				slog.String("path", bundle),
				slog.Any("err", closeErr),
			)
		}

		return fmt.Errorf("appending to %s: %w", bundle, err)
	}

	err = f.Close()
	if err != nil {
		return fmt.Errorf("closing %s: %w", bundle, err)
	}

	return nil
}
