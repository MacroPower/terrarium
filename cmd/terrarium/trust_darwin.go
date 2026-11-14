//go:build darwin

package main

import (
	"context"
	"errors"
	"log/slog"
	"os/exec"
	"strings"
)

// warnUntrustedCA logs a warning when the macOS keychain does not trust
// the MITM CA at caPath. Go-based tools on macOS verify certificates
// through the keychain and ignore SSL_CERT_FILE, so they reject every
// inspected host until the user adds the CA to the login keychain.
//
// The check runs `security verify-cert`, which evaluates the certificate
// against the system anchors and the user's trust settings. It treats
// the certificate as a CA (-l) and stays offline (-L). A verification
// failure means the keychain does not trust the CA. Any other failure,
// such as a missing security binary, skips the check with a debug log.
func warnUntrustedCA(ctx context.Context, caPath string) {
	securityBin, err := exec.LookPath("security")
	if err != nil {
		slog.DebugContext(ctx, "proxy: keychain trust check skipped",
			slog.Any("err", err))

		return
	}

	//nolint:gosec // G204: binary from PATH lookup, path from the CA directory.
	out, err := exec.CommandContext(ctx, securityBin,
		"verify-cert", "-c", caPath, "-l", "-L").CombinedOutput()
	if err == nil {
		return
	}

	var exitErr *exec.ExitError

	if !errors.As(err, &exitErr) {
		slog.DebugContext(ctx, "proxy: keychain trust check skipped",
			slog.Any("err", err))

		return
	}

	slog.WarnContext(ctx, "proxy: macOS keychain does not trust the MITM CA, "+
		"so Go-based tools reject hosts with L7 rules",
		slog.String("ca", caPath),
		slog.String("result", strings.TrimSpace(string(out))),
		slog.String("fix", "security add-trusted-cert -r trustRoot "+
			"-k ~/Library/Keychains/login.keychain-db "+caPath))
}
