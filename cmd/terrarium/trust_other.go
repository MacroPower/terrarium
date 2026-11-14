//go:build !darwin

package main

import "context"

// warnUntrustedCA is a no-op outside macOS. Clients there read the CA
// from the exported files rather than from a system trust store, so
// there is no store to check. See the darwin implementation for the
// keychain check.
func warnUntrustedCA(_ context.Context, _ string) {}
