package certs_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/certs"
)

// writeTempBundle creates a file standing in for a CA bundle and
// returns its path.
func writeTempBundle(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "bundle.pem")
	require.NoError(t, os.WriteFile(path, []byte("test bundle"), 0o600))

	return path
}

// TestFindCABundle cannot use t.Parallel: t.Setenv forbids it.
func TestFindCABundle(t *testing.T) {
	t.Run("SSL_CERT_FILE takes precedence", func(t *testing.T) {
		bundle := writeTempBundle(t)
		t.Setenv("SSL_CERT_FILE", bundle)
		t.Setenv("NIX_SSL_CERT_FILE", "")

		assert.Equal(t, bundle, certs.FindCABundle())
	})

	t.Run("NIX_SSL_CERT_FILE when SSL_CERT_FILE unset", func(t *testing.T) {
		bundle := writeTempBundle(t)
		t.Setenv("SSL_CERT_FILE", "")
		t.Setenv("NIX_SSL_CERT_FILE", bundle)

		assert.Equal(t, bundle, certs.FindCABundle())
	})

	t.Run("missing env var path falls through", func(t *testing.T) {
		bogus := filepath.Join(t.TempDir(), "does-not-exist.pem")
		t.Setenv("SSL_CERT_FILE", bogus)
		t.Setenv("NIX_SSL_CERT_FILE", "")

		// The result is whatever system bundle exists on the host (or
		// "" when none does); it must never be the nonexistent path.
		assert.NotEqual(t, bogus, certs.FindCABundle())
	})
}
