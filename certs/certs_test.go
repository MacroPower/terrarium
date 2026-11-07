package certs_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/certs"
	"go.jacobcolvin.com/terrarium/config"
)

func TestGenerateCA(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath, keyPath, err := certs.GenerateCA(dir)
	require.NoError(t, err)

	assert.Equal(t, filepath.Join(dir, "ca.pem"), certPath)
	assert.Equal(t, filepath.Join(dir, "ca-key.pem"), keyPath)

	certPEM, err := os.ReadFile(certPath)
	require.NoError(t, err)

	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, cert.IsCA)
	assert.Equal(t, "Terrarium CA", cert.Subject.CommonName)
	assert.Equal(t, 0, cert.MaxPathLen)
	assert.True(t, cert.MaxPathLenZero)

	keyPEM, err := os.ReadFile(keyPath)
	require.NoError(t, err)

	keyBlock, _ := pem.Decode(keyPEM)
	require.NotNil(t, keyBlock)
	assert.Equal(t, "EC PRIVATE KEY", keyBlock.Type)

	assertMode(t, keyPath, 0o600)
}

func TestGenerateCARestrictsExistingKeyFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ca-key.pem")
	require.NoError(t, os.WriteFile(keyPath, []byte("old"), 0o644))

	_, _, err := certs.GenerateCA(dir)
	require.NoError(t, err)

	assertMode(t, keyPath, 0o600)
}

func TestLoadOrGenerateCA(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// setup prepares dir and returns the CA cert PEM that
		// LoadOrGenerateCA should keep, or nil when it should
		// generate a new CA.
		setup func(t *testing.T, dir string) []byte
	}{
		"empty dir": {
			setup: func(*testing.T, string) []byte { return nil },
		},
		"valid pair": {
			setup: func(t *testing.T, dir string) []byte {
				t.Helper()

				certPath, _, err := certs.GenerateCA(dir)
				require.NoError(t, err)

				return readFile(t, certPath)
			},
		},
		"valid pair with readable key": {
			setup: func(t *testing.T, dir string) []byte {
				t.Helper()

				certPath, keyPath, err := certs.GenerateCA(dir)
				require.NoError(t, err)
				require.NoError(t, os.Chmod(keyPath, 0o644))

				return readFile(t, certPath)
			},
		},
		"key from another CA": {
			setup: func(t *testing.T, dir string) []byte {
				t.Helper()

				_, _, err := certs.GenerateCA(dir)
				require.NoError(t, err)

				_, otherKey, err := certs.GenerateCA(t.TempDir())
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(
					filepath.Join(dir, "ca-key.pem"), readFile(t, otherKey), 0o600))

				return nil
			},
		},
		"cert without PEM": {
			setup: func(t *testing.T, dir string) []byte {
				t.Helper()

				_, _, err := certs.GenerateCA(dir)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("garbage"), 0o644))

				return nil
			},
		},
		"leaf instead of CA": {
			setup: func(t *testing.T, dir string) []byte {
				t.Helper()

				caDir := t.TempDir()
				leafDir := t.TempDir()

				_, _, err := certs.GenerateCA(caDir)
				require.NoError(t, err)
				require.NoError(t, certs.GenerateLeaf(caDir, leafDir, "example.com"))

				writeFile(
					t,
					filepath.Join(dir, "ca.pem"),
					readFile(t, filepath.Join(leafDir, "example.com", "cert.pem")),
				)
				writeFile(
					t,
					filepath.Join(dir, "ca-key.pem"),
					readFile(t, filepath.Join(leafDir, "example.com", "key.pem")),
				)

				return nil
			},
		},
		"CA that expires before a new leaf": {
			setup: func(t *testing.T, dir string) []byte {
				t.Helper()

				writeShortLivedCA(t, dir, 30*24*time.Hour)

				return nil
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			kept := tt.setup(t, dir)

			certPath, keyPath, err := certs.LoadOrGenerateCA(dir)
			require.NoError(t, err)

			assert.Equal(t, filepath.Join(dir, "ca.pem"), certPath)
			assert.Equal(t, filepath.Join(dir, "ca-key.pem"), keyPath)
			assertMode(t, keyPath, 0o600)

			certPEM := readFile(t, certPath)
			if kept != nil {
				assert.Equal(t, kept, certPEM)
			}

			// The returned pair must sign a leaf that verifies.
			require.NoError(t, certs.GenerateLeaf(dir, t.TempDir(), "example.com"))

			_, err = tls.X509KeyPair(certPEM, readFile(t, keyPath))
			require.NoError(t, err)

			block, _ := pem.Decode(certPEM)
			require.NotNil(t, block)

			cert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)
			assert.True(t, cert.IsCA)
		})
	}
}

func TestLoadOrGenerateCAUnreadableCert(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, _, err := certs.GenerateCA(dir)
	require.NoError(t, err)

	// Reading a directory in place of the cert file fails with an
	// error other than "not exist". LoadOrGenerateCA returns that
	// error instead of overwriting the stored CA.
	certPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.Remove(certPath))
	require.NoError(t, os.Mkdir(certPath, 0o755))

	_, _, err = certs.LoadOrGenerateCA(dir)
	require.Error(t, err)
	require.NotErrorIs(t, err, certs.ErrInvalidCA)
}

func TestGenerateLeafInvalidCA(t *testing.T) {
	t.Parallel()

	caDir := t.TempDir()
	writeFile(t, filepath.Join(caDir, "ca.pem"), []byte("garbage"))
	writeFile(t, filepath.Join(caDir, "ca-key.pem"), []byte("garbage"))

	err := certs.GenerateLeaf(caDir, t.TempDir(), "example.com")
	require.ErrorIs(t, err, certs.ErrInvalidCA)
}

// writeShortLivedCA writes a CA cert and key to dir that expire after
// lifetime.
func writeShortLivedCA(t *testing.T, dir string, lifetime time.Duration) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Short-lived CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(lifetime),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	writeFile(t, filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeFile(
		t,
		filepath.Join(dir, "ca-key.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path) //nolint:gosec // test fixture path.
	require.NoError(t, err)

	return data
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()

	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, want, info.Mode().Perm())
}

func TestGenerateLeafCert(t *testing.T) {
	t.Parallel()

	caDir := t.TempDir()
	_, _, err := certs.GenerateCA(caDir)
	require.NoError(t, err)

	certsDir := t.TempDir()

	tests := map[string]struct {
		domain  string
		wantSAN []string
	}{
		"simple domain": {
			domain:  "api.example.com",
			wantSAN: []string{"api.example.com"},
		},
		"wildcard domain": {
			domain:  "*.example.com",
			wantSAN: []string{"*.example.com"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			localCertsDir := t.TempDir()
			err := certs.GenerateLeaf(caDir, localCertsDir, tt.domain)
			require.NoError(t, err)

			certPEM, err := os.ReadFile(filepath.Join(localCertsDir, tt.domain, "cert.pem"))
			require.NoError(t, err)

			block, _ := pem.Decode(certPEM)
			require.NotNil(t, block)

			cert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)
			assert.Equal(t, tt.domain, cert.Subject.CommonName)
			assert.Equal(t, tt.wantSAN, cert.DNSNames)
			assert.False(t, cert.IsCA)

			keyPEM, err := os.ReadFile(filepath.Join(localCertsDir, tt.domain, "key.pem"))
			require.NoError(t, err)

			keyBlock, _ := pem.Decode(keyPEM)
			require.NotNil(t, keyBlock)
			assert.Equal(t, "EC PRIVATE KEY", keyBlock.Type)

			// Verify cert is signed by CA.
			caCertPEM, err := os.ReadFile(filepath.Join(caDir, "ca.pem"))
			require.NoError(t, err)

			caBlock, _ := pem.Decode(caCertPEM)
			caCert, err := x509.ParseCertificate(caBlock.Bytes)
			require.NoError(t, err)

			pool := x509.NewCertPool()
			pool.AddCert(caCert)

			_, err = cert.Verify(x509.VerifyOptions{
				Roots:   pool,
				DNSName: tt.domain,
			})
			require.NoError(t, err)
		})
	}

	_ = certsDir
}

func TestGenerateCerts(t *testing.T) {
	t.Parallel()

	caDir := t.TempDir()
	certsDir := t.TempDir()

	rules := []config.ResolvedRule{
		{Domain: "api.example.com", HTTPRules: []config.ResolvedHTTPRule{{Path: "/v1/"}}},
		{Domain: "cdn.example.com"},
		{Domain: "internal.example.com", HTTPRules: []config.ResolvedHTTPRule{{Path: "/api/"}, {Path: "/health"}}},
	}

	err := certs.Generate(rules, caDir, certsDir)
	require.NoError(t, err)

	// CA should exist.
	_, err = os.Stat(filepath.Join(caDir, "ca.pem"))
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(caDir, "ca-key.pem"))
	require.NoError(t, err)

	// Path-restricted domains should have certs.
	for _, domain := range []string{"api.example.com", "internal.example.com"} {
		_, err = os.Stat(filepath.Join(certsDir, domain, "cert.pem"))
		require.NoError(t, err, "cert should exist for %s", domain)

		_, err = os.Stat(filepath.Join(certsDir, domain, "key.pem"))
		require.NoError(t, err, "key should exist for %s", domain)
	}

	// Unrestricted domain should NOT have certs.
	_, err = os.Stat(filepath.Join(certsDir, "cdn.example.com", "cert.pem"))
	assert.True(t, os.IsNotExist(err), "cert should not exist for cdn.example.com")
}
