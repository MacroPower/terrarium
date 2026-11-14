package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.jacobcolvin.com/terrarium/config"
)

const (
	caCertFile = "ca.pem"
	caKeyFile  = "ca-key.pem"

	// Leaves from [GenerateLeaf] stay valid for this long.
	leafValidity = 365 * 24 * time.Hour
)

// ErrInvalidCA means that a stored CA certificate and key cannot sign new
// leaves. Causes include a key that does not match the certificate and
// a certificate that expires before a new leaf.
var ErrInvalidCA = errors.New("invalid CA")

// GenerateCA creates an ECDSA P-256 CA certificate and key, writing them
// to dir/ca.pem and dir/ca-key.pem. Returns the paths to the written files.
// Only the owner can read the key file.
func GenerateCA(dir string) (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generating CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("generating serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Terrarium CA",
			Organization: []string{"terrarium"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("creating CA certificate: %w", err)
	}

	err = os.MkdirAll(dir, 0o755)
	if err != nil {
		return "", "", fmt.Errorf("creating CA dir: %w", err)
	}

	certPath := filepath.Join(dir, caCertFile)

	err = writePEM(certPath, "CERTIFICATE", certDER, 0o644)
	if err != nil {
		return "", "", fmt.Errorf("writing CA cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("marshaling CA key: %w", err)
	}

	keyPath := filepath.Join(dir, caKeyFile)

	// Only terrarium reads the CA key, to sign leaves. Envoy reads the
	// leaf keys instead.
	err = writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0o600)
	if err != nil {
		return "", "", fmt.Errorf("writing CA key: %w", err)
	}

	return certPath, keyPath, nil
}

// LoadOrGenerateCA returns the paths to the CA certificate and key in
// dir. It reuses the stored pair when the certificate is a CA, the key
// matches it, and the certificate outlives a new leaf from
// [GenerateLeaf]. Otherwise it generates a new pair with [GenerateCA].
//
// Reusing the CA keeps it trusted across restarts by clients that
// stored it, such as a keychain entry or an exported CA bundle. To
// rotate the CA, delete dir.
func LoadOrGenerateCA(dir string) (string, string, error) {
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	cert, _, err := loadCA(certPath, keyPath)
	if err == nil {
		err = checkCAValidity(cert, time.Now())
	}

	switch {
	case err == nil:
		// GenerateCA wrote the key with mode 0o644 through v0.7.0.
		err = os.Chmod(keyPath, 0o600)
		if err != nil {
			return "", "", fmt.Errorf("restricting CA key: %w", err)
		}

		return certPath, keyPath, nil

	case errors.Is(err, fs.ErrNotExist):
		// No stored pair yet.

	case errors.Is(err, ErrInvalidCA):
		slog.Warn("replacing stored CA",
			slog.String("dir", dir),
			slog.Any("reason", err),
		)

	default:
		return "", "", fmt.Errorf("loading CA: %w", err)
	}

	return GenerateCA(dir)
}

// loadCA reads and parses the CA certificate and key PEM files. It
// returns an error wrapping [ErrInvalidCA] when a file does not parse,
// the certificate is not a CA, or the key does not match it.
func loadCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath) //nolint:gosec // G304: path from caller.
	if err != nil {
		return nil, nil, fmt.Errorf("reading CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath) //nolint:gosec // G304: path from caller.
	if err != nil {
		return nil, nil, fmt.Errorf("reading CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("%w: %s holds no PEM block", ErrInvalidCA, certPath)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: parsing CA cert: %w", ErrInvalidCA, err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("%w: %s holds no PEM block", ErrInvalidCA, keyPath)
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: parsing CA key: %w", ErrInvalidCA, err)
	}

	if !cert.IsCA {
		return nil, nil, fmt.Errorf("%w: %s is not a CA certificate", ErrInvalidCA, certPath)
	}

	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, nil, fmt.Errorf("%w: CA key does not match the certificate", ErrInvalidCA)
	}

	return cert, key, nil
}

// checkCAValidity returns an error wrapping [ErrInvalidCA] when cert is
// not yet valid at now, or expires before a leaf signed at now.
func checkCAValidity(cert *x509.Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("%w: CA is not valid until %s", ErrInvalidCA, cert.NotBefore.Format(time.RFC3339))
	}

	if now.Add(leafValidity).After(cert.NotAfter) {
		return fmt.Errorf("%w: CA expires at %s, before a new leaf", ErrInvalidCA, cert.NotAfter.Format(time.RFC3339))
	}

	return nil
}

// GenerateLeaf creates a leaf certificate for domain signed by the CA
// in caDir, writing cert.pem and key.pem to certsDir/<domain>/.
func GenerateLeaf(caDir, certsDir, domain string) error {
	caCert, caKey, err := loadCA(filepath.Join(caDir, caCertFile), filepath.Join(caDir, caKeyFile))
	if err != nil {
		return err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generating serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:  []string{domain},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(leafValidity),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("creating leaf certificate: %w", err)
	}

	domainDir := filepath.Join(certsDir, domain)

	err = os.MkdirAll(domainDir, 0o755)
	if err != nil {
		return fmt.Errorf("creating cert dir: %w", err)
	}

	err = writePEM(filepath.Join(domainDir, "cert.pem"), "CERTIFICATE", certDER, 0o644)
	if err != nil {
		return fmt.Errorf("writing leaf cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return fmt.Errorf("marshaling leaf key: %w", err)
	}

	// 0o644: in container mode, Envoy runs as its own UID and reads
	// the leaf key to terminate TLS.
	err = writePEM(filepath.Join(domainDir, "key.pem"), "EC PRIVATE KEY", keyDER, 0o644)
	if err != nil {
		return fmt.Errorf("writing leaf key: %w", err)
	}

	return nil
}

// Generate generates a new CA and leaf certificates for all restricted
// rules (those with path or method constraints), and skips
// unrestricted domains. To keep an existing CA, call
// [LoadOrGenerateCA] and then [GenerateLeaves].
func Generate(rules []config.ResolvedRule, caDir, certsDir string) error {
	_, _, err := GenerateCA(caDir)
	if err != nil {
		return fmt.Errorf("generating CA: %w", err)
	}

	return GenerateLeaves(rules, caDir, certsDir)
}

// GenerateLeaves generates a leaf certificate, signed by the CA in
// caDir, for each restricted rule (those with path or method
// constraints). It skips unrestricted domains.
func GenerateLeaves(rules []config.ResolvedRule, caDir, certsDir string) error {
	for _, r := range rules {
		if !r.IsRestricted() {
			continue
		}

		// Convert "**.example.com" to "*.example.com" for cert SANs
		// and directory paths. TLS certs use "*.example.com" as the
		// wildcard SAN form (RFC 6125); there is no "**." SAN.
		domain := wildcardServerName(r.Domain)

		err := GenerateLeaf(caDir, certsDir, domain)
		if err != nil {
			return fmt.Errorf("generating cert for %s: %w", r.Domain, err)
		}
	}

	return nil
}

// wildcardServerName converts a "**." domain prefix to the TLS-standard
// "*." form. TLS certificates use "*.example.com" (RFC 6125); there is
// no "**." SAN.
func wildcardServerName(domain string) string {
	if strings.HasPrefix(domain, "**.") {
		return "*." + domain[3:]
	}

	return domain
}

// writePEM writes a PEM-encoded block to path and sets its mode to
// perm, including when path already exists.
func writePEM(path, pemType string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm) //nolint:gosec // G304: path from caller.
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}

	// OpenFile applies perm only when it creates the file, so set it
	// before the write for a file that already existed.
	err = f.Chmod(perm)
	if err != nil {
		closeAfterError(f, path)

		return fmt.Errorf("setting mode of %s: %w", path, err)
	}

	err = pem.Encode(f, &pem.Block{Type: pemType, Bytes: data})
	if err != nil {
		closeAfterError(f, path)

		return fmt.Errorf("encoding PEM to %s: %w", path, err)
	}

	err = f.Close()
	if err != nil {
		return fmt.Errorf("closing %s: %w", path, err)
	}

	return nil
}

// closeAfterError closes f after a failed write and logs a close
// error, because the caller returns the write error instead.
func closeAfterError(f *os.File, path string) {
	err := f.Close()
	if err != nil {
		slog.Warn("closing file after write error",
			slog.String("path", path),
			slog.Any("error", err),
		)
	}
}
