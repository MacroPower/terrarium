// Package certs generates MITM certificates for L7-restricted egress rules
// and manages the system CA trust bundle.
//
// When an egress rule constrains HTTP paths or methods, Envoy must terminate
// TLS to inspect the request. This package creates the certificate chain
// that makes that possible: an ECDSA P-256 CA and per-domain leaf
// certificates signed by that CA. Only domains with L7 restrictions
// receive leaf certs, and unrestricted domains pass through without MITM.
//
// Container mode calls [Generate], which creates a new CA on every
// start, because the CA lives only as long as the container. Proxy mode
// calls [LoadOrGenerateCA] and [GenerateLeaves] to reuse a stored CA,
// because clients on the host keep the CA in their trust stores. Only
// the owner can read the CA key file.
//
// To make the generated CA trusted inside the container, the bundle
// functions locate the system CA certificate file (checking SSL_CERT_FILE,
// NIX_SSL_CERT_FILE, and well-known paths) and append the CA certificate.
// On systems where the bundle is a read-only symlink (e.g. NixOS), the
// symlink is replaced with a writable copy before appending.
package certs
