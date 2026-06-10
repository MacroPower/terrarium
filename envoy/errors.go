package envoy

import "errors"

// ErrMITMCABundleMissing is returned when a policy contains
// L7-restricted (MITM) rules but no system CA bundle is available to
// verify upstream server certificates. Emitting the MITM cluster
// without a trust store would accept any upstream certificate
// unverified.
var ErrMITMCABundleMissing = errors.New(
	"L7-restricted rules require a CA bundle to verify upstream certificates; set SSL_CERT_FILE or install a system bundle",
)
