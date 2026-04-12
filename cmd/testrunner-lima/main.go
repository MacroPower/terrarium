package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func main() {
	fmt.Println("Run tests with: go test -v -count=1 -timeout=30m ./cmd/testrunner-lima")
}

// buildTestrunner cross-compiles the testrunner binary for linux/GOARCH
// and returns the path to the temporary output file. The caller is
// responsible for removing the file when done.
func buildTestrunner(ctx context.Context) (string, error) {
	goarch := runtime.GOARCH
	out := filepath.Join(os.TempDir(), "testrunner-linux")

	//nolint:gosec // args are controlled by build code.
	cmd := exec.CommandContext(ctx, "go", "build", "-o", out, "-ldflags=-s -w",
		"go.jacobcolvin.com/terrarium/cmd/testrunner")

	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("go build: %w", err)
	}

	return out, nil
}

// testCAKey is the private key for the shared e2e test CA. The
// corresponding certificate is baked into the NixOS image via
// security.pki.certificateFiles.
const testCAKey = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCdHmJODQHF0/yG
iMycO4atR9fXGWzDiS1Xa5T1d/8tiiiWv80K1klKXjXBACe8qacxW/TtyTa4DXtU
tytdy4MhlTJpHCkWTIk6t83Pj3YXm0nCndOMPQW/ZLwdrNDTWI1o3FPueQblI67Q
D1ceAfs3YCEGaRDp+xwqssgvgj5/boCMcibmHTz5kiEgwxfyeF/nEfrgsQyVMB4f
ODYzBnfHtvUPWukXTNs1/aevZY3RQ5gPWjTabmvksCSByI0Ss9TOYSXRNryT9a7B
76nBEsWfK3nHNfT2yYMBi62gN3XpzCZokaL9dN3vZ7gV1PAh9SZojFZtZBQ3PWR7
HnSWGKXdAgMBAAECgf9uWLQHWC7tHXGs8KiBlJUb4si6vy2j/1FIcFNbqaLwgD8V
HZKVN9AaDvy4QQfBuni4gJSlMPrHDd7YmgDUfJAfbusMVsfm7ndlirgHkYwWnzsH
GCALfupI1p4m1s+EL83l14Kky5ZNwM74fxXQ9tt4jAr0dZrN57XGRyxECi6fhFii
deScuwwqCW6wfdqahdWT+1x901YHCmIuvw50lB46R4k7Xx3cCjB7HHLHOmhzLbLl
i29606G6UWR72dGr6GeFaomOruJ/sFeMnAT60tu9lTV5QmeXoEJX0nSGeVPPgXJl
zb2ljPjM61By0txo52A65ABERheCVjoYSY7h7xECgYEAymF0940cxs4UTUBKS7kL
cefRWi1sBQ+G4xyfBl9mJcdh/Hgt5WYJOQ/kD24it650KY/K43x3Rp7cNDZrUNnN
IqViJMNQ0sSphSgKLzBP7uQrVBj1M9CkWGomGAXetNIT+pF71wRcutHImX6diA1H
teVsj7cZidQaLOnwWF3YyN8CgYEAxr8D9Fr2I7M4hiyXa/YBQyNdqmUOqF7KYSLe
sBZMxla64AWscfLd7FLVYy68sYBZvAJQ/7wmaWl1ibs1l/SUlsnRSOemx9ph90gT
goZu8+/3o7z+MIeUgsSNVnWJhVL98C0lFFAeMXA2r9jPGSUTiAQPF1rreOFJMmzj
ZWWo3MMCgYBQdwkzd9auMLefs2UW0F79jecODKs7I95EpFeSCBIsCScrY3kUEUqv
dmL9w5NoJqOm9rX7Vrxxxq3U0KJAhihqkwj/huy2sFyaRb4u3u2ZFP0pNbcgP99o
C+RTftn6WOB6qqdraR+ZY9l3NgFaW7VcW/ia93je9QbnPqhB6iZMTwKBgQCioAai
WhPyXmIwGCjHJIMf5r5sAUkfKIE9PoUtXPHxkWJUkQ/sJajGCXmmMMYiED5dAyA4
QkLEGpEc5F0UPAOh5v4jQ7pK6j0jVIzyTwJXBNKD3s+38hjpb9+fEYo32BMGBkrC
9lPebE2zUhsUHix/LaMTn0fyn5V/d24SuD6WdQKBgQCMRTViy0HfOI+E51k47ZXC
OKM387ppeDLZ63OzI/NnZmZHVwJiuia7v1kieSqF9AZN4Ttam9xioBJZL3Kl9rsN
2VgYX/6X/yr0P4qQ3ncexVMpua6H6LlB1pdw76wMod/0sCBpT+xML5zJLeYVFBUP
OhAlU0aSuY8qaUtgUd9wxQ==
-----END PRIVATE KEY-----`

// testCACert is the public certificate for the shared e2e test CA.
// It is baked into the NixOS trust store via
// security.pki.certificateFiles and written to the VM at
// /tmp/test-ca.pem for nginx cert signing.
const testCACert = `-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIUBC5S7BcMBCj2jX+HZBaxgKgRNGQwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjA0MTAyMTI0MDNaFw0zNjA0MDcy
MTI0MDNaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCdHmJODQHF0/yGiMycO4atR9fXGWzDiS1Xa5T1d/8tiiiWv80K
1klKXjXBACe8qacxW/TtyTa4DXtUtytdy4MhlTJpHCkWTIk6t83Pj3YXm0nCndOM
PQW/ZLwdrNDTWI1o3FPueQblI67QD1ceAfs3YCEGaRDp+xwqssgvgj5/boCMcibm
HTz5kiEgwxfyeF/nEfrgsQyVMB4fODYzBnfHtvUPWukXTNs1/aevZY3RQ5gPWjTa
bmvksCSByI0Ss9TOYSXRNryT9a7B76nBEsWfK3nHNfT2yYMBi62gN3XpzCZokaL9
dN3vZ7gV1PAh9SZojFZtZBQ3PWR7HnSWGKXdAgMBAAGjUzBRMB0GA1UdDgQWBBSh
73q9XcJxqUC4lDvy0+ighKDsvzAfBgNVHSMEGDAWgBSh73q9XcJxqUC4lDvy0+ig
hKDsvzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBe7xL1s9Yd
xCfaGp9MY/djnY7ooMw8tr8vv5jsJPv9ivGHyL+Pabxg9vRN821TLtuvqO3KB1Se
AhObGXF2acojtPsOt1at6D9wqCanEOKyIlx8dr1NCbQVmwsEReJC1YLe1z/o+Dsx
X0cpJ3Xy5WhHo3JWCoVdQY/I4qonhYCnLQzx6xnse1MKooeTkJbfRA9LikysuYB6
ZiLfLCRHsXaPNUX0aNC8eKzsq/QycVKk1v0b4L5p5ROraAAa5xIFz1xbfascp3pg
yVJKpXIx3Kad+LPXRo07ALfkuS/TxuIobzE1rQYlI/gLzVjodI7/fwbiUdKjTJzp
ssNR5atdtwy+
-----END CERTIFICATE-----`

// defaultNginxConf serves static "OK" on ports 80 and 443.
const defaultNginxConf = `server {
    listen 80;
    listen 443 ssl;
    ssl_certificate /tmp/nginx-cert.pem;
    ssl_certificate_key /tmp/nginx-key.pem;
    location / {
        return 200 "OK\n";
        add_header Content-Type text/plain;
    }
}`

// headerEchoNginxConf echoes the X-Token header value in the response body.
const headerEchoNginxConf = `server {
    listen 80;
    listen 443 ssl;
    ssl_certificate /tmp/nginx-cert.pem;
    ssl_certificate_key /tmp/nginx-key.pem;
    location / {
        return 200 "TOKEN=$http_x_token\n";
        add_header Content-Type text/plain;
    }
}`

// l7NginxConf serves different responses based on the request path.
const l7NginxConf = `server {
    listen 80;
    listen 443 ssl;
    ssl_certificate /tmp/nginx-cert.pem;
    ssl_certificate_key /tmp/nginx-key.pem;

    location /allowed/ {
        return 200 "ALLOWED_PATH\n";
        add_header Content-Type text/plain;
    }
    location /denied/ {
        return 200 "DENIED_PATH\n";
        add_header Content-Type text/plain;
    }
    location / {
        return 200 "ROOT_PATH\n";
        add_header Content-Type text/plain;
    }
}`

// nginxConfOnPort returns an nginx config that serves "OK" on a single
// TLS port.
func nginxConfOnPort(port int) string {
	return fmt.Sprintf(`server {
    listen %d ssl;
    ssl_certificate /tmp/nginx-cert.pem;
    ssl_certificate_key /tmp/nginx-key.pem;
    location / {
        return 200 "OK\n";
        add_header Content-Type text/plain;
    }
}`, port)
}
