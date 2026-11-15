package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"
	"go.jacobcolvin.com/terrarium/envoybin"
)

const (
	testVersion = "v9.9.9"
	testCommit  = "0123456789abcdef0123456789abcdef01234567"
	testToken   = "test-token"

	linuxName  = "envoy-9.9.9-linux-x86_64"
	darwinName = "envoy-v9.9.9-darwin-arm64.tar.xz"
)

var (
	linuxAMD64  = envoybin.Platform{OS: "linux", Arch: "amd64"}
	darwinARM64 = envoybin.Platform{OS: "darwin", Arch: "arm64"}

	testBinary = []byte("fake envoy binary")
)

// sha256Hex returns the lowercase hex SHA-256 of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}

// tarXz returns a tar.xz archive that holds binary as its bin/envoy entry
// below one top-level directory.
func tarXz(t *testing.T, binary []byte) []byte {
	t.Helper()

	var archive bytes.Buffer

	tw := tar.NewWriter(&archive)

	require.NoError(t, tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     "envoy-" + testVersion + "/bin/envoy",
		Mode:     0o755,
		Size:     int64(len(binary)),
	}))

	_, err := tw.Write(binary)
	require.NoError(t, err)
	require.NoError(t, tw.Close())

	var buf bytes.Buffer

	xw, err := xz.NewWriter(&buf)
	require.NoError(t, err)

	_, err = xw.Write(archive.Bytes())
	require.NoError(t, err)
	require.NoError(t, xw.Close())

	return buf.Bytes()
}

// call is one program start that a [release] recorded.
type call struct {
	name string
	args []string
}

// release is a test double for the publishers of one Envoy version. It
// serves the documents in docs over HTTP and stands in for the gh CLI and
// for the envoy binary.
type release struct {
	t *testing.T

	// docs maps a URL path to the body of its document. A path without
	// an entry answers with status 404.
	docs map[string][]byte

	// attestation is the error of the gh CLI.
	attestation error

	// runErr is the error of the envoy binary.
	runErr error

	// version is the output of the envoy binary for --version.
	version string

	// drop is a URL path. The server closes the connection of a request
	// for it and sends no answer.
	drop string

	srv   *httptest.Server
	calls []call
}

// newRelease starts a [release] whose documents vouch for the builds of
// its manifest. The key signs the checksums of the Linux build.
func newRelease(t *testing.T, key *signer) *release {
	t.Helper()

	archive := tarXz(t, testBinary)

	versions, err := json.Marshal(map[string]any{
		"latestVersion": testVersion,
		"sha256sums": map[string]string{
			darwinName:              sha256Hex(archive),
			"envoy-other-build.txz": sha256Hex(testBinary),
		},
	})
	require.NoError(t, err)

	r := &release{
		t: t,
		docs: map[string][]byte{
			"/release/" + linuxName:        testBinary,
			"/release/checksums.txt.asc":   key.sign(t, sha256Hex(testBinary)+"  "+linuxName+"\n"),
			"/key":                         key.public,
			"/tetrate/" + darwinName:       archive,
			"/tetrate/envoy-versions.json": versions,
			"/commit":                      []byte(testCommit + "\n"),
		},
		version: "\nenvoy  version: " + testCommit + "/9.9.9/Clean/RELEASE/BoringSSL\n",
	}

	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)

	return r
}

// serve answers a request with the document of its path.
func (r *release) serve(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/commit" {
		assert.Equal(r.t, "application/vnd.github.sha", req.Header.Get("Accept"))
		assert.Equal(r.t, "Bearer "+testToken, req.Header.Get("Authorization"))
	} else {
		assert.Empty(r.t, req.Header.Get("Authorization"), "token sent to %s", req.URL.Path)
	}

	if req.URL.Path == r.drop {
		conn, _, err := http.NewResponseController(w).Hijack()
		if assert.NoError(r.t, err) {
			assert.NoError(r.t, conn.Close())
		}

		return
	}

	body, ok := r.docs[req.URL.Path]
	if !ok {
		http.NotFound(w, req)

		return
	}

	_, err := w.Write(body)
	assert.NoError(r.t, err)
}

// run is the [runFunc] of the release. It records each call. For the gh
// CLI it returns the attestation error. Every other program is the envoy
// binary, which must hold [testBinary]. It answers with the version
// output, or with runErr when the release has one.
func (r *release) run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, call{name: name, args: args})

	if name == "gh" {
		return nil, r.attestation
	}

	data, err := os.ReadFile(name)
	require.NoError(r.t, err)
	assert.Equal(r.t, testBinary, data)

	info, err := os.Stat(name)
	require.NoError(r.t, err)
	assert.Equal(r.t, os.FileMode(0o755), info.Mode().Perm())

	if r.runErr != nil {
		return nil, r.runErr
	}

	return []byte(r.version), nil
}

// manifest returns a manifest whose builds are the downloads of the
// release.
func (r *release) manifest() envoybin.Manifest {
	archive := r.docs["/tetrate/"+darwinName]

	return envoybin.Manifest{
		Version: testVersion,
		Builds: map[envoybin.Platform]envoybin.Build{
			linuxAMD64: {
				URL:            r.srv.URL + "/release/" + linuxName,
				Format:         envoybin.FormatBinary,
				DownloadSHA256: sha256Hex(testBinary),
				BinarySHA256:   sha256Hex(testBinary),
			},
			darwinARM64: {
				URL:            r.srv.URL + "/tetrate/" + darwinName,
				Format:         envoybin.FormatTarXz,
				DownloadSHA256: sha256Hex(archive),
				BinarySHA256:   sha256Hex(testBinary),
			},
		},
	}
}

// verifier returns a [verifier] for platform that reads every document
// from the release.
func (r *release) verifier(platform envoybin.Platform, fingerprint string) *verifier {
	return &verifier{
		client:      r.srv.Client(),
		run:         r.run,
		token:       testToken,
		fingerprint: fingerprint,
		src: sources{
			signingKey:      r.srv.URL + "/key",
			tetrateVersions: r.srv.URL + "/tetrate/envoy-versions.json",
			tagCommit:       r.srv.URL + "/commit",
		},
		platform: platform,
		manifest: r.manifest(),
	}
}

// signer is an OpenPGP key pair for the checksums of a [release].
type signer struct {
	sign        func(t *testing.T, text string) []byte
	fingerprint string
	public      []byte
}

// newSigner returns a [signer] with a new key pair.
func newSigner(t *testing.T) *signer {
	t.Helper()

	key := newKey(t)

	return &signer{
		sign: func(t *testing.T, text string) []byte {
			t.Helper()

			return clearsigned(t, key, text)
		},
		fingerprint: fingerprintOf(key),
		public:      armoredKeys(t, key),
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	key := newSigner(t)
	other := newSigner(t)

	errExec := errors.New("exec format error")

	ghCall := func(path string) call {
		return call{name: "gh", args: []string{
			"attestation", "verify", path,
			"--repo", "tetratelabs/archive-envoy",
			"--signer-workflow", "tetratelabs/archive-envoy/.github/workflows/build-macos.yaml",
		}}
	}

	tests := map[string]struct {
		// change edits the release and the verifier before the check.
		change   func(t *testing.T, r *release, v *verifier)
		err      error
		msg      string
		platform envoybin.Platform
		// wantRun reports whether the envoy binary runs.
		wantRun bool
	}{
		"linux build": {
			platform: linuxAMD64,
			wantRun:  true,
		},
		"darwin build": {
			platform: darwinARM64,
			wantRun:  true,
		},
		"manifest pins another download hash": {
			platform: linuxAMD64,
			change: func(_ *testing.T, _ *release, v *verifier) {
				b := v.manifest.Builds[linuxAMD64]
				b.DownloadSHA256 = sha256Hex([]byte("another download"))
				v.manifest.Builds[linuxAMD64] = b
			},
			err: envoybin.ErrHashMismatch,
		},
		"manifest pins another binary hash": {
			platform: darwinARM64,
			change: func(_ *testing.T, _ *release, v *verifier) {
				b := v.manifest.Builds[darwinARM64]
				b.BinarySHA256 = sha256Hex([]byte("another binary"))
				v.manifest.Builds[darwinARM64] = b
			},
			err: envoybin.ErrHashMismatch,
		},
		"build is not published": {
			platform: darwinARM64,
			change: func(_ *testing.T, r *release, _ *verifier) {
				delete(r.docs, "/tetrate/"+darwinName)
			},
			err: envoybin.ErrDownload,
			msg: "status 404",
		},
		"manifest without a build for the platform": {
			platform: envoybin.Platform{OS: "linux", Arch: "riscv64"},
			err:      envoybin.ErrUnsupportedPlatform,
			msg:      "linux-riscv64",
		},
		"platform without a provenance check": {
			platform: envoybin.Platform{OS: "freebsd", Arch: "amd64"},
			change: func(_ *testing.T, _ *release, v *verifier) {
				v.manifest.Builds[v.platform] = v.manifest.Builds[linuxAMD64]
			},
			err: ErrNoProvenance,
			msg: "freebsd-amd64",
		},
		"signed checksums list another hash": {
			platform: linuxAMD64,
			change: func(t *testing.T, r *release, _ *verifier) {
				t.Helper()

				r.docs["/release/checksums.txt.asc"] = key.sign(t,
					sha256Hex([]byte("another download"))+"  "+linuxName+"\n")
			},
			err: ErrChecksum,
			msg: "manifest pins " + sha256Hex(testBinary),
		},
		"signed checksums do not list the download": {
			platform: linuxAMD64,
			change: func(t *testing.T, r *release, _ *verifier) {
				t.Helper()

				r.docs["/release/checksums.txt.asc"] = key.sign(t,
					sha256Hex(testBinary)+"  envoy-contrib-9.9.9-linux-x86_64\n")
			},
			err: ErrChecksum,
			msg: "does not list " + linuxName,
		},
		"checksums carry the signature of another key": {
			platform: linuxAMD64,
			change: func(t *testing.T, r *release, _ *verifier) {
				t.Helper()

				r.docs["/release/checksums.txt.asc"] = other.sign(t, sha256Hex(testBinary)+"  "+linuxName+"\n")
			},
			err: ErrSignature,
		},
		"release serves another signing key": {
			platform: linuxAMD64,
			change: func(t *testing.T, r *release, _ *verifier) {
				t.Helper()

				r.docs["/release/checksums.txt.asc"] = other.sign(t, sha256Hex(testBinary)+"  "+linuxName+"\n")
				r.docs["/key"] = other.public
			},
			err: ErrSigningKey,
		},
		"release has no checksums": {
			platform: linuxAMD64,
			change: func(_ *testing.T, r *release, _ *verifier) {
				delete(r.docs, "/release/checksums.txt.asc")
			},
			err: ErrFetch,
			msg: "/release/checksums.txt.asc: status 404",
		},
		"signing key is missing": {
			platform: linuxAMD64,
			change: func(_ *testing.T, r *release, _ *verifier) {
				delete(r.docs, "/key")
			},
			err: ErrFetch,
			msg: "/key: status 404",
		},
		"signing key request fails": {
			platform: linuxAMD64,
			change: func(_ *testing.T, r *release, _ *verifier) {
				r.drop = "/key"
			},
			err: ErrFetch,
			msg: `/key": EOF`,
		},
		"tetrate index is missing": {
			platform: darwinARM64,
			change: func(_ *testing.T, r *release, _ *verifier) {
				delete(r.docs, "/tetrate/envoy-versions.json")
			},
			err: ErrFetch,
			msg: "/tetrate/envoy-versions.json: status 404",
		},
		"tetrate index lists another hash": {
			platform: darwinARM64,
			change: func(_ *testing.T, r *release, _ *verifier) {
				r.docs["/tetrate/envoy-versions.json"] = []byte(
					`{"sha256sums":{"` + darwinName + `":"` + sha256Hex([]byte("another download")) + `"}}`)
			},
			err: ErrChecksum,
			msg: "index of the Tetrate archive lists " + sha256Hex([]byte("another download")),
		},
		"tetrate index does not list the download": {
			platform: darwinARM64,
			change: func(_ *testing.T, r *release, _ *verifier) {
				r.docs["/tetrate/envoy-versions.json"] = []byte(`{"sha256sums":{}}`)
			},
			err: ErrChecksum,
			msg: "does not list " + darwinName,
		},
		"tetrate index is not JSON": {
			platform: darwinARM64,
			change: func(_ *testing.T, r *release, _ *verifier) {
				r.docs["/tetrate/envoy-versions.json"] = []byte("<html>")
			},
			msg: "/tetrate/envoy-versions.json",
		},
		"binary has no attestation": {
			platform: darwinARM64,
			change: func(_ *testing.T, r *release, _ *verifier) {
				r.attestation = errors.New("gh: exit status 1: HTTP 404: Not Found")
			},
			err: ErrAttestation,
			msg: "HTTP 404",
		},
		"release tag has another commit": {
			platform: linuxAMD64,
			change: func(_ *testing.T, r *release, _ *verifier) {
				r.docs["/commit"] = []byte(strings.Repeat("f", 40))
			},
			err:     ErrCommit,
			msg:     "binary reports " + testCommit,
			wantRun: true,
		},
		"binary reports another commit": {
			platform: darwinARM64,
			change: func(_ *testing.T, r *release, _ *verifier) {
				r.version = "envoy  version: " + strings.Repeat("e", 40) + "/9.9.9/Modified/DEBUG/BoringSSL\n"
			},
			err:     ErrCommit,
			msg:     testVersion + " is at " + testCommit,
			wantRun: true,
		},
		"binary reports no commit": {
			platform: linuxAMD64,
			change: func(_ *testing.T, r *release, _ *verifier) {
				r.version = "envoy  version: 0123456/9.9.9/Clean/RELEASE/BoringSSL\n"
			},
			err:     ErrCommit,
			msg:     "no commit in version output",
			wantRun: true,
		},
		"binary does not run": {
			platform: linuxAMD64,
			change: func(_ *testing.T, r *release, _ *verifier) {
				r.runErr = errExec
			},
			err:     errExec,
			msg:     "read envoy version: exec format error",
			wantRun: true,
		},
		"release tag is missing": {
			platform: linuxAMD64,
			change: func(_ *testing.T, r *release, _ *verifier) {
				delete(r.docs, "/commit")
			},
			err: ErrFetch,
			msg: "/commit: status 404",
		},
		"release tag answer is not a commit": {
			platform: linuxAMD64,
			change: func(_ *testing.T, r *release, _ *verifier) {
				r.docs["/commit"] = []byte(`{"sha":"` + testCommit + `"}`)
			},
			err: ErrFetch,
			msg: "does not return a commit hash",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRelease(t, key)
			v := r.verifier(tc.platform, key.fingerprint)

			if tc.change != nil {
				tc.change(t, r, v)
			}

			var out bytes.Buffer

			err := v.verify(t.Context(), &out)

			var envoyRuns []call

			for _, c := range r.calls {
				if c.name != "gh" {
					envoyRuns = append(envoyRuns, c)
				}
			}

			if tc.wantRun {
				require.Len(t, envoyRuns, 1)
				assert.Equal(t, []string{"--version"}, envoyRuns[0].args)
			} else {
				assert.Empty(t, envoyRuns, "the binary ran before its provenance checks passed")
			}

			if tc.err != nil || tc.msg != "" {
				require.Error(t, err)

				if tc.err != nil {
					require.ErrorIs(t, err, tc.err)
				}

				require.ErrorContains(t, err, tc.msg)
				assert.NotContains(t, out.String(), testCommit)

				return
			}

			require.NoError(t, err)
			assert.Contains(t, out.String(), "ok: binary reports the release commit "+testCommit+"\n")

			path := envoyRuns[0].name

			if tc.platform == darwinARM64 {
				// The attestation covers the binary that then runs.
				assert.Equal(t, []call{ghCall(path), {name: path, args: []string{"--version"}}}, r.calls)
			} else {
				assert.Equal(t, []call{{name: path, args: []string{"--version"}}}, r.calls)
			}

			// The verifier removes the binary after the check.
			assert.NoFileExists(t, path)
		})
	}
}

// TestVerifyWithoutToken checks that the request for the commit of the
// release tag carries no credentials when the verifier has no token.
func TestVerifyWithoutToken(t *testing.T) {
	t.Parallel()

	var auth []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		auth = req.Header.Values("Authorization")

		_, err := w.Write([]byte(testCommit))
		assert.NoError(t, err)
	}))
	t.Cleanup(srv.Close)

	v := &verifier{
		client: srv.Client(),
		run: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("version: " + testCommit + "/"), nil
		},
		src:      sources{tagCommit: srv.URL},
		manifest: envoybin.Manifest{Version: testVersion},
	}

	got, err := v.checkVersionCommit(t.Context(), "envoy")
	require.NoError(t, err)
	assert.Equal(t, testCommit, got)
	assert.Empty(t, auth)
}

// TestNewVerifier checks that the verifier of the verify command reads
// the public sources of the pinned version, requires the pinned signing
// key, and starts processes.
func TestNewVerifier(t *testing.T) {
	t.Parallel()

	m := envoybin.Manifest{
		Version: testVersion,
		Builds: map[envoybin.Platform]envoybin.Build{
			darwinARM64: {URL: "https://example.com/" + darwinName, Format: envoybin.FormatTarXz},
		},
	}

	v := newVerifier(m, darwinARM64, testToken)

	assert.Equal(t, signingKeyFingerprint, v.fingerprint)
	assert.Equal(t, defaultSources(testVersion), v.src)
	assert.Equal(t, testToken, v.token)
	assert.Equal(t, darwinARM64, v.platform)
	assert.Equal(t, m, v.manifest)
	assert.NotNil(t, v.client)

	// Two func values compare only by their code pointers.
	require.NotNil(t, v.run)
	assert.Equal(t, reflect.ValueOf(runCommand).Pointer(), reflect.ValueOf(v.run).Pointer())
}

func TestDefaultSources(t *testing.T) {
	t.Parallel()

	assert.Equal(t, sources{
		signingKey:      "https://raw.githubusercontent.com/envoyproxy/envoy/v1.40.2/envoy-maintainers-public.key",
		tetrateVersions: "https://archive.tetratelabs.io/envoy/envoy-versions.json",
		tagCommit:       "https://api.github.com/repos/envoyproxy/envoy/commits/v1.40.2",
	}, defaultSources("v1.40.2"))
}

func TestRunCommand(t *testing.T) {
	t.Parallel()

	out, err := runCommand(t.Context(), "sh", "-c", "echo stdout; echo stderr >&2")
	require.NoError(t, err)
	assert.Equal(t, "stdout\nstderr\n", string(out))

	_, err = runCommand(t.Context(), "sh", "-c", "echo no attestation >&2; exit 3")
	require.Error(t, err)
	require.ErrorContains(t, err, "sh: exit status 3: no attestation")
}
