package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"go.jacobcolvin.com/terrarium/envoybin"
)

// The GOOS names of the platforms that have a provenance check.
const (
	osLinux  = "linux"
	osDarwin = "darwin"
)

// The repository whose workflow builds and attests the macOS binary, and
// the path of that workflow.
const (
	tetrateRepo     = "tetratelabs/archive-envoy"
	tetrateWorkflow = tetrateRepo + "/.github/workflows/build-macos.yaml"
)

// maxBody bounds the size of each document that the verifier reads into
// memory.
const maxBody = 16 << 20

var (
	// ErrNoProvenance means that the verifier has no provenance check
	// for the operating system of the platform.
	ErrNoProvenance = errors.New("no provenance check for platform")

	// ErrChecksum means that a hash in the manifest differs from the
	// hash that the publisher of the build lists.
	ErrChecksum = errors.New("published checksum differs from manifest")

	// ErrAttestation means that the binary has no valid build
	// attestation.
	ErrAttestation = errors.New("build attestation")

	// ErrCommit means that the binary does not report the commit of the
	// release tag.
	ErrCommit = errors.New("version commit differs from release tag")

	// ErrFetch means that a document did not download.
	ErrFetch = errors.New("fetch")

	// The commit in the output of `envoy --version`, for example
	// "envoy  version: <commit>/1.40.2/Clean/RELEASE/BoringSSL".
	versionCommit = regexp.MustCompile(`version: ([0-9a-f]{40})/`)

	// A full commit hash.
	commit = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// sources holds the URLs of the documents that the verifier compares a
// build with.
type sources struct {
	// The armored OpenPGP key that signs the checksums of an Envoy
	// release.
	signingKey string

	// The JSON index of the Tetrate archive. Its sha256sums object maps
	// the file name of each archive to its SHA-256.
	tetrateVersions string

	// A document whose body is the commit of the release tag.
	tagCommit string
}

// defaultSources returns the [sources] for the Envoy release version, for
// example "v1.40.2".
func defaultSources(version string) sources {
	return sources{
		signingKey: "https://raw.githubusercontent.com/envoyproxy/envoy/" + version +
			"/envoy-maintainers-public.key",
		tetrateVersions: "https://archive.tetratelabs.io/envoy/envoy-versions.json",
		tagCommit:       "https://api.github.com/repos/envoyproxy/envoy/commits/" + version,
	}
}

// runFunc runs the program name with args and returns its combined output.
type runFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

// runCommand is the [runFunc] that starts a process. Its error holds the
// output of the process.
func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	//nolint:gosec // the callers pass fixed program names and arguments.
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", name, err, bytes.TrimSpace(out))
	}

	return out, nil
}

// verifier checks the provenance of the build that a manifest pins for one
// platform.
type verifier struct {
	client *http.Client

	// Run starts the gh CLI and the envoy binary.
	run runFunc

	// Token authenticates the request for the commit of the release tag.
	// The request carries no credentials when token is empty.
	token string

	// Fingerprint is the fingerprint of the key that must sign the
	// checksums of the Envoy release.
	fingerprint string

	src      sources
	platform envoybin.Platform
	manifest envoybin.Manifest
}

// newVerifier returns a [verifier] that checks the build of m for platform
// against the public sources of the pinned version.
func newVerifier(m envoybin.Manifest, platform envoybin.Platform, token string) *verifier {
	return &verifier{
		client:      &http.Client{},
		run:         runCommand,
		token:       token,
		fingerprint: signingKeyFingerprint,
		src:         defaultSources(m.Version),
		platform:    platform,
		manifest:    m,
	}
}

// verify downloads the build for the platform and checks it in this order:
//
//  1. The download and the binary have the hashes in the manifest.
//  2. The publisher vouches for those hashes. For Linux, the signed
//     checksums of the Envoy release list the hash of the download. For
//     macOS, the index of the Tetrate archive lists the hash of the
//     download, and the binary has a build attestation from the Tetrate
//     workflow.
//  3. The binary reports the commit of the Envoy release tag as its
//     version commit.
//
// The binary runs only after the first two checks pass. The platform must
// be the platform of the host, because the host runs the binary. The
// method writes one line to out for each check that passes.
func (v *verifier) verify(ctx context.Context, out io.Writer) error {
	build, ok := v.manifest.Builds[v.platform]
	if !ok {
		return fmt.Errorf("%w: %s", envoybin.ErrUnsupportedPlatform, v.platform)
	}

	dir, err := os.MkdirTemp("", "envoymanifest-*")
	if err != nil {
		return fmt.Errorf("create temporary directory: %w", err)
	}

	defer os.RemoveAll(dir)

	inst := envoybin.NewInstaller(dir,
		envoybin.WithManifest(v.manifest),
		envoybin.WithPlatform(v.platform),
		envoybin.WithHTTPClient(v.client),
	)

	path, err := inst.Install(ctx)
	if err != nil {
		return fmt.Errorf("install envoy %s for %s: %w", v.manifest.Version, v.platform, err)
	}

	report(out, "download and binary have the hashes in the manifest")

	switch v.platform.OS {
	case osLinux:
		err = v.checkSignedChecksums(ctx, build)
		if err != nil {
			return err
		}

		report(out, "signed checksums of the Envoy release list the download")

	case osDarwin:
		err = v.checkTetrate(ctx, build, path)
		if err != nil {
			return err
		}

		report(out, "Tetrate archive lists the download and attests the binary")

	default:
		return fmt.Errorf("%w: %s", ErrNoProvenance, v.platform)
	}

	want, err := v.checkVersionCommit(ctx, path)
	if err != nil {
		return err
	}

	report(out, "binary reports the release commit "+want)

	return nil
}

// report writes one line about a check that passed. The line informs the
// reader of the job log and takes no part in the check, so report ignores
// a write that fails.
func report(out io.Writer, msg string) {
	_, _ = fmt.Fprintln(out, "ok: "+msg) //nolint:errcheck // informational output.
}

// checkSignedChecksums compares the download hash of build with the
// checksums.txt.asc file of the Envoy release. The file sits next to the
// download and must carry a signature of the pinned key.
func (v *verifier) checkSignedChecksums(ctx context.Context, build envoybin.Build) error {
	dir, name := splitURL(build.URL)

	signed, err := v.get(ctx, dir+"checksums.txt.asc", nil)
	if err != nil {
		return err
	}

	key, err := v.get(ctx, v.src.signingKey, nil)
	if err != nil {
		return err
	}

	sums, err := signedChecksums(signed, key, v.fingerprint)
	if err != nil {
		return err
	}

	return compare("checksums.txt.asc file of the Envoy release", name, sums, build.DownloadSHA256)
}

// checkTetrate compares the download hash of build with the index of the
// Tetrate archive. It then checks that the binary at path has a build
// attestation from the Tetrate workflow.
func (v *verifier) checkTetrate(ctx context.Context, build envoybin.Build, path string) error {
	_, name := splitURL(build.URL)

	data, err := v.get(ctx, v.src.tetrateVersions, nil)
	if err != nil {
		return err
	}

	var index struct {
		SHA256Sums map[string]string `json:"sha256sums"`
	}

	err = json.Unmarshal(data, &index)
	if err != nil {
		return fmt.Errorf("parse %s: %w", v.src.tetrateVersions, err)
	}

	err = compare("index of the Tetrate archive", name, index.SHA256Sums, build.DownloadSHA256)
	if err != nil {
		return err
	}

	_, err = v.run(ctx, "gh", "attestation", "verify", path,
		"--repo", tetrateRepo,
		"--signer-workflow", tetrateWorkflow,
	)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAttestation, err)
	}

	return nil
}

// checkVersionCommit runs the binary at path with --version and compares
// the commit in its output with the commit of the release tag. It returns
// that commit.
func (v *verifier) checkVersionCommit(ctx context.Context, path string) (string, error) {
	header := http.Header{"Accept": {"application/vnd.github.sha"}}
	if v.token != "" {
		header.Set("Authorization", "Bearer "+v.token)
	}

	data, err := v.get(ctx, v.src.tagCommit, header)
	if err != nil {
		return "", err
	}

	want := strings.TrimSpace(string(data))
	if !commit.MatchString(want) {
		return "", fmt.Errorf("%w: %s does not return a commit hash", ErrFetch, v.src.tagCommit)
	}

	out, err := v.run(ctx, path, "--version")
	if err != nil {
		return "", fmt.Errorf("read envoy version: %w", err)
	}

	match := versionCommit.FindSubmatch(out)
	if match == nil {
		return "", fmt.Errorf("%w: no commit in version output %q", ErrCommit, bytes.TrimSpace(out))
	}

	got := string(match[1])
	if got != want {
		return "", fmt.Errorf("%w: %s is at %s, binary reports %s",
			ErrCommit, v.manifest.Version, want, got)
	}

	return want, nil
}

// get returns the body of the document at url. It sends header with the
// request.
func (v *verifier) get(ctx context.Context, url string, header http.Header) ([]byte, error) {
	//nolint:gosec // G704: the URLs come from the manifest and from [sources].
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}

	maps.Copy(req.Header, header)

	resp, err := v.client.Do(req) //nolint:gosec // G704: see the request.
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}

	defer resp.Body.Close() //nolint:errcheck // read-only body.

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: GET %s: status %s", ErrFetch, url, resp.Status)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("%w: GET %s: %w", ErrFetch, url, err)
	}

	return data, nil
}

// compare checks that the checksum list sums holds the hash want for the
// file name. The argument list names the document of the publisher in
// each error.
func compare(list, name string, sums map[string]string, want string) error {
	got, ok := sums[name]
	if !ok {
		return fmt.Errorf("%w: the %s does not list %s", ErrChecksum, list, name)
	}

	if !strings.EqualFold(got, want) {
		return fmt.Errorf("%w: %s: manifest pins %s, the %s lists %s", ErrChecksum, name, want, list, got)
	}

	return nil
}

// splitURL splits url after its last slash into the directory, which keeps
// the slash, and the file name.
func splitURL(url string) (string, string) {
	i := strings.LastIndex(url, "/") + 1

	return url[:i], url[i:]
}
