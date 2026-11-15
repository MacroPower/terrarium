package envoybin

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ulikunitz/xz"
)

var (
	// ErrUnsupportedPlatform means that the manifest has no build for the
	// platform.
	ErrUnsupportedPlatform = errors.New("no managed envoy build for platform")

	// ErrNotInstalled means that no file exists at the install path.
	ErrNotInstalled = errors.New("envoy binary not installed")

	// ErrHashMismatch means that a download or an installed binary does
	// not have the SHA-256 that the manifest pins.
	ErrHashMismatch = errors.New("sha256 mismatch")

	// ErrDownload means that the HTTP download did not complete.
	ErrDownload = errors.New("download envoy")
)

// The name of the installed binary, and the path that ends the binary's
// entry in an archive.
const (
	binaryName    = "envoy"
	archiveBinary = "bin/" + binaryName
)

// Installer installs and verifies the Envoy binary that a [Manifest] pins
// for one [Platform].
//
// Create instances with [NewInstaller].
type Installer struct {
	client   *http.Client
	dir      string
	platform Platform
	manifest Manifest
}

// Option configures an [Installer].
//
// The following options are available:
//
//   - [WithManifest]
//   - [WithPlatform]
//   - [WithHTTPClient]
type Option func(*Installer)

// WithManifest is an [Option] that replaces [DefaultManifest].
func WithManifest(m Manifest) Option {
	return func(i *Installer) {
		i.manifest = m
	}
}

// WithPlatform is an [Option] that replaces [HostPlatform].
func WithPlatform(p Platform) Option {
	return func(i *Installer) {
		i.platform = p
	}
}

// WithHTTPClient is an [Option] that sets the client for downloads. The
// default client has no timeout, so only the context of
// [Installer.Install] bounds each download.
func WithHTTPClient(c *http.Client) Option {
	return func(i *Installer) {
		i.client = c
	}
}

// NewInstaller creates a new [Installer] that keeps binaries below dir.
func NewInstaller(dir string, opts ...Option) *Installer {
	i := &Installer{
		client:   &http.Client{},
		dir:      dir,
		platform: HostPlatform(),
		manifest: DefaultManifest(),
	}

	for _, opt := range opts {
		opt(i)
	}

	return i
}

// Path returns the install path of the binary without reading the file.
// It returns [ErrUnsupportedPlatform] when the manifest has no build for
// the platform.
func (i *Installer) Path() (string, error) {
	_, path, err := i.lookup()

	return path, err
}

// Verify hashes the installed binary and returns its path when the hash
// equals the manifest's hash.
//
// It returns [ErrUnsupportedPlatform] when the manifest has no build for
// the platform and [ErrNotInstalled] when the binary is missing. It
// returns [ErrHashMismatch] when the binary has a different hash.
func (i *Installer) Verify() (string, error) {
	build, path, err := i.lookup()
	if err != nil {
		return "", err
	}

	err = verifyFile(path, build.BinarySHA256)
	if err != nil {
		return "", err
	}

	return path, nil
}

// Install downloads the pinned build, checks it, and returns the path of
// the installed binary. When the install path already holds a binary with
// the pinned hash, Install returns the path without a download.
//
// Install writes to temporary files in the target directory and renames
// the checked binary into place. A download that stops early therefore
// leaves no file at the returned path.
//
// The context bounds the whole install. When the context ends during the
// download, during the extraction, or before the rename, Install removes
// its temporary files and returns an error that wraps the context's error.
//
// It returns [ErrUnsupportedPlatform] when the manifest has no build for
// the platform and [ErrDownload] when the download does not complete. It
// returns [ErrHashMismatch] when the download or the extracted binary has
// a different hash. A binary at the install path with a different hash
// also returns [ErrHashMismatch], and Install does not replace it.
func (i *Installer) Install(ctx context.Context) (string, error) {
	build, path, err := i.lookup()
	if err != nil {
		return "", err
	}

	err = verifyFile(path, build.BinarySHA256)
	if err == nil {
		return path, nil
	}

	if !errors.Is(err, ErrNotInstalled) {
		return "", err
	}

	dir := filepath.Dir(path)

	err = os.MkdirAll(dir, 0o755)
	if err != nil {
		return "", fmt.Errorf("create install directory: %w", err)
	}

	download, sum, err := fetch(ctx, i.client, build.URL, dir)
	if err != nil {
		return "", err
	}

	// After a successful rename the temporary name is gone, and the
	// remove does nothing.
	defer os.Remove(download)

	if sum != build.DownloadSHA256 {
		return "", mismatch(build.URL, build.DownloadSHA256, sum)
	}

	binary, sum, err := unpack(ctx, build, download, sum, dir)
	if err != nil {
		return "", err
	}

	defer os.Remove(binary)

	if sum != build.BinarySHA256 {
		return "", mismatch(binaryName+" from "+build.URL, build.BinarySHA256, sum)
	}

	err = os.Chmod(binary, 0o755)
	if err != nil {
		return "", fmt.Errorf("make binary executable: %w", err)
	}

	// The checks above do not read the context, so a context that ended
	// after the last read stops the install here.
	err = ctx.Err()
	if err != nil {
		return "", fmt.Errorf("move binary into place: %w", err)
	}

	err = os.Rename(binary, path)
	if err != nil {
		return "", fmt.Errorf("move binary into place: %w", err)
	}

	return path, nil
}

// lookup returns the build and the install path for the platform.
func (i *Installer) lookup() (Build, string, error) {
	build, ok := i.manifest.Builds[i.platform]
	if !ok {
		return Build{}, "", fmt.Errorf("%w: %s", ErrUnsupportedPlatform, i.platform)
	}

	return build, filepath.Join(i.dir, i.manifest.Version, i.platform.String(), binaryName), nil
}

// Measure downloads the build b with client and returns a copy of b whose
// DownloadSHA256 and BinarySHA256 are the hashes of the downloaded
// content. It ignores the hashes that b holds, so it tells nothing about
// the origin of the content. Call it only to compute the hashes of a new
// pin.
//
// It returns [ErrDownload] when the download does not complete.
func Measure(ctx context.Context, client *http.Client, b Build) (Build, error) {
	dir, err := os.MkdirTemp("", "envoybin-*")
	if err != nil {
		return Build{}, fmt.Errorf("create temporary directory: %w", err)
	}

	defer os.RemoveAll(dir)

	path, sum, err := fetch(ctx, client, b.URL, dir)
	if err != nil {
		return Build{}, err
	}

	b.DownloadSHA256 = sum

	_, b.BinarySHA256, err = unpack(ctx, b, path, sum, dir)
	if err != nil {
		return Build{}, err
	}

	return b, nil
}

// fetch downloads url with client into a temporary file in dir. It
// returns the path of the file and the hex SHA-256 of its content.
func fetch(ctx context.Context, client *http.Client, url, dir string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrDownload, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrDownload, err)
	}

	defer resp.Body.Close() //nolint:errcheck // read-only body.

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("%w: GET %s: status %s", ErrDownload, url, resp.Status)
	}

	path, sum, err := writeTemp(dir, resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("%w: GET %s: %w", ErrDownload, url, err)
	}

	return path, sum, nil
}

// unpack returns the path and the hex SHA-256 of the envoy binary in the
// download of b. The download is the file at path, and sum is its hex
// SHA-256. A [FormatBinary] download is the binary. For [FormatTarXz],
// unpack copies the binary into a temporary file in dir.
func unpack(ctx context.Context, b Build, path, sum, dir string) (string, string, error) {
	switch b.Format {
	case FormatBinary:
		return path, sum, nil

	case FormatTarXz:
		binary, binarySum, err := extractTarXz(ctx, path, dir)
		if err != nil {
			return "", "", fmt.Errorf("extract %s: %w", b.URL, err)
		}

		return binary, binarySum, nil

	default:
		return "", "", fmt.Errorf("%s: unknown download format %q", b.URL, b.Format)
	}
}

// extractTarXz copies the envoy binary out of the tar.xz archive into a
// temporary file in dir. It returns the path of the file and the hex
// SHA-256 of its content. It stops with the error of ctx when ctx ends
// before the copy completes.
func extractTarXz(ctx context.Context, archive, dir string) (string, string, error) {
	f, err := os.Open(archive)
	if err != nil {
		return "", "", fmt.Errorf("open archive: %w", err)
	}

	defer f.Close() //nolint:errcheck // read-only file.

	xr, err := xz.NewReader(bufio.NewReader(f))
	if err != nil {
		return "", "", fmt.Errorf("read xz header: %w", err)
	}

	tr := tar.NewReader(readerFunc(func(p []byte) (int, error) {
		err := ctx.Err()
		if err != nil {
			return 0, fmt.Errorf("interrupted: %w", err)
		}

		return xr.Read(p)
	}))

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return "", "", fmt.Errorf("no %s entry in archive", archiveBinary)
		}

		if err != nil {
			return "", "", fmt.Errorf("read archive: %w", err)
		}

		if hdr.Typeflag != tar.TypeReg || !isArchiveBinary(hdr.Name) {
			continue
		}

		return writeTemp(dir, tr)
	}
}

// readerFunc is a function that implements [io.Reader].
type readerFunc func(p []byte) (int, error)

// Read calls f.
func (f readerFunc) Read(p []byte) (int, error) {
	return f(p)
}

// isArchiveBinary reports whether name is the archive entry of the envoy
// binary. The archive keeps the entry below one top-level directory.
func isArchiveBinary(name string) bool {
	return name == archiveBinary || strings.HasSuffix(name, "/"+archiveBinary)
}

// writeTemp copies r into a new temporary file in dir and returns the
// path of the file and the hex SHA-256 of its content. It removes the
// file when the copy does not complete.
func writeTemp(dir string, r io.Reader) (string, string, error) {
	f, err := os.CreateTemp(dir, "."+binaryName+"-*.tmp")
	if err != nil {
		return "", "", fmt.Errorf("create temporary file: %w", err)
	}

	h := sha256.New()

	_, err = io.Copy(io.MultiWriter(f, h), r)
	if err == nil {
		err = f.Sync()
	}

	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}

	if err != nil {
		return "", "", errors.Join(fmt.Errorf("write %s: %w", f.Name(), err), os.Remove(f.Name()))
	}

	return f.Name(), hex.EncodeToString(h.Sum(nil)), nil
}

// verifyFile compares the SHA-256 of the file at path with want. It
// returns [ErrNotInstalled] when the file does not exist and
// [ErrHashMismatch] when the hashes differ.
func verifyFile(path, want string) error {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrNotInstalled, path)
	}

	if err != nil {
		return fmt.Errorf("open binary: %w", err)
	}

	defer f.Close() //nolint:errcheck // read-only file.

	h := sha256.New()

	_, err = io.Copy(h, f)
	if err != nil {
		return fmt.Errorf("hash %s: %w", path, err)
	}

	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return mismatch(path, want, got)
	}

	return nil
}

// mismatch returns an [ErrHashMismatch] that names the checked subject
// and both hashes.
func mismatch(subject, want, got string) error {
	return fmt.Errorf("%w: %s: want %s, got %s", ErrHashMismatch, subject, want, got)
}
