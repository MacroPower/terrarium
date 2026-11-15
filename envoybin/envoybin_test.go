package envoybin_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"

	"go.jacobcolvin.com/terrarium/envoybin"
)

const testVersion = "v9.9.9"

var (
	testPlatform = envoybin.Platform{OS: "testos", Arch: "testarch"}
	testBinary   = []byte("#!/bin/sh\necho fake envoy\n")
)

// sha256Hex returns the lowercase hex SHA-256 of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:])
}

// tarEntry is one entry of a test archive. An entry without a link target
// is a regular file that holds data.
type tarEntry struct {
	name string
	link string
	data []byte
}

// tarXz returns a tar.xz archive that holds entries in the given order.
func tarXz(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()

	var buf bytes.Buffer

	tw := tar.NewWriter(&buf)

	for _, e := range entries {
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     e.name,
			Mode:     0o755,
			Size:     int64(len(e.data)),
		}

		if e.link != "" {
			hdr.Typeflag = tar.TypeSymlink
			hdr.Linkname = e.link
		}

		require.NoError(t, tw.WriteHeader(hdr))

		_, err := tw.Write(e.data)
		require.NoError(t, err)
	}

	require.NoError(t, tw.Close())

	return xzBytes(t, buf.Bytes())
}

// xzBytes returns data as an xz stream.
func xzBytes(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer

	xw, err := xz.NewWriter(&buf)
	require.NoError(t, err)

	_, err = xw.Write(data)
	require.NoError(t, err)
	require.NoError(t, xw.Close())

	return buf.Bytes()
}

// roundTripFunc is a function that implements [http.RoundTripper].
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip calls f.
func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// readerFunc is a function that implements [io.Reader].
type readerFunc func(p []byte) (int, error)

// Read calls f.
func (f readerFunc) Read(p []byte) (int, error) {
	return f(p)
}

// serveBytes starts an HTTP server that answers every request with body.
// The returned counter holds the number of requests.
func serveBytes(t *testing.T, body []byte) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var requests atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)

		_, err := w.Write(body)
		assert.NoError(t, err)
	}))
	t.Cleanup(srv.Close)

	return srv, &requests
}

// respondWith returns a response function that writes body.
func respondWith(body []byte) func(t *testing.T, w http.ResponseWriter) {
	return func(t *testing.T, w http.ResponseWriter) {
		t.Helper()

		_, err := w.Write(body)
		assert.NoError(t, err)
	}
}

// newInstaller returns an installer for [testPlatform] in a new temporary
// directory, with build as the only entry of the manifest. It also
// returns the install path of the binary.
func newInstaller(
	t *testing.T,
	build envoybin.Build,
	opts ...envoybin.Option,
) (*envoybin.Installer, string) {
	t.Helper()

	dir := t.TempDir()

	opts = append([]envoybin.Option{
		envoybin.WithPlatform(testPlatform),
		envoybin.WithManifest(envoybin.Manifest{
			Version: testVersion,
			Builds:  map[envoybin.Platform]envoybin.Build{testPlatform: build},
		}),
	}, opts...)

	return envoybin.NewInstaller(dir, opts...), filepath.Join(dir, testVersion, "testos-testarch", "envoy")
}

// requireNothingInstalled asserts that the install directory of path
// holds no binary and no temporary file.
func requireNothingInstalled(t *testing.T, path string) {
	t.Helper()

	entries, err := os.ReadDir(filepath.Dir(path))
	if !os.IsNotExist(err) {
		require.NoError(t, err)
	}

	assert.Empty(t, entries)
}

func TestInstall(t *testing.T) {
	t.Parallel()

	top := "envoy-" + testVersion + "-testos-testarch/"

	archive := tarXz(t,
		tarEntry{name: top + "README.md", data: []byte("not the binary")},
		tarEntry{name: top + "bin/envoy", data: testBinary},
	)

	// Only a regular file counts as the binary, so the installer skips
	// the symlink of the same name.
	linkFirst := tarXz(t,
		tarEntry{name: "other/bin/envoy", link: "../../" + top + "bin/envoy"},
		tarEntry{name: top + "bin/envoy", data: testBinary},
	)

	// The entry name bin/envoy without a directory before it also names
	// the binary.
	topLevel := tarXz(t, tarEntry{name: "bin/envoy", data: testBinary})

	// The name of the binary must be the whole path element bin, so the
	// installer skips sbin/envoy.
	suffixFirst := tarXz(t,
		tarEntry{name: top + "sbin/envoy", data: []byte("not the binary")},
		tarEntry{name: top + "bin/envoy", data: testBinary},
	)

	tests := map[string]struct {
		format envoybin.Format
		body   []byte
	}{
		"bare binary": {
			format: envoybin.FormatBinary,
			body:   testBinary,
		},
		"tar.xz archive": {
			format: envoybin.FormatTarXz,
			body:   archive,
		},
		"tar.xz archive with a symlink before the binary": {
			format: envoybin.FormatTarXz,
			body:   linkFirst,
		},
		"tar.xz archive with the binary at the top level": {
			format: envoybin.FormatTarXz,
			body:   topLevel,
		},
		"tar.xz archive with a file whose name only ends in bin/envoy": {
			format: envoybin.FormatTarXz,
			body:   suffixFirst,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv, requests := serveBytes(t, tc.body)
			inst, want := newInstaller(t, envoybin.Build{
				URL:            srv.URL + "/envoy",
				Format:         tc.format,
				DownloadSHA256: sha256Hex(tc.body),
				BinarySHA256:   sha256Hex(testBinary),
			})

			got, err := inst.Install(t.Context())
			require.NoError(t, err)
			assert.Equal(t, want, got)

			data, err := os.ReadFile(got)
			require.NoError(t, err)
			assert.Equal(t, testBinary, data)

			info, err := os.Stat(got)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())

			entries, err := os.ReadDir(filepath.Dir(got))
			require.NoError(t, err)
			assert.Len(t, entries, 1, "temporary files remain next to the binary")

			verified, err := inst.Verify()
			require.NoError(t, err)
			assert.Equal(t, want, verified)

			path, err := inst.Path()
			require.NoError(t, err)
			assert.Equal(t, want, path)

			// The binary is in place, so a second install does not
			// download.
			got, err = inst.Install(t.Context())
			require.NoError(t, err)
			assert.Equal(t, want, got)
			assert.Equal(t, int64(1), requests.Load())
		})
	}
}

func TestInstallErrors(t *testing.T) {
	t.Parallel()

	archive := tarXz(t, tarEntry{name: "envoy/bin/envoy", data: testBinary})
	noBinary := tarXz(t, tarEntry{name: "envoy/bin/not-envoy", data: testBinary})
	onlyLink := tarXz(t, tarEntry{name: "envoy/bin/envoy", link: "../libexec/envoy"})
	notTar := xzBytes(t, bytes.Repeat([]byte("not a tar archive\n"), 64))

	tests := map[string]struct {
		respond func(t *testing.T, w http.ResponseWriter)
		err     error
		// url replaces the URL of the test server, which then expects
		// no request.
		url   string
		msg   string
		build envoybin.Build
	}{
		"download hash differs": {
			build: envoybin.Build{
				Format:         envoybin.FormatBinary,
				DownloadSHA256: sha256Hex([]byte("another download")),
				BinarySHA256:   sha256Hex(testBinary),
			},
			respond: respondWith(testBinary),
			err:     envoybin.ErrHashMismatch,
		},
		"binary hash differs": {
			build: envoybin.Build{
				Format:         envoybin.FormatTarXz,
				DownloadSHA256: sha256Hex(archive),
				BinarySHA256:   sha256Hex([]byte("another binary")),
			},
			respond: respondWith(archive),
			err:     envoybin.ErrHashMismatch,
		},
		"status not found": {
			build: envoybin.Build{
				Format:         envoybin.FormatBinary,
				DownloadSHA256: sha256Hex(testBinary),
				BinarySHA256:   sha256Hex(testBinary),
			},
			respond: func(_ *testing.T, w http.ResponseWriter) {
				w.WriteHeader(http.StatusNotFound)
			},
			err: envoybin.ErrDownload,
			msg: "404",
		},
		"download stops early": {
			build: envoybin.Build{
				Format:         envoybin.FormatBinary,
				DownloadSHA256: sha256Hex(testBinary),
				BinarySHA256:   sha256Hex(testBinary),
			},
			// The server closes the connection when the handler writes
			// fewer bytes than Content-Length announces.
			respond: func(t *testing.T, w http.ResponseWriter) {
				t.Helper()

				w.Header().Set("Content-Length", strconv.Itoa(len(testBinary)))

				_, err := w.Write(testBinary[:len(testBinary)/2])
				assert.NoError(t, err)
			},
			err: envoybin.ErrDownload,
		},
		"malformed URL": {
			build: envoybin.Build{
				Format:         envoybin.FormatBinary,
				DownloadSHA256: sha256Hex(testBinary),
				BinarySHA256:   sha256Hex(testBinary),
			},
			url: "://bad",
			err: envoybin.ErrDownload,
			msg: "missing protocol scheme",
		},
		"archive with only a symlink named like the binary": {
			build: envoybin.Build{
				Format:         envoybin.FormatTarXz,
				DownloadSHA256: sha256Hex(onlyLink),
				BinarySHA256:   sha256Hex(testBinary),
			},
			respond: respondWith(onlyLink),
			msg:     "no bin/envoy entry",
		},
		"xz stream is not a tar archive": {
			build: envoybin.Build{
				Format:         envoybin.FormatTarXz,
				DownloadSHA256: sha256Hex(notTar),
				BinarySHA256:   sha256Hex(testBinary),
			},
			respond: respondWith(notTar),
			msg:     "read archive",
		},
		"archive without the binary": {
			build: envoybin.Build{
				Format:         envoybin.FormatTarXz,
				DownloadSHA256: sha256Hex(noBinary),
				BinarySHA256:   sha256Hex(testBinary),
			},
			respond: respondWith(noBinary),
			msg:     "no bin/envoy entry",
		},
		"download is not an archive": {
			build: envoybin.Build{
				Format:         envoybin.FormatTarXz,
				DownloadSHA256: sha256Hex(testBinary),
				BinarySHA256:   sha256Hex(testBinary),
			},
			respond: respondWith(testBinary),
			msg:     "read xz header",
		},
		"unknown format": {
			build: envoybin.Build{
				Format:         "zip",
				DownloadSHA256: sha256Hex(testBinary),
				BinarySHA256:   sha256Hex(testBinary),
			},
			respond: respondWith(testBinary),
			msg:     `unknown download format "zip"`,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if !assert.NotNil(t, tc.respond, "unexpected request") {
					return
				}

				tc.respond(t, w)
			}))
			t.Cleanup(srv.Close)

			tc.build.URL = srv.URL + "/envoy"
			if tc.url != "" {
				tc.build.URL = tc.url
			}

			inst, path := newInstaller(t, tc.build)

			_, err := inst.Install(t.Context())
			require.Error(t, err)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			}

			require.ErrorContains(t, err, tc.msg)
			requireNothingInstalled(t, path)

			_, err = inst.Verify()
			require.ErrorIs(t, err, envoybin.ErrNotInstalled)
		})
	}
}

func TestMeasure(t *testing.T) {
	t.Parallel()

	archive := tarXz(t,
		tarEntry{name: "envoy/README.md", data: []byte("not the binary")},
		tarEntry{name: "envoy/bin/envoy", data: testBinary},
	)
	noBinary := tarXz(t, tarEntry{name: "envoy/bin/not-envoy", data: testBinary})

	// Measure ignores the hashes of the build that it receives.
	stale := sha256Hex([]byte("another version"))

	tests := map[string]struct {
		err          error
		msg          string
		format       envoybin.Format
		wantDownload string
		wantBinary   string
		body         []byte
		status       int
	}{
		"bare binary": {
			format:       envoybin.FormatBinary,
			body:         testBinary,
			wantDownload: sha256Hex(testBinary),
			wantBinary:   sha256Hex(testBinary),
		},
		"tar.xz archive": {
			format:       envoybin.FormatTarXz,
			body:         archive,
			wantDownload: sha256Hex(archive),
			wantBinary:   sha256Hex(testBinary),
		},
		"download is missing": {
			format: envoybin.FormatBinary,
			status: http.StatusNotFound,
			err:    envoybin.ErrDownload,
			msg:    "status 404",
		},
		"archive without the binary": {
			format: envoybin.FormatTarXz,
			body:   noBinary,
			msg:    "no bin/envoy entry",
		},
		"unknown format": {
			format: "zip",
			body:   testBinary,
			msg:    `unknown download format "zip"`,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}

				_, err := w.Write(tc.body)
				assert.NoError(t, err)
			}))
			t.Cleanup(srv.Close)

			build := envoybin.Build{
				URL:            srv.URL + "/envoy",
				Format:         tc.format,
				DownloadSHA256: stale,
				BinarySHA256:   stale,
			}

			got, err := envoybin.Measure(t.Context(), srv.Client(), build)

			if tc.msg != "" {
				require.Error(t, err)

				if tc.err != nil {
					require.ErrorIs(t, err, tc.err)
				}

				require.ErrorContains(t, err, tc.msg)
				assert.Equal(t, envoybin.Build{}, got)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, envoybin.Build{
				URL:            build.URL,
				Format:         tc.format,
				DownloadSHA256: tc.wantDownload,
				BinarySHA256:   tc.wantBinary,
			}, got)

			// The measured build installs, so Measure computes the
			// hashes that Install checks.
			inst, _ := newInstaller(t, got)

			_, err = inst.Install(t.Context())
			require.NoError(t, err)
		})
	}
}

func TestInstallTransportError(t *testing.T) {
	t.Parallel()

	errTransport := errors.New("transport stopped")

	var requests atomic.Int64

	// The round tripper fails every request, so the test opens no socket.
	client := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requests.Add(1)

			return nil, errTransport
		}),
	}

	inst, path := newInstaller(t, envoybin.Build{
		URL:            "http://envoy.invalid/envoy",
		Format:         envoybin.FormatBinary,
		DownloadSHA256: sha256Hex(testBinary),
		BinarySHA256:   sha256Hex(testBinary),
	}, envoybin.WithHTTPClient(client))

	_, err := inst.Install(t.Context())
	require.ErrorIs(t, err, envoybin.ErrDownload)
	require.ErrorIs(t, err, errTransport)
	assert.Equal(t, int64(1), requests.Load())
	requireNothingInstalled(t, path)

	_, err = inst.Verify()
	require.ErrorIs(t, err, envoybin.ErrNotInstalled)
}

func TestInstallCanceled(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(testBinary)))

		_, err := w.Write(testBinary[:len(testBinary)/2])
		assert.NoError(t, err)

		assert.NoError(t, http.NewResponseController(w).Flush())
		close(started)

		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	inst, path := newInstaller(t, envoybin.Build{
		URL:            srv.URL + "/envoy",
		Format:         envoybin.FormatBinary,
		DownloadSHA256: sha256Hex(testBinary),
		BinarySHA256:   sha256Hex(testBinary),
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		defer cancel()

		<-started

		// The temporary file shows that Install has the response and
		// copies its body, so the cancel stops the copy.
		assert.Eventually(t, func() bool {
			entries, err := os.ReadDir(filepath.Dir(path))

			return err == nil && len(entries) == 1
		}, 10*time.Second, time.Millisecond, "no temporary file during the download")
	}()

	_, err := inst.Install(ctx)
	require.ErrorIs(t, err, envoybin.ErrDownload)
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorContains(t, err, "write ")
	requireNothingInstalled(t, path)
}

func TestInstallCanceledAfterDownload(t *testing.T) {
	t.Parallel()

	archive := tarXz(t, tarEntry{name: "envoy/bin/envoy", data: testBinary})

	tests := map[string]struct {
		format envoybin.Format
		msg    string
		body   []byte
	}{
		"before the rename of a bare binary": {
			format: envoybin.FormatBinary,
			body:   testBinary,
			msg:    "move binary into place",
		},
		"during the extraction of a tar.xz archive": {
			format: envoybin.FormatTarXz,
			body:   archive,
			msg:    "extract",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			// The body cancels the context when it reports its end, so
			// the download completes and every later step sees the
			// cancel.
			end := readerFunc(func([]byte) (int, error) {
				cancel()

				return 0, io.EOF
			})

			client := &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Status:     "200 OK",
						Request:    r,
						Body:       io.NopCloser(io.MultiReader(bytes.NewReader(tc.body), end)),
					}, nil
				}),
			}

			inst, path := newInstaller(t, envoybin.Build{
				URL:            "http://envoy.invalid/envoy",
				Format:         tc.format,
				DownloadSHA256: sha256Hex(tc.body),
				BinarySHA256:   sha256Hex(testBinary),
			}, envoybin.WithHTTPClient(client))

			_, err := inst.Install(ctx)
			require.ErrorIs(t, err, context.Canceled)
			require.NotErrorIs(t, err, envoybin.ErrDownload)
			require.ErrorContains(t, err, tc.msg)
			requireNothingInstalled(t, path)
		})
	}
}

func TestInstallFilesystemErrors(t *testing.T) {
	t.Parallel()

	archive := tarXz(t, tarEntry{name: "envoy/bin/envoy", data: testBinary})

	// removeEntries removes every entry of the install directory. The
	// client calls the round tripper and Install reads the body on the
	// goroutine of the test, so the hooks can stop the test.
	removeEntries := func(t *testing.T, path string) {
		t.Helper()

		dir := filepath.Dir(path)

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1, "no temporary file at the end of the download")

		for _, e := range entries {
			require.NoError(t, os.Remove(filepath.Join(dir, e.Name())))
		}
	}

	tests := map[string]struct {
		// onRequest runs when the request reaches the round tripper.
		// Install has created the install directory by then.
		onRequest func(t *testing.T, path string)
		// onEOF runs when the body reports its end. The temporary file
		// holds the whole download by then.
		onEOF func(t *testing.T, path string)
		// check asserts the state of the install directory after the
		// install.
		check func(t *testing.T, path string)
		// err is the only sentinel that the error wraps. A nil err means
		// that the error wraps no sentinel.
		err    error
		format envoybin.Format
		msg    string
		body   []byte
	}{
		"install directory removed before the download": {
			format: envoybin.FormatBinary,
			body:   testBinary,
			onRequest: func(t *testing.T, path string) {
				t.Helper()

				require.NoError(t, os.Remove(filepath.Dir(path)))
			},
			check: requireNothingInstalled,
			err:   envoybin.ErrDownload,
			msg:   "create temporary file",
		},
		"directory appears at the install path": {
			format: envoybin.FormatBinary,
			body:   testBinary,
			onRequest: func(t *testing.T, path string) {
				t.Helper()

				require.NoError(t, os.Mkdir(path, 0o755))
			},
			check: func(t *testing.T, path string) {
				t.Helper()

				info, err := os.Stat(path)
				require.NoError(t, err)
				assert.True(t, info.IsDir())

				entries, err := os.ReadDir(path)
				require.NoError(t, err)
				assert.Empty(t, entries)

				entries, err = os.ReadDir(filepath.Dir(path))
				require.NoError(t, err)
				assert.Len(t, entries, 1, "temporary files remain next to the obstacle")
			},
			msg: "move binary into place",
		},
		"temporary file removed after the download, bare binary": {
			format: envoybin.FormatBinary,
			body:   testBinary,
			onEOF:  removeEntries,
			check:  requireNothingInstalled,
			msg:    "make binary executable",
		},
		"temporary file removed after the download, tar.xz": {
			format: envoybin.FormatTarXz,
			body:   archive,
			onEOF:  removeEntries,
			check:  requireNothingInstalled,
			msg:    "open archive",
		},
	}

	sentinels := []error{
		envoybin.ErrUnsupportedPlatform,
		envoybin.ErrNotInstalled,
		envoybin.ErrHashMismatch,
		envoybin.ErrDownload,
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// The round tripper needs the install path, which exists only
			// after the installer has the client.
			var path string

			client := &http.Client{
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if tc.onRequest != nil {
						tc.onRequest(t, path)
					}

					end := readerFunc(func([]byte) (int, error) {
						if tc.onEOF != nil {
							tc.onEOF(t, path)
						}

						return 0, io.EOF
					})

					return &http.Response{
						StatusCode: http.StatusOK,
						Status:     "200 OK",
						Request:    r,
						Body:       io.NopCloser(io.MultiReader(bytes.NewReader(tc.body), end)),
					}, nil
				}),
			}

			inst, path := newInstaller(t, envoybin.Build{
				URL:            "http://envoy.invalid/envoy",
				Format:         tc.format,
				DownloadSHA256: sha256Hex(tc.body),
				BinarySHA256:   sha256Hex(testBinary),
			}, envoybin.WithHTTPClient(client))

			_, err := inst.Install(t.Context())
			require.ErrorContains(t, err, tc.msg)

			for _, sentinel := range sentinels {
				if errors.Is(sentinel, tc.err) {
					require.ErrorIs(t, err, sentinel)

					continue
				}

				require.NotErrorIs(t, err, sentinel)
			}

			tc.check(t, path)
		})
	}
}

func TestWithHTTPClient(t *testing.T) {
	t.Parallel()

	var requests []string

	client := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			requests = append(requests, r.Method+" "+r.URL.String())

			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Request:    r,
				Body:       io.NopCloser(bytes.NewReader(testBinary)),
			}, nil
		}),
	}

	// The host does not resolve, so only the round tripper can serve the
	// download.
	inst, want := newInstaller(t, envoybin.Build{
		URL:            "http://envoy.invalid/envoy",
		Format:         envoybin.FormatBinary,
		DownloadSHA256: sha256Hex(testBinary),
		BinarySHA256:   sha256Hex(testBinary),
	}, envoybin.WithHTTPClient(client))

	got, err := inst.Install(t.Context())
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.Equal(t, []string{"GET http://envoy.invalid/envoy"}, requests)

	data, err := os.ReadFile(got)
	require.NoError(t, err)
	assert.Equal(t, testBinary, data)
}

func TestInstallPathObstructed(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// obstruct puts an obstacle on the way to path and returns a
		// function that asserts that the obstacle is unchanged.
		obstruct func(t *testing.T, path string) func()
		msg      string
	}{
		"regular file in place of the version directory": {
			obstruct: func(t *testing.T, path string) func() {
				t.Helper()

				file := filepath.Dir(filepath.Dir(path))
				require.NoError(t, os.WriteFile(file, []byte("obstacle"), 0o644))

				return func() {
					data, err := os.ReadFile(file)
					require.NoError(t, err)
					assert.Equal(t, "obstacle", string(data))
				}
			},
			msg: "open binary",
		},
		"directory at the install path": {
			obstruct: func(t *testing.T, path string) func() {
				t.Helper()

				require.NoError(t, os.MkdirAll(path, 0o755))

				return func() {
					info, err := os.Stat(path)
					require.NoError(t, err)
					assert.True(t, info.IsDir())

					entries, err := os.ReadDir(path)
					require.NoError(t, err)
					assert.Empty(t, entries)

					entries, err = os.ReadDir(filepath.Dir(path))
					require.NoError(t, err)
					assert.Len(t, entries, 1, "temporary files remain next to the obstacle")
				}
			},
			msg: "hash ",
		},
	}

	sentinels := []error{
		envoybin.ErrUnsupportedPlatform,
		envoybin.ErrNotInstalled,
		envoybin.ErrHashMismatch,
		envoybin.ErrDownload,
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv, requests := serveBytes(t, testBinary)
			inst, path := newInstaller(t, envoybin.Build{
				URL:            srv.URL + "/envoy",
				Format:         envoybin.FormatBinary,
				DownloadSHA256: sha256Hex(testBinary),
				BinarySHA256:   sha256Hex(testBinary),
			})

			unchanged := tc.obstruct(t, path)

			_, verifyErr := inst.Verify()
			_, installErr := inst.Install(t.Context())

			for _, err := range []error{verifyErr, installErr} {
				require.ErrorContains(t, err, tc.msg)

				for _, sentinel := range sentinels {
					require.NotErrorIs(t, err, sentinel)
				}
			}

			assert.Zero(t, requests.Load())
			unchanged()
		})
	}
}

func TestInstallDirectoryObstructed(t *testing.T) {
	t.Parallel()

	srv, requests := serveBytes(t, testBinary)
	inst, path := newInstaller(t, envoybin.Build{
		URL:            srv.URL + "/envoy",
		Format:         envoybin.FormatBinary,
		DownloadSHA256: sha256Hex(testBinary),
		BinarySHA256:   sha256Hex(testBinary),
	})

	// A symlink without a target stands in place of the install
	// directory. Opening the binary through it reports a missing file,
	// and creating the directory fails for every user, root included.
	link := filepath.Dir(path)
	versionDir := filepath.Dir(link)
	target := filepath.Join(t.TempDir(), "missing")

	require.NoError(t, os.MkdirAll(versionDir, 0o755))
	require.NoError(t, os.Symlink(target, link))

	_, err := inst.Verify()
	require.ErrorIs(t, err, envoybin.ErrNotInstalled)

	_, err = inst.Install(t.Context())
	require.ErrorContains(t, err, "create install directory")

	for _, sentinel := range []error{
		envoybin.ErrUnsupportedPlatform,
		envoybin.ErrNotInstalled,
		envoybin.ErrHashMismatch,
		envoybin.ErrDownload,
	} {
		require.NotErrorIs(t, err, sentinel)
	}

	assert.Zero(t, requests.Load())

	got, err := os.Readlink(link)
	require.NoError(t, err)
	assert.Equal(t, target, got)
	assert.NoFileExists(t, target)

	entries, err := os.ReadDir(versionDir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "temporary files remain next to the symlink")
	assert.Equal(t, filepath.Base(link), entries[0].Name())
}

func TestVerifyModifiedBinary(t *testing.T) {
	t.Parallel()

	srv, requests := serveBytes(t, testBinary)
	inst, _ := newInstaller(t, envoybin.Build{
		URL:            srv.URL + "/envoy",
		Format:         envoybin.FormatBinary,
		DownloadSHA256: sha256Hex(testBinary),
		BinarySHA256:   sha256Hex(testBinary),
	})

	path, err := inst.Install(t.Context())
	require.NoError(t, err)

	modified := bytes.Clone(testBinary)
	modified[len(modified)/2] ^= 0x01

	require.NoError(t, os.WriteFile(path, modified, 0o755))

	_, err = inst.Verify()
	require.ErrorIs(t, err, envoybin.ErrHashMismatch)
	require.ErrorContains(t, err, path)

	// Install refuses to replace the modified binary, and it does not
	// download again.
	_, err = inst.Install(t.Context())
	require.ErrorIs(t, err, envoybin.ErrHashMismatch)
	assert.Equal(t, int64(1), requests.Load())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, modified, data)
}

// TestOpen checks that the file from [envoybin.Installer.Open] is the
// file that Open hashed, also after another file takes the install
// path.
func TestOpen(t *testing.T) {
	t.Parallel()

	srv, _ := serveBytes(t, testBinary)
	inst, path := newInstaller(t, envoybin.Build{
		URL:            srv.URL + "/envoy",
		Format:         envoybin.FormatBinary,
		DownloadSHA256: sha256Hex(testBinary),
		BinarySHA256:   sha256Hex(testBinary),
	})

	_, err := inst.Install(t.Context())
	require.NoError(t, err)

	f, err := inst.Open()
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, f.Close())
	})

	assert.Equal(t, path, f.Name())

	// A rename puts another file at the install path. A write to the
	// path changes the open file itself.
	other := filepath.Join(t.TempDir(), "other")
	require.NoError(t, os.WriteFile(other, []byte("not the checked binary"), 0o755))
	require.NoError(t, os.Rename(other, path))

	// The read starts at the first byte, although the hash read the
	// whole file.
	data, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, testBinary, data)

	_, err = inst.Open()
	require.ErrorIs(t, err, envoybin.ErrHashMismatch)
	require.ErrorContains(t, err, path)
}

func TestOpenErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// installed is the content of the file at the install path.
		// A nil value means that no file exists.
		installed []byte
		platform  envoybin.Platform
		err       error
	}{
		"not installed": {
			platform: testPlatform,
			err:      envoybin.ErrNotInstalled,
		},
		"another hash": {
			installed: []byte("not envoy"),
			platform:  testPlatform,
			err:       envoybin.ErrHashMismatch,
		},
		"platform without a build": {
			platform: envoybin.Platform{OS: "plan9", Arch: "mips"},
			err:      envoybin.ErrUnsupportedPlatform,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			inst, path := newInstaller(t, envoybin.Build{
				URL:            "http://127.0.0.1:0/envoy",
				Format:         envoybin.FormatBinary,
				DownloadSHA256: sha256Hex(testBinary),
				BinarySHA256:   sha256Hex(testBinary),
			}, envoybin.WithPlatform(tt.platform))

			if tt.installed != nil {
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
				require.NoError(t, os.WriteFile(path, tt.installed, 0o755))
			}

			f, err := inst.Open()
			require.ErrorIs(t, err, tt.err)
			assert.Nil(t, f)
		})
	}
}

func TestVerifyNotInstalled(t *testing.T) {
	t.Parallel()

	inst, path := newInstaller(t, envoybin.Build{
		URL:            "http://127.0.0.1:0/envoy",
		Format:         envoybin.FormatBinary,
		DownloadSHA256: sha256Hex(testBinary),
		BinarySHA256:   sha256Hex(testBinary),
	})

	_, err := inst.Verify()
	require.ErrorIs(t, err, envoybin.ErrNotInstalled)
	require.ErrorContains(t, err, path)
}

func TestUnsupportedPlatform(t *testing.T) {
	t.Parallel()

	srv, requests := serveBytes(t, testBinary)
	dir := t.TempDir()

	inst := envoybin.NewInstaller(dir,
		envoybin.WithPlatform(envoybin.Platform{OS: "plan9", Arch: "mips"}),
		envoybin.WithManifest(envoybin.Manifest{
			Version: testVersion,
			Builds: map[envoybin.Platform]envoybin.Build{
				testPlatform: {
					URL:            srv.URL + "/envoy",
					Format:         envoybin.FormatBinary,
					DownloadSHA256: sha256Hex(testBinary),
					BinarySHA256:   sha256Hex(testBinary),
				},
			},
		}),
	)

	_, err := inst.Path()
	require.ErrorIs(t, err, envoybin.ErrUnsupportedPlatform)
	require.ErrorContains(t, err, "plan9-mips")

	_, err = inst.Verify()
	require.ErrorIs(t, err, envoybin.ErrUnsupportedPlatform)

	_, err = inst.Install(t.Context())
	require.ErrorIs(t, err, envoybin.ErrUnsupportedPlatform)

	assert.Zero(t, requests.Load())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestDefaultManifest(t *testing.T) {
	t.Parallel()

	m := envoybin.DefaultManifest()
	assert.Equal(t, envoybin.Version, m.Version)

	platforms := make([]string, 0, len(m.Builds))
	for p := range m.Builds {
		platforms = append(platforms, p.String())
	}

	assert.ElementsMatch(t, []string{"linux-amd64", "linux-arm64", "darwin-arm64"}, platforms)

	sha := regexp.MustCompile(`^[0-9a-f]{64}$`)

	for p, b := range m.Builds {
		t.Run(p.String(), func(t *testing.T) {
			t.Parallel()

			assert.True(t, strings.HasPrefix(b.URL, "https://"), "URL %q", b.URL)
			assert.Contains(t, b.URL, "/"+envoybin.Version+"/")
			assert.Regexp(t, sha, b.DownloadSHA256)
			assert.Regexp(t, sha, b.BinarySHA256)

			switch b.Format {
			case envoybin.FormatBinary:
				assert.Equal(t, b.DownloadSHA256, b.BinarySHA256)

			case envoybin.FormatTarXz:
				assert.True(t, strings.HasSuffix(b.URL, ".tar.xz"), "URL %q", b.URL)
				assert.NotEqual(t, b.DownloadSHA256, b.BinarySHA256)

			default:
				assert.Failf(t, "unknown format", "%q", b.Format)
			}
		})
	}
}

func TestMuslPlatformUnsupported(t *testing.T) {
	t.Parallel()

	var requests atomic.Int64

	client := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requests.Add(1)

			return nil, errors.New("unexpected request")
		}),
	}

	tests := map[string]struct {
		platform envoybin.Platform
		want     string
	}{
		"musl linux/amd64": {
			platform: envoybin.Platform{OS: "linux", Arch: "amd64", Libc: envoybin.LibcMusl},
			want:     "linux-amd64-musl",
		},
		"musl linux/arm64": {
			platform: envoybin.Platform{OS: "linux", Arch: "arm64", Libc: "musl"},
			want:     "linux-arm64-musl",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			// The installer keeps [envoybin.DefaultManifest], which holds
			// the glibc builds for both architectures.
			inst := envoybin.NewInstaller(dir,
				envoybin.WithPlatform(tc.platform),
				envoybin.WithHTTPClient(client),
			)

			_, err := inst.Path()
			require.ErrorIs(t, err, envoybin.ErrUnsupportedPlatform)
			require.ErrorContains(t, err, tc.want)

			_, err = inst.Verify()
			require.ErrorIs(t, err, envoybin.ErrUnsupportedPlatform)

			_, err = inst.Install(t.Context())
			require.ErrorIs(t, err, envoybin.ErrUnsupportedPlatform)

			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			assert.Empty(t, entries)
		})
	}

	t.Cleanup(func() {
		assert.Zero(t, requests.Load())
	})
}

func TestHostLibc(t *testing.T) {
	t.Parallel()

	const (
		glibcAMD64 = "lib64/ld-linux-x86-64.so.2"
		muslAMD64  = "lib/ld-musl-x86_64.so.1"
		glibcARM64 = "lib/ld-linux-aarch64.so.1"
		muslARM64  = "lib/ld-musl-aarch64.so.1"
	)

	tests := map[string]struct {
		arch  string
		files []string
		want  string
	}{
		"amd64 with the glibc loader only": {
			arch:  "amd64",
			files: []string{glibcAMD64},
			want:  "",
		},
		"amd64 with the musl loader only": {
			arch:  "amd64",
			files: []string{muslAMD64},
			want:  envoybin.LibcMusl,
		},
		"amd64 with both loaders": {
			arch:  "amd64",
			files: []string{glibcAMD64, muslAMD64},
			want:  "",
		},
		"amd64 with neither loader": {
			arch: "amd64",
			want: "",
		},
		"amd64 with the loaders of arm64": {
			arch:  "amd64",
			files: []string{glibcARM64, muslARM64},
			want:  "",
		},
		"amd64 with the musl loader of amd64 and the glibc loader of arm64": {
			arch:  "amd64",
			files: []string{muslAMD64, glibcARM64},
			want:  envoybin.LibcMusl,
		},
		"arm64 with the glibc loader only": {
			arch:  "arm64",
			files: []string{glibcARM64},
			want:  "",
		},
		"arm64 with the musl loader only": {
			arch:  "arm64",
			files: []string{muslARM64},
			want:  envoybin.LibcMusl,
		},
		"arm64 with both loaders": {
			arch:  "arm64",
			files: []string{glibcARM64, muslARM64},
			want:  "",
		},
		"arm64 with neither loader": {
			arch: "arm64",
			want: "",
		},
		"arm64 with the musl loader of arm64 and the glibc loader of amd64": {
			arch:  "arm64",
			files: []string{muslARM64, glibcAMD64},
			want:  envoybin.LibcMusl,
		},
		"architecture without known loaders": {
			arch:  "riscv64",
			files: []string{"lib/ld-musl-riscv64.so.1"},
			want:  "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			root := fstest.MapFS{}
			for _, f := range tc.files {
				root[f] = &fstest.MapFile{Mode: 0o755}
			}

			assert.Equal(t, tc.want, envoybin.HostLibc(root, tc.arch))
		})
	}
}

func TestPlatformString(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		platform envoybin.Platform
		want     string
	}{
		"without a libc": {
			platform: envoybin.Platform{OS: "linux", Arch: "arm64"},
			want:     "linux-arm64",
		},
		"with musl": {
			platform: envoybin.Platform{OS: "linux", Arch: "arm64", Libc: envoybin.LibcMusl},
			want:     "linux-arm64-musl",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, tc.platform.String())
		})
	}
}

func TestPlatformOf(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		goos   string
		goarch string
		files  []string
		want   envoybin.Platform
	}{
		"linux arm64 with the musl loader only": {
			goos:   "linux",
			goarch: "arm64",
			files:  []string{"lib/ld-musl-aarch64.so.1"},
			want:   envoybin.Platform{OS: "linux", Arch: "arm64", Libc: envoybin.LibcMusl},
		},
		"linux amd64 with the musl loader only": {
			goos:   "linux",
			goarch: "amd64",
			files:  []string{"lib/ld-musl-x86_64.so.1"},
			want:   envoybin.Platform{OS: "linux", Arch: "amd64", Libc: envoybin.LibcMusl},
		},
		"linux arm64 with the glibc loader only": {
			goos:   "linux",
			goarch: "arm64",
			files:  []string{"lib/ld-linux-aarch64.so.1"},
			want:   envoybin.Platform{OS: "linux", Arch: "arm64"},
		},
		"darwin arm64 with the musl loader only": {
			goos:   "darwin",
			goarch: "arm64",
			files:  []string{"lib/ld-musl-aarch64.so.1"},
			want:   envoybin.Platform{OS: "darwin", Arch: "arm64"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			root := fstest.MapFS{}
			for _, f := range tc.files {
				root[f] = &fstest.MapFile{Mode: 0o755}
			}

			assert.Equal(t, tc.want, envoybin.PlatformOf(tc.goos, tc.goarch, root))
		})
	}
}

func TestHostPlatform(t *testing.T) {
	t.Parallel()

	want := envoybin.PlatformOf(runtime.GOOS, runtime.GOARCH, os.DirFS("/"))

	assert.Equal(t, want, envoybin.HostPlatform())
}
