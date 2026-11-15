package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.jacobcolvin.com/terrarium/envoybin"
)

// serveDocs starts an HTTP server that answers each path in docs with its
// body, and every other path with status 404.
func serveDocs(t *testing.T, docs map[string][]byte) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, ok := docs[req.URL.Path]
		if !ok {
			http.NotFound(w, req)

			return
		}

		_, err := w.Write(body)
		assert.NoError(t, err)
	}))
	t.Cleanup(srv.Close)

	return srv
}

// manifestSourceOf returns the text of a Go file that pins the hashes of
// the linux-amd64 and darwin-arm64 builds of m as string literals.
func manifestSourceOf(m envoybin.Manifest) string {
	linux := m.Builds[linuxAMD64]
	darwin := m.Builds[darwinARM64]

	return `package envoybin

const Version = "` + m.Version + `" // renovate: datasource=github-releases depName=envoyproxy/envoy

var builds = map[Platform]Build{
	{OS: osLinux, Arch: archAMD64}: {
		DownloadSHA256: "` + linux.DownloadSHA256 + `",
		BinarySHA256:   "` + linux.BinarySHA256 + `",
	},
	{OS: osDarwin, Arch: archARM64}: {
		DownloadSHA256: "` + darwin.DownloadSHA256 + `",
		BinarySHA256:   "` + darwin.BinarySHA256 + `",
	},
}
`
}

func TestUpdate(t *testing.T) {
	t.Parallel()

	linuxBinary := []byte("linux envoy of the pinned version")
	darwinBinary := []byte("darwin envoy of the pinned version")
	archive := tarXz(t, darwinBinary)

	// current holds the hashes of the downloads that the server has.
	current := func(url string) envoybin.Manifest {
		return envoybin.Manifest{
			Version: testVersion,
			Builds: map[envoybin.Platform]envoybin.Build{
				linuxAMD64: {
					URL:            url + "/" + linuxName,
					Format:         envoybin.FormatBinary,
					DownloadSHA256: sha256Hex(linuxBinary),
					BinarySHA256:   sha256Hex(linuxBinary),
				},
				darwinARM64: {
					URL:            url + "/" + darwinName,
					Format:         envoybin.FormatTarXz,
					DownloadSHA256: sha256Hex(archive),
					BinarySHA256:   sha256Hex(darwinBinary),
				},
			},
		}
	}

	// stale returns a copy of m with the hashes that edit sets.
	stale := func(m envoybin.Manifest, edit func(linux, darwin *envoybin.Build)) envoybin.Manifest {
		linux := m.Builds[linuxAMD64]
		darwin := m.Builds[darwinARM64]

		edit(&linux, &darwin)

		m.Builds = map[envoybin.Platform]envoybin.Build{linuxAMD64: linux, darwinARM64: darwin}

		return m
	}

	previous := func(linux, darwin *envoybin.Build) {
		linux.DownloadSHA256 = sha256Hex([]byte("linux envoy of the previous version"))
		linux.BinarySHA256 = linux.DownloadSHA256
		darwin.DownloadSHA256 = sha256Hex([]byte("darwin archive of the previous version"))
		darwin.BinarySHA256 = sha256Hex([]byte("darwin envoy of the previous version"))
	}

	tests := map[string]struct {
		// edit sets the hashes that the manifest holds before the
		// update.
		edit func(linux, darwin *envoybin.Build)
		// source replaces the text of the source file.
		source func(m envoybin.Manifest) string
		err    error
		msg    string
		// missing names a download that the server does not have.
		missing string
	}{
		"hashes of the previous version": {
			edit: previous,
		},
		"hashes of the pinned version": {
			edit: func(_, _ *envoybin.Build) {},
		},
		"hash of one build is the previous hash of another": {
			edit: func(linux, darwin *envoybin.Build) {
				linux.DownloadSHA256 = sha256Hex(darwinBinary)
				linux.BinarySHA256 = sha256Hex(darwinBinary)
				darwin.BinarySHA256 = sha256Hex(linuxBinary)
			},
		},
		"build is not published": {
			edit:    previous,
			missing: "/" + darwinName,
			err:     envoybin.ErrDownload,
			msg:     "measure envoy " + testVersion + " for darwin-arm64",
		},
		"source file does not hold a hash": {
			edit: previous,
			source: func(m envoybin.Manifest) string {
				return strings.Replace(manifestSourceOf(m), m.Builds[darwinARM64].BinarySHA256, "sum", 1)
			},
			err: ErrManifestSource,
			msg: "does not hold the hash",
		},
		"manifest holds an empty hash": {
			edit: func(linux, _ *envoybin.Build) {
				linux.DownloadSHA256 = ""
				linux.BinarySHA256 = ""
			},
			err: ErrManifestSource,
			msg: `hash "" of linux-amd64 is not a lowercase hex SHA-256`,
		},
		"manifest holds a placeholder hash": {
			edit: func(_, darwin *envoybin.Build) {
				darwin.BinarySHA256 = "x"
			},
			err: ErrManifestSource,
			msg: `hash "x" of darwin-arm64 is not a lowercase hex SHA-256`,
		},
		"manifest holds an uppercase hash": {
			edit: func(linux, _ *envoybin.Build) {
				linux.DownloadSHA256 = strings.ToUpper(sha256Hex(linuxBinary))
				linux.BinarySHA256 = linux.DownloadSHA256
			},
			err: ErrManifestSource,
			msg: "of linux-amd64 is not a lowercase hex SHA-256",
		},
		"two downloads share one previous hash": {
			edit: func(linux, darwin *envoybin.Build) {
				previous(linux, darwin)

				darwin.DownloadSHA256 = linux.DownloadSHA256
			},
			err: ErrManifestSource,
			msg: "belongs to two different files",
		},
		"download and binary of one build share one previous hash": {
			edit: func(linux, darwin *envoybin.Build) {
				previous(linux, darwin)

				darwin.BinarySHA256 = darwin.DownloadSHA256
			},
			err: ErrManifestSource,
			msg: "belongs to two different files",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			docs := map[string][]byte{
				"/" + linuxName:  linuxBinary,
				"/" + darwinName: archive,
			}
			delete(docs, tc.missing)

			srv := serveDocs(t, docs)
			want := current(srv.URL)
			before := stale(want, tc.edit)

			source := manifestSourceOf(before)
			if tc.source != nil {
				source = tc.source(before)
			}

			path := filepath.Join(t.TempDir(), "manifest.go")
			require.NoError(t, os.WriteFile(path, []byte(source), 0o644))

			var out bytes.Buffer

			err := update(t.Context(), srv.Client(), before, path, &out)

			got, readErr := os.ReadFile(path)
			require.NoError(t, readErr)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				require.ErrorContains(t, err, tc.msg)
				assert.Equal(t, source, string(got), "a stopped update changed the source file")

				return
			}

			require.NoError(t, err)
			assert.Equal(t, manifestSourceOf(want), string(got))
			assert.Equal(t,
				"darwin-arm64: download "+sha256Hex(archive)+", binary "+sha256Hex(darwinBinary)+"\n"+
					"linux-amd64: download "+sha256Hex(linuxBinary)+", binary "+sha256Hex(linuxBinary)+"\n",
				out.String())
		})
	}
}

func TestUpdateMissingSource(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "manifest.go")

	// The update reads the source file before it downloads a build, so
	// the client gets no request.
	err := update(t.Context(), nil, envoybin.DefaultManifest(), path, &bytes.Buffer{})
	require.ErrorIs(t, err, ErrManifestSource)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestUpdateSourceIsDirectory(t *testing.T) {
	t.Parallel()

	// The read of the source file fails before the first download, so
	// the client gets no request.
	err := update(t.Context(), nil, envoybin.DefaultManifest(), t.TempDir(), &bytes.Buffer{})
	require.ErrorIs(t, err, ErrManifestSource)
	require.ErrorContains(t, err, "is a directory")
}

// failWriter is an [io.Writer] whose Write method returns err.
type failWriter struct {
	err error
}

func (w failWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestUpdateOutputFails(t *testing.T) {
	t.Parallel()

	binary := []byte("linux envoy of the pinned version")
	srv := serveDocs(t, map[string][]byte{"/" + linuxName: binary})

	previous := sha256Hex([]byte("linux envoy of the previous version"))
	m := envoybin.Manifest{
		Version: testVersion,
		Builds: map[envoybin.Platform]envoybin.Build{
			linuxAMD64: {
				URL:            srv.URL + "/" + linuxName,
				Format:         envoybin.FormatBinary,
				DownloadSHA256: previous,
				BinarySHA256:   previous,
			},
		},
	}

	source := "package envoybin\n\nconst sum = \"" + previous + "\"\n"
	path := filepath.Join(t.TempDir(), "manifest.go")
	require.NoError(t, os.WriteFile(path, []byte(source), 0o644))

	err := update(t.Context(), srv.Client(), m, path, failWriter{err: io.ErrClosedPipe})
	require.ErrorIs(t, err, io.ErrClosedPipe)
	require.ErrorContains(t, err, "print hashes")

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, source, string(got), "a stopped update changed the source file")
}

// TestManifestSourceHoldsHashes checks the requirement of the update
// command on [envoybin.DefaultManifest] and its source file. Each hash of
// the manifest must be a lowercase hex SHA-256, and the file must hold it
// as a string literal.
func TestManifestSourceHoldsHashes(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(manifestSource)))
	require.NoError(t, err)

	m := envoybin.DefaultManifest()
	require.NotEmpty(t, m.Builds)

	for p, b := range m.Builds {
		assert.Regexp(t, hexSHA256, b.DownloadSHA256, "download hash of %s", p)
		assert.Regexp(t, hexSHA256, b.BinarySHA256, "binary hash of %s", p)
		assert.Contains(t, string(data), `"`+b.DownloadSHA256+`"`, "download hash of %s", p)
		assert.Contains(t, string(data), `"`+b.BinarySHA256+`"`, "binary hash of %s", p)
	}

	assert.Contains(t, string(data), `"`+m.Version+`" // renovate: datasource=github-releases depName=envoyproxy/envoy`)
}
