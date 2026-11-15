package envoybin

import (
	"io/fs"
	"os"
	"runtime"
	"strings"
)

// Version is the Envoy release that [DefaultManifest] pins. The hashes in
// [DefaultManifest] belong to this release, so change them together with
// the version. After you change the version, run this command from the
// root of the repository to write the hashes of the release into this
// file:
//
//	go run ./cmd/envoymanifest update
//
// Renovate changes the version and runs the same command.
const Version = "v1.40.2" // renovate: datasource=github-releases depName=envoyproxy/envoy

// Format identifies how a download packages the envoy binary.
type Format string

// Format values.
const (
	// FormatBinary is a bare executable.
	FormatBinary Format = "binary"

	// FormatTarXz is an xz-compressed tar archive that holds the
	// executable in a bin directory.
	FormatTarXz Format = "tar.xz"
)

// The GOOS and GOARCH names of the platforms in [DefaultManifest].
const (
	osLinux   = "linux"
	osDarwin  = "darwin"
	archAMD64 = "amd64"
	archARM64 = "arm64"
)

// LibcMusl is the [Platform] Libc value of a Linux host whose C library
// is musl, such as Alpine Linux.
const LibcMusl = "musl"

// Platform identifies an operating system, a CPU architecture, and a C
// library.
type Platform struct {
	// OS is the GOOS name of the operating system.
	OS string

	// Arch is the GOARCH name of the CPU architecture.
	Arch string

	// Libc is [LibcMusl] on a musl Linux host. It is empty on macOS and
	// on glibc Linux.
	Libc string
}

// HostPlatform returns the [Platform] that the program runs on.
//
// On Linux it sets Libc to [LibcMusl] when the root file system holds
// the musl loader for the architecture and does not hold the glibc
// loader. Every other Linux host counts as glibc Linux.
func HostPlatform() Platform {
	return platformOf(runtime.GOOS, runtime.GOARCH, os.DirFS("/"))
}

// platformOf returns the [Platform] of a host with the operating system
// goos, the architecture goarch, and the root file system root. It reads
// root only for a Linux host, to set Libc with [hostLibc].
func platformOf(goos, goarch string, root fs.FS) Platform {
	p := Platform{OS: goos, Arch: goarch}

	if p.OS == osLinux {
		p.Libc = hostLibc(root, p.Arch)
	}

	return p
}

// String returns the platform as "<os>-<arch>", for example "linux-arm64".
// A platform with a Libc value gets the value as a suffix, for example
// "linux-arm64-musl".
func (p Platform) String() string {
	s := p.OS + "-" + p.Arch
	if p.Libc != "" {
		s += "-" + p.Libc
	}

	return s
}

// loaders names the dynamic loaders of one Linux architecture, as paths
// relative to the root of the file system.
type loaders struct {
	// The glibc loader, which the Envoy release binary names as its
	// interpreter.
	glibc string

	// The musl loader, which a musl host installs.
	musl string
}

// linuxLoaders maps a GOARCH name to the loaders of that architecture.
var linuxLoaders = map[string]loaders{
	archAMD64: {glibc: "lib64/ld-linux-x86-64.so.2", musl: "lib/ld-musl-x86_64.so.1"},
	archARM64: {glibc: "lib/ld-linux-aarch64.so.1", musl: "lib/ld-musl-aarch64.so.1"},
}

// hostLibc returns the [Platform] Libc value of a Linux host with the
// architecture arch and the root file system root. It returns [LibcMusl]
// when root holds the musl loader and does not hold the glibc loader. It
// returns the empty string for every other root.
func hostLibc(root fs.FS, arch string) string {
	l, ok := linuxLoaders[arch]
	if !ok {
		return ""
	}

	if exists(root, l.glibc) || !exists(root, l.musl) {
		return ""
	}

	return LibcMusl
}

// exists reports whether root holds a file at name.
func exists(root fs.FS, name string) bool {
	_, err := fs.Stat(root, name)

	return err == nil
}

// Build describes the pinned Envoy download for one [Platform].
type Build struct {
	// URL is the HTTP location of the download.
	URL string

	// Format is the packaging of the download.
	Format Format

	// DownloadSHA256 is the lowercase hex SHA-256 of the download.
	DownloadSHA256 string

	// BinarySHA256 is the lowercase hex SHA-256 of the envoy binary. For
	// [FormatBinary] it equals DownloadSHA256.
	BinarySHA256 string
}

// Manifest pins one Envoy version and the [Build] for each supported
// [Platform].
type Manifest struct {
	// Builds maps each supported platform to its build.
	Builds map[Platform]Build

	// Version names the pinned release, for example "v1.40.2". It forms
	// one directory of the install path.
	Version string
}

// DefaultManifest returns the [Manifest] for [Version].
//
// The Linux builds come from the Envoy GitHub release and link against
// glibc. A musl Linux host cannot run them, so the manifest has no build
// for a [Platform] whose Libc is [LibcMusl]. The macOS build comes from
// the Tetrate archive of Envoy builds, because the Envoy project does not
// publish macOS binaries.
//
// Keep each hash as a string literal of 64 lowercase hex digits in this
// function. The update command of cmd/envoymanifest finds each hash by
// that literal and replaces it, and it rejects a hash of another form.
// Give a build that you add placeholder hashes of 64 hex digits, with a
// different value for each file, and then run the update command.
func DefaultManifest() Manifest {
	num := strings.TrimPrefix(Version, "v")
	upstream := "https://github.com/envoyproxy/envoy/releases/download/" + Version + "/envoy-" + num
	tetrate := "https://archive.tetratelabs.io/envoy/download/" + Version + "/envoy-" + Version

	return Manifest{
		Version: Version,
		Builds: map[Platform]Build{
			{OS: osLinux, Arch: archAMD64}: {
				URL:            upstream + "-linux-x86_64",
				Format:         FormatBinary,
				DownloadSHA256: "1d64506e25c1844f146162ddb2ece7010fa4e784faddb40a079021491f1f03cc",
				BinarySHA256:   "1d64506e25c1844f146162ddb2ece7010fa4e784faddb40a079021491f1f03cc",
			},
			{OS: osLinux, Arch: archARM64}: {
				URL:            upstream + "-linux-aarch_64",
				Format:         FormatBinary,
				DownloadSHA256: "b9d6d1e06dd5838a3506de9f4deebad3de9a2ce6cadb87cd76222ca286213baf",
				BinarySHA256:   "b9d6d1e06dd5838a3506de9f4deebad3de9a2ce6cadb87cd76222ca286213baf",
			},
			{OS: osDarwin, Arch: archARM64}: {
				URL:            tetrate + "-darwin-arm64.tar.xz",
				Format:         FormatTarXz,
				DownloadSHA256: "3ccd840a1f5ec924baa56561dee913783103db2d3198ebf61f9b224c8ca9bcc0",
				BinarySHA256:   "9ad406f2b3cb27d5f005652346cceed76ff93a6619740e204ccf130250c5d498",
			},
		},
	}
}
