// Package envoybin installs a pinned Envoy binary for the host platform
// and checks the binary against hashes compiled into terrarium.
//
// A [Manifest] pins one Envoy version. For each supported platform it
// records the download URL, the SHA-256 of the download, and the SHA-256
// of the envoy binary. [DefaultManifest] returns the manifest that
// terrarium ships. Platforms without an entry have no managed build, and
// every operation on them returns [ErrUnsupportedPlatform]. A [Platform]
// includes the C library of a Linux host, because the Linux builds link
// against glibc. Musl Linux, such as Alpine Linux, has no managed build.
//
// An [Installer] keeps each binary at <dir>/<version>/<os>-<arch>/envoy,
// so builds for different versions and platforms can share one directory.
// [Installer.Install] downloads the build to a temporary file in the
// target directory and checks both hashes before it renames the binary
// into place. The final path therefore holds either a complete, checked
// binary or nothing.
//
// [Installer.Verify] hashes the installed binary and returns its path.
// [Installer.Open] does the same check and returns the open file. Call
// [Installer.Open] before every start of Envoy and execute the binary
// through the open file where the platform allows it. On Linux, the path
// /proc/self/fd/<n> names the open file. A process that replaces the
// file at the install path after the check then has no effect on the
// binary that runs.
//
// A missing binary returns [ErrNotInstalled], which a caller can answer
// with [Installer.Install]. A binary with the wrong hash returns
// [ErrHashMismatch]. No method replaces such a binary, because the
// mismatch can mean that someone replaced the file. The user must
// inspect the file and remove it before a new install.
//
// A hash proves the origin of a binary only when the hash comes from the
// publisher of the binary. The envoymanifest command in cmd/envoymanifest
// maintains the hashes of the manifest. Its update command calls [Measure]
// to compute the hashes of each build after the version changes. Its
// verify command compares the pinned hashes with the checksums that the
// publisher of each build signs or attests. A workflow runs the verify
// command on every pull request that changes the pin.
package envoybin
