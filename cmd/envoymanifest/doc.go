// Package main maintains the Envoy pin of the envoybin package. The pin is
// the release version and the SHA-256 hashes in envoybin/manifest.go.
//
// The update command computes the hashes of the pinned version. Renovate
// changes the version in envoybin/manifest.go and then runs the command,
// so the version and the hashes change in one commit. The command
// downloads every build of the manifest and replaces the hashes in the
// source file. It changes nothing when a build is missing.
//
// The verify command checks the provenance of the build for the host
// platform. The envoy workflow in .github/workflows runs it on one runner
// for each platform of the manifest. The command fails when one of these
// checks fails:
//
//   - The download and the binary in it have the hashes in the manifest.
//   - For a Linux build, the checksums.txt.asc file of the Envoy release
//     lists the hash of the download. The file must carry a signature of
//     the Envoy maintainers' key, whose fingerprint this package pins.
//   - For a macOS build, the index of the Tetrate archive lists the hash
//     of the download. The gh CLI must also find a build attestation of
//     the binary from the Tetrate workflow.
//   - The binary reports the commit of the Envoy release tag in the output
//     of its --version flag.
//
// Usage, from the root of the repository:
//
//	go run ./cmd/envoymanifest update [file]
//	go run ./cmd/envoymanifest verify [platform]
//
// The file argument defaults to envoybin/manifest.go. The platform
// argument, for example linux-arm64, names the platform that the caller
// expects the host to be. The verify command fails when the host is a
// different platform. It sends the token in the GH_TOKEN or GITHUB_TOKEN
// environment variable with its request to the GitHub API. The gh CLI
// reads the same variables.
package main
