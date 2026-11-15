// Package main maintains the vendorHash of the Lima flake in
// lima/flake.nix. The flake builds terrarium with the buildGoModule
// function of nixpkgs, which requires the hash of the vendor tree of the
// root Go module. The vendor tree changes with the dependencies in go.mod
// and go.sum, and with the packages that the root module imports.
//
// The check command fails when the hash in the flake is not the hash of
// the vendor tree. The lint task runs it. The update command writes the
// hash of the vendor tree into the flake. The format task runs it.
// Renovate also runs it after it changes a dependency in the root go.mod,
// so the dependency and the hash change in one commit.
//
// Both commands create the vendor tree in a temporary directory with
// `go mod vendor`. They need each module of the root go.mod in the module
// cache, or internet access to download it. They set GOWORK=off as the
// flake does. They compute the hash as Nix does, which is the SHA-256 of
// the Nix archive (NAR) of the tree, and they do not need Nix.
//
// Usage, from the root of the repository:
//
//	go run ./cmd/vendorhash check
//	go run ./cmd/vendorhash update
package main
