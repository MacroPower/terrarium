// Package main maintains the go.sum files of the Dagger modules in the ci
// and ci/tests directories.
//
// The Dagger modules import packages that Dagger generates, and
// .gitignore excludes the generated files. Without those files,
// `go mod tidy` removes the requirements of the generated packages, so
// it cannot check or write go.sum in a checkout. The modules are also
// outside the workspace of go.work, so the tidy check of the lint task
// does not read them. The commands of this package read go.mod and go.sum
// and no Go source file.
//
// The check command fails when go.sum does not hold the two hashes of a
// module version that go.mod requires, or when it holds the hash of
// another version of a required module. It applies the replace directives
// of go.mod. It does not run the go command, so it works without the
// module cache and without internet access. The lint task runs it.
//
// The update command removes the hashes of the other versions of each
// required module and adds each missing hash with `go mod download`. The
// go command also raises a requirement in go.mod when another required
// module needs a later version. The format task runs the update command.
// Renovate also runs it after it changes a dependency in the go.mod of a
// Dagger module, so the dependency and its hashes change in one commit.
// The command needs each required module in the module cache, or internet
// access to download it. It sets GOWORK=off.
//
// `go mod tidy` also keeps the hashes of modules that go.mod does not
// require, for the packages that the tests of a dependency import. Both
// commands leave those lines unchanged. `dagger develop` generates the
// packages and tidies the module, and each go.sum that it writes passes
// the check command.
//
// Usage, from the root of the repository:
//
//	go run ./cmd/modsum check
//	go run ./cmd/modsum update
package main
