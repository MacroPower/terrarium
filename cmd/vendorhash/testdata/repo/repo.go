// Package repo is the root module of the test repository. It imports one
// package of a dependency, so that the module has a vendor tree.
package repo

import "example.test/dep"

// Name returns the name of the dependency.
func Name() string {
	return dep.Name
}
