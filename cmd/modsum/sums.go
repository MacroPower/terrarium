package main

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// goModSuffix ends the version of a go.sum line that holds the hash of a
// go.mod file. The other lines hold the hash of the files of a module.
const goModSuffix = "/go.mod"

var (
	// ErrModFile means that the command cannot read or parse a go.mod
	// file.
	ErrModFile = errors.New("go.mod file")

	// ErrSumFile means that the command cannot read, parse, or write a
	// go.sum file.
	ErrSumFile = errors.New("go.sum file")
)

// requirement is a module that a go.mod file requires.
type requirement struct {
	// The module path of the require directive. The go command takes
	// this path as the name of the module.
	path string

	// The module version that go.sum holds hashes for. It is the
	// required version, or the version that a replace directive names.
	sum module.Version
}

// requirements returns the modules that the go.mod file in data requires,
// in the order of the file. It applies the replace directives. It skips a
// module that a replace directive points at a directory, because go.sum
// holds no hash for a directory. The name argument is the path of the
// file, for messages.
func requirements(name string, data []byte) ([]requirement, error) {
	file, err := modfile.Parse(name, data, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrModFile, err)
	}

	// A replace directive names one version of a module, or every
	// version with an empty version. The go command prefers the
	// directive that names the version.
	replaced := make(map[module.Version]module.Version, len(file.Replace))
	for _, r := range file.Replace {
		replaced[r.Old] = r.New
	}

	reqs := make([]requirement, 0, len(file.Require))

	for _, r := range file.Require {
		sum := r.Mod

		target, ok := replaced[r.Mod]
		if !ok {
			target, ok = replaced[module.Version{Path: r.Mod.Path}]
		}

		if ok {
			// A replacement without a version is a directory.
			if target.Version == "" {
				continue
			}

			sum = target
		}

		reqs = append(reqs, requirement{path: r.Mod.Path, sum: sum})
	}

	return reqs, nil
}

// sumLine is one line of a go.sum file.
type sumLine struct {
	// The line without its line ending.
	text string

	// The module version of the line, without [goModSuffix].
	mod module.Version

	// Whether the line holds the hash of the go.mod file of the module
	// version, not the hash of its files.
	goMod bool
}

// parseSums returns the lines of the go.sum file in data. The name
// argument is the path of the file, for messages.
func parseSums(name string, data []byte) ([]sumLine, error) {
	var lines []sumLine

	for n, text := range strings.Split(string(data), "\n") {
		text = strings.TrimRight(text, "\r")

		fields := strings.Fields(text)
		if len(fields) == 0 {
			continue
		}

		if len(fields) != 3 {
			return nil, fmt.Errorf("%w: %s:%d: a line has %d fields, want 3", ErrSumFile, name, n+1, len(fields))
		}

		version, goMod := strings.CutSuffix(fields[1], goModSuffix)

		lines = append(lines, sumLine{
			mod:   module.Version{Path: fields[0], Version: version},
			goMod: goMod,
			text:  text,
		})
	}

	return lines, nil
}

// formatSums returns the text of a go.sum file that holds lines.
func formatSums(lines []sumLine) []byte {
	var text strings.Builder

	for _, line := range lines {
		text.WriteString(line.text)
		text.WriteByte('\n')
	}

	return []byte(text.String())
}

// selected indexes the module versions that go.sum holds hashes for.
type selected struct {
	// Each module version of the requirements.
	versions map[module.Version]bool

	// The module path of each of those versions, and the path of each
	// requirement that a replace directive points at another module.
	// The build uses no version of a replaced module.
	paths map[string]bool
}

// selectVersions returns the [selected] module versions of reqs.
func selectVersions(reqs []requirement) selected {
	sel := selected{
		versions: make(map[module.Version]bool, len(reqs)),
		paths:    make(map[string]bool, len(reqs)),
	}

	for _, req := range reqs {
		sel.versions[req.sum] = true
		sel.paths[req.sum.Path] = true
		sel.paths[req.path] = true
	}

	return sel
}

// other reports whether mod is a version of a required module, or of
// the module that replaces one, that the requirements do not select.
func (s selected) other(mod module.Version) bool {
	return s.paths[mod.Path] && !s.versions[mod]
}

// problems returns one message for each difference between the
// requirements of a go.mod file and the lines of its go.sum file. A
// requirement without the hash of its files or the hash of its go.mod
// file is a difference. The hash of the files of a version of a required
// module that go.mod does not select is a difference too.
//
// The go.mod hash of another version is not a difference. The go command
// keeps it when a dependency requires that version, because it reads the
// go.mod file of that version to select the versions of the build.
func problems(reqs []requirement, lines []sumLine) []string {
	// The module versions that have a hash of their files, and the
	// module versions that have a hash of their go.mod file.
	files := make(map[module.Version]bool, len(lines))
	goMods := make(map[module.Version]bool, len(lines))

	for _, line := range lines {
		if line.goMod {
			goMods[line.mod] = true
		} else {
			files[line.mod] = true
		}
	}

	var msgs []string

	for _, req := range reqs {
		if !files[req.sum] {
			msgs = append(msgs, fmt.Sprintf("no hash of %s %s", req.sum.Path, req.sum.Version))
		}

		if !goMods[req.sum] {
			msgs = append(msgs, fmt.Sprintf("no go.mod hash of %s %s", req.sum.Path, req.sum.Version))
		}
	}

	sel := selectVersions(reqs)

	for _, line := range lines {
		if !line.goMod && sel.other(line.mod) {
			msgs = append(msgs, fmt.Sprintf(
				"a hash of %s %s, and go.mod does not select that version", line.mod.Path, line.mod.Version,
			))
		}
	}

	return msgs
}

// trim returns lines without the hashes of the versions of required
// modules that the requirements do not select. It removes the hash of the
// files and the hash of the go.mod file of each such version. It keeps
// each line of a module that go.mod does not require.
func trim(reqs []requirement, lines []sumLine) []sumLine {
	sel := selectVersions(reqs)

	kept := make([]sumLine, 0, len(lines))

	for _, line := range lines {
		if !sel.other(line.mod) {
			kept = append(kept, line)
		}
	}

	return kept
}
