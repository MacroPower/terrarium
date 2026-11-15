package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"

	"go.jacobcolvin.com/terrarium/envoybin"
)

var (
	// ErrManifestSource means that the update command cannot replace the
	// hashes of the manifest in its source file.
	ErrManifestSource = errors.New("update manifest source")

	// The lowercase hex form of a SHA-256.
	hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// update downloads every build of m with client and computes its hashes.
// It then replaces each hash of m in the Go source file at path with the
// computed hash. It writes one line to out for each build.
//
// Each hash of m must be 64 lowercase hex digits, and the source file
// must hold it as a string literal. The function finds a hash by that
// literal, and text of another form, such as an empty placeholder, also
// matches other parts of the file. The function checks both requirements
// before the first download.
//
// The function writes the file after every build has downloaded, so a
// missing build leaves the file unchanged.
func update(ctx context.Context, client *http.Client, m envoybin.Manifest, path string, out io.Writer) error {
	info, err := os.Stat(path) //nolint:gosec // G703: the caller names the source file.
	if err != nil {
		return fmt.Errorf("%w: %w", ErrManifestSource, err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // G703: the caller names the source file.
	if err != nil {
		return fmt.Errorf("%w: %w", ErrManifestSource, err)
	}

	src := string(data)
	ps := platforms(m)

	for _, p := range ps {
		b := m.Builds[p]

		for _, sum := range []string{b.DownloadSHA256, b.BinarySHA256} {
			if !hexSHA256.MatchString(sum) {
				return fmt.Errorf("%w: hash %q of %s is not a lowercase hex SHA-256", ErrManifestSource, sum, p)
			}

			if !strings.Contains(src, literal(sum)) {
				return fmt.Errorf("%w: %s does not hold the hash %s of %s", ErrManifestSource, path, sum, p)
			}
		}
	}

	// Each hash of m, and the hash that takes its place.
	replaced := make(map[string]string)

	// The literals of the entries of replaced, as the arguments of
	// [strings.NewReplacer].
	var pairs []string

	replace := func(old, sum string) error {
		prev, ok := replaced[old]
		if ok && prev != sum {
			return fmt.Errorf("%w: hash %s belongs to two different files", ErrManifestSource, old)
		}

		if !ok {
			replaced[old] = sum
			pairs = append(pairs, literal(old), literal(sum))
		}

		return nil
	}

	for _, p := range ps {
		old := m.Builds[p]

		build, err := envoybin.Measure(ctx, client, old)
		if err != nil {
			return fmt.Errorf("measure envoy %s for %s: %w", m.Version, p, err)
		}

		err = replace(old.DownloadSHA256, build.DownloadSHA256)
		if err != nil {
			return err
		}

		err = replace(old.BinarySHA256, build.BinarySHA256)
		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(out, "%s: download %s, binary %s\n", p, build.DownloadSHA256, build.BinarySHA256)
		if err != nil {
			return fmt.Errorf("print hashes: %w", err)
		}
	}

	// One pass replaces every hash, so a computed hash that equals
	// another hash of m does not change again.
	updated := strings.NewReplacer(pairs...).Replace(src)

	//nolint:gosec // G703: the caller names the source file.
	err = os.WriteFile(path, []byte(updated), info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrManifestSource, err)
	}

	return nil
}

// literal returns the Go string literal that holds the hash sum.
func literal(sum string) string {
	return `"` + sum + `"`
}

// platforms returns the platforms of m, ordered by their names.
func platforms(m envoybin.Manifest) []envoybin.Platform {
	ps := make([]envoybin.Platform, 0, len(m.Builds))
	for p := range m.Builds {
		ps = append(ps, p)
	}

	slices.SortFunc(ps, func(a, b envoybin.Platform) int {
		return strings.Compare(a.String(), b.String())
	})

	return ps
}
