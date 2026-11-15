package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
)

var (
	// ErrFlakeSource means that the command cannot read or replace the
	// vendorHash in the flake.
	ErrFlakeSource = errors.New("flake source")

	// An assignment of a string to the vendorHash attribute. The one
	// group is the string.
	vendorHashAttr = regexp.MustCompile(`\bvendorHash\s*=\s*"([^"]*)"`)
)

// flake is the text of a flake that assigns one string to vendorHash.
// Create instances with [readFlake].
type flake struct {
	path string
	text string
	mode fs.FileMode

	// The offsets in text of the start and the end of the string.
	start, end int
}

// readFlake reads the flake at path. The flake must assign a string to
// vendorHash exactly one time, because [flake.write] replaces that string.
func readFlake(path string) (*flake, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFlakeSource, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFlakeSource, err)
	}

	text := string(data)

	matches := vendorHashAttr.FindAllStringSubmatchIndex(text, -1)
	if len(matches) != 1 {
		return nil, fmt.Errorf(
			"%w: %s assigns a string to vendorHash %d times, want 1",
			ErrFlakeSource, path, len(matches),
		)
	}

	return &flake{
		path:  path,
		text:  text,
		mode:  info.Mode().Perm(),
		start: matches[0][2],
		end:   matches[0][3],
	}, nil
}

// hash returns the string that the flake assigns to vendorHash.
func (f *flake) hash() string {
	return f.text[f.start:f.end]
}

// write replaces the string that the flake assigns to vendorHash with sum,
// in the file and in f.
func (f *flake) write(sum string) error {
	text := f.text[:f.start] + sum + f.text[f.end:]

	err := os.WriteFile(f.path, []byte(text), f.mode)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFlakeSource, err)
	}

	f.text = text
	f.end = f.start + len(sum)

	return nil
}
