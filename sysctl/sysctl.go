package sysctl

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultProcRoot is the standard procfs path for kernel parameters.
const DefaultProcRoot = "/proc/sys"

// Sysctl reads and writes Linux kernel parameters through procfs.
// Create instances with [New].
type Sysctl struct {
	procRoot string
}

// Option configures optional behavior of a [Sysctl].
//
// The following options are available:
//
//   - [WithProcRoot]
type Option func(*Sysctl)

// WithProcRoot is an [Option] that overrides the [DefaultProcRoot] directory.
// This is primarily useful for testing with a temporary directory.
func WithProcRoot(root string) Option {
	return func(s *Sysctl) {
		s.procRoot = root
	}
}

// New creates a new [Sysctl].
func New(opts ...Option) *Sysctl {
	s := &Sysctl{
		procRoot: DefaultProcRoot,
	}
	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Read returns the value of the kernel parameter identified by param.
// Trailing whitespace is trimmed from the result.
func (s *Sysctl) Read(param ...string) (string, error) {
	data, err := os.ReadFile(s.path(param))
	if err != nil {
		return "", fmt.Errorf("reading sysctl %s: %w", name(param), err)
	}

	return strings.TrimRight(string(data), " \n"), nil
}

// ReadInt returns the integer value of the kernel parameter identified
// by param.
func (s *Sysctl) ReadInt(param ...string) (int64, error) {
	val, err := s.Read(param...)
	if err != nil {
		return 0, err
	}

	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing sysctl %s: %w", name(param), err)
	}

	return n, nil
}

// Write sets the kernel parameter identified by param to the given
// value.
func (s *Sysctl) Write(value string, param ...string) error {
	err := os.WriteFile(s.path(param), []byte(value), 0o644)
	if err != nil {
		return fmt.Errorf("writing sysctl %s: %w", name(param), err)
	}

	return nil
}

// WriteInt sets the kernel parameter identified by param to the given
// integer value.
func (s *Sysctl) WriteInt(value int64, param ...string) error {
	return s.Write(strconv.FormatInt(value, 10), param...)
}

// Enable sets the kernel parameter identified by param to "1".
func (s *Sysctl) Enable(param ...string) error {
	return s.Write("1", param...)
}

// Disable sets the kernel parameter identified by param to "0".
func (s *Sysctl) Disable(param ...string) error {
	return s.Write("0", param...)
}

// path joins the proc root with the parameter components.
func (s *Sysctl) path(param []string) string {
	return filepath.Join(append([]string{s.procRoot}, param...)...)
}

// name returns the dotted parameter name for use in error messages.
func name(param []string) string {
	return strings.Join(param, ".")
}
