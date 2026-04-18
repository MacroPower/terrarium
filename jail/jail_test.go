package jail_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.jacobcolvin.com/terrarium/jail"
)

// fixture lays out a minimal /proc and /sys/kernel/security/apparmor
// tree inside t.TempDir() and returns a [*jail.Config] pointing at it.
// Options control what the fixture pre-populates.
type fixtureOpts struct {
	// omitAppArmorRoot skips creating the securityfs apparmor tree,
	// triggering ErrAppArmorUnavailable.
	omitAppArmorRoot bool
	// currentLabel is written verbatim to
	// /proc/self/attr/apparmor/current. Empty means no file written.
	currentLabel string
	// profileNames populates policy/profiles/<id>/name entries.
	profileNames []string
	// flatProfiles populates the flat "profiles" fallback file. One
	// entry per line. Used when profileNames is empty.
	flatProfiles []string
	// omitProfilesDir skips creating policy/profiles entirely (forces
	// the flat-list fallback in [profileLoaded]).
	omitProfilesDir bool
	// attrWriteFn overrides the write() call on the exec attr. Nil
	// means a default stub that records the payload and returns full
	// length.
	attrWriteFn func(fd int, p []byte) (int, error)
	// execveFn overrides execve. Nil means a stub that records args
	// and returns ENOEXEC.
	execveFn func(path string, argv, envv []string) error
}

type fixture struct {
	cfg         *jail.Config
	execPayload []byte
	// binPath is an executable file inside the fixture's tempdir
	// that tests can pass to exec() without relying on the host PATH.
	binPath     string
	execveCalls int
}

func newFixture(t *testing.T, opts fixtureOpts) *fixture {
	t.Helper()

	dir := t.TempDir()
	procRoot := filepath.Join(dir, "proc")
	apparmorRoot := filepath.Join(dir, "sys", "kernel", "security", "apparmor")

	binPath := filepath.Join(dir, "fake-bin")
	require.NoError(t, os.WriteFile(binPath, []byte("#!/bin/sh\n"), 0o755))

	// /proc/self/attr/apparmor directory (always present so tests can
	// write current/exec attr files).
	attrDir := filepath.Join(procRoot, "self", "attr", "apparmor")
	require.NoError(t, os.MkdirAll(attrDir, 0o755))

	if opts.currentLabel != "" {
		require.NoError(t, os.WriteFile(
			filepath.Join(attrDir, "current"),
			[]byte(opts.currentLabel), 0o644))
	}

	// Pre-create a writable exec attr file so changeOnExec can open
	// it for writing.
	execAttr := filepath.Join(attrDir, "exec")
	require.NoError(t, os.WriteFile(execAttr, nil, 0o644))

	if !opts.omitAppArmorRoot {
		require.NoError(t, os.MkdirAll(apparmorRoot, 0o755))

		if !opts.omitProfilesDir && len(opts.profileNames) > 0 {
			profilesDir := filepath.Join(apparmorRoot, "policy", "profiles")
			require.NoError(t, os.MkdirAll(profilesDir, 0o755))

			for i, name := range opts.profileNames {
				entry := filepath.Join(profilesDir, "p"+strconv.Itoa(i))
				require.NoError(t, os.MkdirAll(entry, 0o755))
				require.NoError(t, os.WriteFile(
					filepath.Join(entry, "name"),
					[]byte(name+"\n"), 0o644))
			}
		}

		if len(opts.flatProfiles) > 0 {
			content := strings.Join(opts.flatProfiles, "\n") + "\n"

			require.NoError(t, os.WriteFile(
				filepath.Join(apparmorRoot, "profiles"),
				[]byte(content), 0o644))
		}
	}

	f := &fixture{}

	cfg := jail.NewConfig(procRoot, apparmorRoot)

	// Default write stub records the payload and returns full length.
	if opts.attrWriteFn == nil {
		cfg.SetWrite(func(_ int, p []byte) (int, error) {
			f.execPayload = append(f.execPayload, p...)
			return len(p), nil
		})
	} else {
		cfg.SetWrite(opts.attrWriteFn)
	}

	// Default execve stub records the call and returns ENOEXEC so
	// Exec can return cleanly after arming.
	if opts.execveFn == nil {
		cfg.SetExecve(func(_ string, _, _ []string) error {
			f.execveCalls++

			return unix.ENOEXEC
		})
	} else {
		cfg.SetExecve(opts.execveFn)
	}

	f.cfg = cfg
	f.binPath = binPath

	return f
}

func TestExecPreflight(t *testing.T) {
	t.Parallel()

	t.Run("ErrAppArmorUnavailable", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t, fixtureOpts{omitAppArmorRoot: true})

		err := jail.InternalExec(f.cfg, jail.Options{Profile: "terrarium.workload"}, []string{f.binPath})

		require.ErrorIs(t, err, jail.ErrAppArmorUnavailable)
		assert.Equal(t, 0, f.execveCalls, "execve must not run when preflight fails")
	})

	// Labels that represent a confined caller. "unconfined (complain)"
	// is intentionally absent: its parsed label is still "unconfined",
	// so re-entry is allowed.
	alreadyConfinedLabels := map[string]string{
		"enforce mode":       "terrarium.workload (enforce)\n",
		"namespaced enforce": ":root://terrarium.workload (enforce)\n",
	}

	for name, label := range alreadyConfinedLabels {
		t.Run("ErrAlreadyConfined/"+name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t, fixtureOpts{
				currentLabel: label,
				profileNames: []string{"terrarium.workload"},
			})

			err := jail.InternalExec(f.cfg, jail.Options{Profile: "terrarium.workload"}, []string{f.binPath})

			require.ErrorIs(t, err, jail.ErrAlreadyConfined)
			assert.Equal(t, 0, f.execveCalls)
		})
	}

	// Labels that parse to "unconfined" — re-entry must succeed past
	// the checkUnconfined gate.
	unconfinedLabels := map[string]string{
		"bare-no-newline":   "unconfined",
		"bare-with-newline": "unconfined\n",
		"complain-mode":     "unconfined (complain)\n",
	}

	for name, label := range unconfinedLabels {
		t.Run("unconfined-accepted/"+name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t, fixtureOpts{
				currentLabel: label,
				profileNames: []string{"terrarium.workload"},
			})

			err := jail.InternalExec(f.cfg, jail.Options{Profile: "terrarium.workload"}, []string{f.binPath})

			// Preflight passes; only the execve stub errors out.
			require.NotErrorIs(t, err, jail.ErrAlreadyConfined)
			assert.Equal(t, 1, f.execveCalls)
		})
	}

	t.Run("ErrProfileNotLoaded/profiles-dir-absent", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t, fixtureOpts{
			currentLabel:    "unconfined\n",
			omitProfilesDir: true,
		})

		err := jail.InternalExec(f.cfg, jail.Options{Profile: "terrarium.workload"}, []string{f.binPath})

		require.ErrorIs(t, err, jail.ErrProfileNotLoaded)
		assert.Equal(t, 0, f.execveCalls)
	})

	t.Run("ErrProfileNotLoaded/flat-list-absent", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t, fixtureOpts{
			currentLabel:    "unconfined\n",
			omitProfilesDir: true,
			flatProfiles:    []string{"other.profile (enforce)"},
		})

		err := jail.InternalExec(f.cfg, jail.Options{Profile: "terrarium.workload"}, []string{f.binPath})

		require.ErrorIs(t, err, jail.ErrProfileNotLoaded)
	})

	t.Run("ErrProfileNotLoaded/namespaced-dir-absent", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t, fixtureOpts{
			currentLabel: "unconfined\n",
			profileNames: []string{"other.workload"},
		})

		err := jail.InternalExec(f.cfg, jail.Options{Profile: "terrarium.workload"}, []string{f.binPath})

		require.ErrorIs(t, err, jail.ErrProfileNotLoaded)
	})

	t.Run("namespaced-match/profiles-dir", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t, fixtureOpts{
			currentLabel: "unconfined\n",
			profileNames: []string{":root://terrarium.workload"},
		})

		err := jail.InternalExec(f.cfg, jail.Options{Profile: "terrarium.workload"}, []string{f.binPath})

		// Preflight + arming both succeed; only the execve stub errors.
		require.ErrorContains(t, err, "execve")
		assert.Equal(t, 1, f.execveCalls)
	})

	t.Run("ErrNoCommand", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t, fixtureOpts{
			currentLabel: "unconfined\n",
			profileNames: []string{"terrarium.workload"},
		})

		err := jail.InternalExec(f.cfg, jail.Options{Profile: "terrarium.workload"}, nil)

		require.ErrorIs(t, err, jail.ErrNoCommand)
		assert.Equal(t, 0, f.execveCalls)
	})

	t.Run("short-write-on-exec-attr", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t, fixtureOpts{
			currentLabel: "unconfined\n",
			profileNames: []string{"terrarium.workload"},
			attrWriteFn: func(_ int, p []byte) (int, error) {
				return len(p) - 1, nil
			},
		})

		err := jail.InternalExec(f.cfg, jail.Options{Profile: "terrarium.workload"}, []string{f.binPath})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "short write")
		assert.Equal(t, 0, f.execveCalls, "execve must not run after short write")
	})

	t.Run("arming-payload-shape", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t, fixtureOpts{
			currentLabel: "unconfined\n",
			profileNames: []string{"terrarium.workload"},
		})

		err := jail.InternalExec(f.cfg, jail.Options{Profile: "terrarium.workload"}, []string{f.binPath})
		require.ErrorIs(t, err, unix.ENOEXEC)

		assert.Equal(t, "exec terrarium.workload", string(f.execPayload),
			"arming payload must use the 'exec' verb for deferred transitions")
	})

	t.Run("ErrNoCommand-single-empty-arg", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t, fixtureOpts{
			currentLabel: "unconfined\n",
			profileNames: []string{"terrarium.workload"},
		})

		// argv == [""] is a valid length-1 slice but argv[0] is empty,
		// which [lookPath] rejects with a distinct error.
		err := jail.InternalExec(f.cfg, jail.Options{Profile: "terrarium.workload"}, []string{""})

		require.Error(t, err)
		assert.Equal(t, 0, f.execveCalls)
	})
}

func TestCurrentProfileParsing(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		label string
		want  string
	}{
		"unconfined-with-newline":     {"unconfined\n", "unconfined"},
		"unconfined-no-newline":       {"unconfined", "unconfined"},
		"unconfined-complain":         {"unconfined (complain)\n", "unconfined"},
		"workload-enforce":            {"terrarium.workload (enforce)\n", "terrarium.workload"},
		"namespaced-workload-enforce": {":root://terrarium.workload (enforce)", ":root://terrarium.workload"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t, fixtureOpts{currentLabel: tc.label})

			got, err := jail.CurrentProfile(f.cfg)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestProfileLoaded(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		fixture fixtureOpts
		query   string
		want    bool
	}{
		"short-match-in-profiles-dir": {
			fixture: fixtureOpts{profileNames: []string{"terrarium.workload"}},
			query:   "terrarium.workload",
			want:    true,
		},
		"namespaced-match-in-profiles-dir": {
			fixture: fixtureOpts{profileNames: []string{":root://terrarium.workload"}},
			query:   "terrarium.workload",
			want:    true,
		},
		"short-match-via-flat-fallback": {
			fixture: fixtureOpts{
				omitProfilesDir: true,
				flatProfiles:    []string{"terrarium.workload (enforce)"},
			},
			query: "terrarium.workload",
			want:  true,
		},
		"namespaced-match-via-flat-fallback": {
			fixture: fixtureOpts{
				omitProfilesDir: true,
				flatProfiles:    []string{":root://terrarium.workload (enforce)"},
			},
			query: "terrarium.workload",
			want:  true,
		},
		"absent-in-both": {
			fixture: fixtureOpts{
				omitProfilesDir: true,
				flatProfiles:    []string{"other.profile (enforce)"},
			},
			query: "terrarium.workload",
			want:  false,
		},
		"flat-absent": {
			fixture: fixtureOpts{omitProfilesDir: true},
			query:   "terrarium.workload",
			want:    false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t, fixtureOpts{
				currentLabel:    "unconfined\n",
				profileNames:    tc.fixture.profileNames,
				flatProfiles:    tc.fixture.flatProfiles,
				omitProfilesDir: tc.fixture.omitProfilesDir,
			})

			got, err := jail.ProfileLoaded(f.cfg, tc.query)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestSentinelErrorsDistinct verifies each exported sentinel is a
// distinct error value so callers can discriminate with [errors.Is].
func TestSentinelErrorsDistinct(t *testing.T) {
	t.Parallel()

	sentinels := []error{
		jail.ErrAppArmorUnavailable,
		jail.ErrAlreadyConfined,
		jail.ErrProfileNotLoaded,
		jail.ErrNoCommand,
	}

	for i, a := range sentinels {
		for j, b := range sentinels {
			if i == j {
				continue
			}

			assert.NotErrorIs(t, a, b,
				"sentinels %d and %d must not match via errors.Is", i, j)
		}
	}
}
