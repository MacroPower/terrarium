package jail

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"

	"go.jacobcolvin.com/terrarium/internal/lookpath"
)

// Sentinel errors returned by [Exec]. Tests compare with
// [errors.Is] (via require.ErrorIs).
var (
	// ErrAppArmorUnavailable indicates the kernel's AppArmor securityfs
	// tree is not present, which means AppArmor is not enabled or not
	// loaded.
	ErrAppArmorUnavailable = errors.New("apparmor securityfs not present")

	// ErrAlreadyConfined indicates the calling process is already
	// under an AppArmor profile. Nested transitions into the workload
	// profile are refused so the confinement boundary stays at the
	// first jail call.
	ErrAlreadyConfined = errors.New("process is already confined")

	// ErrProfileNotLoaded indicates the requested profile was not found
	// in the kernel's loaded policy set.
	ErrProfileNotLoaded = errors.New("apparmor profile not loaded")

	// ErrNoCommand indicates [Exec] was called with an empty argv.
	ErrNoCommand = errors.New("no command specified")
)

// Options controls the AppArmor transition performed by [Exec].
type Options struct {
	// Profile is the AppArmor profile to transition into (e.g.
	// "terrarium.workload"). Must already be loaded into the kernel.
	Profile string
}

// config holds filesystem roots so tests can inject fixtures instead
// of touching the real /proc and /sys trees. Unexported because the
// public [Exec] wraps it.
type config struct {
	// write is the function used to write the arming command to the
	// exec attr. Tests override it to simulate short writes.
	write func(fd int, p []byte) (int, error)

	// execve is called to replace the current process. Tests override
	// it to observe the call without replacing the process; production
	// uses [unix.Exec].
	execve func(path string, argv, envv []string) error

	procRoot     string
	apparmorRoot string
}

func defaultConfig() *config {
	return &config{
		procRoot:     "/proc",
		apparmorRoot: "/sys/kernel/security/apparmor",
		write:        unix.Write,
		execve:       unix.Exec,
	}
}

// Exec performs the AppArmor preflight checks, arms a deferred
// profile transition on the current thread, and then calls execve
// to replace the process with argv[0]. The caller must hold
// [runtime.LockOSThread] before calling Exec.
//
// On success Exec does not return. On failure it returns a wrapped
// sentinel error from this package or a syscall error.
func Exec(opts Options, argv []string) error {
	return exec(defaultConfig(), opts, argv)
}

func exec(cfg *config, opts Options, argv []string) error {
	err := checkAppArmorAvailable(cfg)
	if err != nil {
		return err
	}

	err = checkUnconfined(cfg)
	if err != nil {
		return err
	}

	loaded, err := profileLoaded(cfg, opts.Profile)
	if err != nil {
		return fmt.Errorf("checking profile %s: %w", opts.Profile, err)
	}

	if !loaded {
		return fmt.Errorf("%w: %s", ErrProfileNotLoaded, opts.Profile)
	}

	if len(argv) == 0 {
		return ErrNoCommand
	}

	bin, err := lookpath.Find(argv[0])
	if err != nil {
		return fmt.Errorf("resolving %s: %w", argv[0], err)
	}

	err = changeOnExec(cfg, opts.Profile)
	if err != nil {
		return fmt.Errorf("arming profile transition: %w", err)
	}

	err = cfg.execve(bin, argv, unix.Environ())
	// execve only returns on error; the armed transition is discarded
	// by the kernel automatically.
	return fmt.Errorf("execve %s: %w", bin, err)
}
