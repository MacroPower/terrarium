package privdrop

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Options controls the privilege-drop behavior before execve.
type Options struct {
	InhCaps       uint64
	AmbientCaps   uint64
	UID           uint32
	GID           uint32
	ClearGroups   bool
	InitGroups    bool
	NoNewPrivs    bool
	ClearBounding bool
}

// Exec performs privilege-dropping syscalls and then calls execve to
// replace the current process with argv[0]. The caller must hold
// [runtime.LockOSThread] before calling Exec, because capability
// syscalls are per-thread.
//
// Exec does not return on success. On failure it returns an error
// describing the failed syscall.
func Exec(opts Options, argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("empty argv")
	}

	// Dispatch based on whether ambient caps are needed.
	// The two paths have different syscall ordering requirements.
	if opts.AmbientCaps != 0 {
		return execWithAmbientCaps(opts, argv)
	}

	return execDropAll(opts, argv)
}

// execWithAmbientCaps implements Path A: preserve specific capabilities
// across the UID transition using PR_SET_KEEPCAPS, then set inheritable
// and ambient caps. Used for Envoy (CAP_NET_ADMIN).
func execWithAmbientCaps(opts Options, argv []string) error {
	// 1. Clear supplementary groups.
	if opts.ClearGroups {
		err := unix.Setgroups(nil)
		if err != nil {
			return fmt.Errorf("setgroups([]): %w", err)
		}
	}

	// 2. Set GID.
	err := unix.Setresgid(int(opts.GID), int(opts.GID), int(opts.GID))
	if err != nil {
		return fmt.Errorf("setresgid(%d): %w", opts.GID, err)
	}

	// 3. Enable KEEPCAPS so permitted caps survive the UID transition.
	err = unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("prctl(PR_SET_KEEPCAPS, 1): %w", err)
	}

	// 4. Drop to non-root UID. Kernel clears effective but preserves
	// permitted (because KEEPCAPS is set).
	err = unix.Setresuid(int(opts.UID), int(opts.UID), int(opts.UID))
	if err != nil {
		return fmt.Errorf("setresuid(%d): %w", opts.UID, err)
	}

	// 5. Reset KEEPCAPS (defense in depth).
	err = unix.Prctl(unix.PR_SET_KEEPCAPS, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("prctl(PR_SET_KEEPCAPS, 0): %w", err)
	}

	// 6. Set effective = permitted = inheritable = desired caps.
	caps := opts.AmbientCaps | opts.InhCaps
	err = setCaps(caps, caps, caps)
	if err != nil {
		return fmt.Errorf("setting caps: %w", err)
	}

	// 7. Raise ambient caps.
	for bit := range 64 {
		if opts.AmbientCaps&(1<<bit) != 0 {
			err = unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(bit), 0, 0)
			if err != nil {
				return fmt.Errorf("prctl(PR_CAP_AMBIENT_RAISE, %d): %w", bit, err)
			}
		}
	}

	// 8. Exec.
	return execvp(argv)
}

// execDropAll implements Path B: drop all privileges. Used for the user
// command. Clears bounding set and inheritable caps while still root,
// then transitions UID (kernel auto-clears permitted+effective).
func execDropAll(opts Options, argv []string) error {
	// 1. Resolve and set supplementary groups (if --init-groups).
	if opts.InitGroups {
		gids, err := resolveGroups(opts.UID)
		if err != nil {
			return fmt.Errorf("resolving groups: %w", err)
		}

		ints := make([]int, len(gids))
		for i, g := range gids {
			ints[i] = int(g)
		}

		err = unix.Setgroups(ints)
		if err != nil {
			return fmt.Errorf("setgroups: %w", err)
		}
	} else if opts.ClearGroups {
		err := unix.Setgroups(nil)
		if err != nil {
			return fmt.Errorf("setgroups([]): %w", err)
		}
	}

	// 2. Set GID (requires CAP_SETGID, still root).
	err := unix.Setresgid(int(opts.GID), int(opts.GID), int(opts.GID))
	if err != nil {
		return fmt.Errorf("setresgid(%d): %w", opts.GID, err)
	}

	// 3. Drop all bounding set caps (requires CAP_SETPCAP, still root).
	if opts.ClearBounding {
		last, err := capLastCap()
		if err != nil {
			return fmt.Errorf("reading cap_last_cap: %w", err)
		}

		for c := 0; c <= last; c++ {
			err = unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0)
			if err != nil {
				return fmt.Errorf("prctl(PR_CAPBSET_DROP, %d): %w", c, err)
			}
		}
	}

	// 4. Clear inheritable caps only. We must preserve effective and
	// permitted because CAP_SETUID is still needed for setresuid below.
	// The kernel auto-clears permitted+effective on the UID transition
	// when KEEPCAPS is not set.
	err = clearInheritableOnly()
	if err != nil {
		return fmt.Errorf("clearing inheritable caps: %w", err)
	}

	// 5. Set NO_NEW_PRIVS.
	if opts.NoNewPrivs {
		err = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
		if err != nil {
			return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
		}
	}

	// 6. Drop to non-root UID. Without KEEPCAPS, kernel auto-clears
	// permitted and effective.
	err = unix.Setresuid(int(opts.UID), int(opts.UID), int(opts.UID))
	if err != nil {
		return fmt.Errorf("setresuid(%d): %w", opts.UID, err)
	}

	// 7. Exec.
	return execvp(argv)
}

// clearInheritableOnly uses capget+capset to clear only the inheritable
// set while preserving effective and permitted. This is the fallback
// when setCaps(0, 0, 0) fails because clearing effective+permitted
// would remove capabilities needed for subsequent syscalls.
func clearInheritableOnly() error {
	hdr := capHeader{
		Version: linuxCapabilityVersion2,
		PID:     0,
	}

	var data [2]capData

	//nolint:gosec // G103: required for capget/capset syscall kernel ABI.
	_, _, errno := unix.Syscall(
		unix.SYS_CAPGET,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("capget: %w", errno)
	}

	// Zero inheritable, keep effective and permitted.
	data[0].Inheritable = 0
	data[1].Inheritable = 0

	//nolint:gosec // G103: required for capget/capset syscall kernel ABI.
	_, _, errno = unix.Syscall(
		unix.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("capset: %w", errno)
	}

	return nil
}

// execvp resolves the command path and calls unix.Exec (execve).
// Does not return on success.
func execvp(argv []string) error {
	bin, err := lookPath(argv[0])
	if err != nil {
		return fmt.Errorf("resolving %s: %w", argv[0], err)
	}

	err = unix.Exec(bin, argv, unix.Environ())
	// unix.Exec only returns on error.
	return fmt.Errorf("execve %s: %w", bin, err)
}
