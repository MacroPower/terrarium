package jail

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// stripMode removes the AppArmor mode suffix from a label. Labels are
// emitted as "<name>" or "<name> (<mode>)"; namespaced labels like
// ":root://terrarium.workload (enforce)" split on the first " (" so
// the namespace prefix is preserved.
func stripMode(label string) string {
	before, _, found := strings.Cut(label, " (")
	if !found {
		return label
	}

	return before
}

// checkAppArmorAvailable returns [ErrAppArmorUnavailable] when the
// kernel's AppArmor securityfs tree is absent.
func checkAppArmorAvailable(cfg *config) error {
	_, err := os.Stat(cfg.apparmorRoot)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAppArmorUnavailable, err)
	}

	return nil
}

// checkUnconfined returns [ErrAlreadyConfined] when the caller already
// has a non-unconfined AppArmor label. Nested transitions are refused
// so the confinement boundary stays at the first jail call.
func checkUnconfined(cfg *config) error {
	label, err := currentProfile(cfg)
	if err != nil {
		return fmt.Errorf("reading current profile: %w", err)
	}

	if label != "unconfined" {
		return fmt.Errorf("%w: %s", ErrAlreadyConfined, label)
	}

	return nil
}

// currentProfile returns the AppArmor label of the calling process,
// stripped of the mode suffix.
//
// The preferred path is /proc/self/attr/apparmor/current, which is
// AppArmor-specific and robust against multi-LSM stacks that multiplex
// /proc/self/attr/current. Falls back to /proc/self/attr/current on
// ENOENT.
func currentProfile(cfg *config) (string, error) {
	data, err := readAttr(cfg, "current")
	if err != nil {
		return "", err
	}

	return stripMode(strings.TrimRight(string(data), "\n")), nil
}

// profileLoaded reports whether the named AppArmor profile is present
// in the kernel's loaded policy set. It compares both the short name
// and the namespaced form (":root://<name>") so callers can pass
// either regardless of how the profile was loaded.
func profileLoaded(cfg *config, name string) (bool, error) {
	bare := strings.TrimPrefix(name, ":root://")
	targets := map[string]struct{}{
		bare:              {},
		":root://" + bare: {},
	}

	// Preferred: per-profile directories under policy/profiles. Each
	// directory has a "name" file containing the profile's name.
	profilesDir := filepath.Join(cfg.apparmorRoot, "policy", "profiles")

	entries, err := os.ReadDir(profilesDir)
	switch {
	case err == nil:
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}

			nameFile := filepath.Join(profilesDir, e.Name(), "name")

			data, err := os.ReadFile(nameFile)
			if err != nil {
				continue
			}

			loaded := strings.TrimSpace(string(data))
			if _, ok := targets[loaded]; ok {
				return true, nil
			}
		}

		return false, nil

	case errors.Is(err, os.ErrNotExist):
		// Fall through to flat-list fallback.

	default:
		return false, fmt.Errorf("reading %s: %w", profilesDir, err)
	}

	// Fallback: flat profiles list on older kernels. Each line is
	// "<name> (<mode>)".
	flatPath := filepath.Join(cfg.apparmorRoot, "profiles")

	data, err := os.ReadFile(flatPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}

		return false, fmt.Errorf("reading %s: %w", flatPath, err)
	}

	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if _, ok := targets[stripMode(line)]; ok {
			return true, nil
		}
	}

	return false, nil
}

// changeOnExec arms a deferred AppArmor transition on the current
// thread. The kernel applies the transition on the next execve from
// this thread.
//
// The kernel interface requires a single write() per command, so we
// use [unix.Write] directly rather than [os.WriteFile]. EINTR is
// retried; any short write is fatal.
func changeOnExec(cfg *config, profile string) error {
	payload := []byte("exec " + profile)

	fd, err := openAttr(cfg, "exec")
	if err != nil {
		return err
	}

	defer func() {
		err := unix.Close(fd)
		if err != nil {
			slog.Warn("closing apparmor exec attr fd", "err", err)
		}
	}()

	for {
		n, err := cfg.write(fd, payload)
		if errors.Is(err, unix.EINTR) {
			continue
		}

		if err != nil {
			return fmt.Errorf("writing exec attr: %w", err)
		}

		if n != len(payload) {
			return fmt.Errorf("short write to exec attr: wrote %d of %d bytes", n, len(payload))
		}

		return nil
	}
}

// readAttr reads a /proc/self/attr/apparmor/<name> file, falling back
// to /proc/self/attr/<name> on ENOENT so older kernels without the
// AppArmor-specific subdirectory still work.
func readAttr(cfg *config, name string) ([]byte, error) {
	primary := filepath.Join(cfg.procRoot, "self", "attr", "apparmor", name)

	data, err := os.ReadFile(primary)
	if err == nil {
		return data, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading %s: %w", primary, err)
	}

	fallback := filepath.Join(cfg.procRoot, "self", "attr", name)

	data, err = os.ReadFile(fallback)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", fallback, err)
	}

	return data, nil
}

// openAttr opens a /proc/self/attr/apparmor/<name> file for writing,
// falling back to /proc/self/attr/<name> on ENOENT.
func openAttr(cfg *config, name string) (int, error) {
	primary := filepath.Join(cfg.procRoot, "self", "attr", "apparmor", name)

	fd, err := unix.Open(primary, unix.O_WRONLY, 0)
	if err == nil {
		return fd, nil
	}

	if !errors.Is(err, unix.ENOENT) {
		return -1, fmt.Errorf("opening %s: %w", primary, err)
	}

	fallback := filepath.Join(cfg.procRoot, "self", "attr", name)

	fd, err = unix.Open(fallback, unix.O_WRONLY, 0)
	if err != nil {
		return -1, fmt.Errorf("opening %s: %w", fallback, err)
	}

	return fd, nil
}
