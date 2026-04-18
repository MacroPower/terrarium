package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
)

// mainpidSentinel matches "mainpid:<unit>" tokens. Unit names follow
// systemd's charset (alphanumerics, plus @._-).
var mainpidSentinel = regexp.MustCompile(`mainpid:([A-Za-z0-9@._-]+)`)

// resolvePIDSentinel replaces every "mainpid:<unit>" token in s with
// the numeric PID reported by `systemctl show --value -p MainPID
// <unit>`. `pidof` is avoided because it is non-deterministic across
// siblings; MainPID names the systemd-tracked primary PID explicitly.
func resolvePIDSentinel(ctx context.Context, s string) (string, error) {
	var resolveErr error

	out := mainpidSentinel.ReplaceAllStringFunc(s, func(match string) string {
		if resolveErr != nil {
			return match
		}

		unit := strings.TrimPrefix(match, "mainpid:")

		raw, err := exec.CommandContext(ctx, //nolint:gosec // unit name from test spec
			"systemctl", "show", "--value", "-p", "MainPID", unit).Output()
		if err != nil {
			resolveErr = fmt.Errorf("systemctl show %s: %w", unit, err)
			return match
		}

		pid := strings.TrimSpace(string(raw))
		if pid == "" || pid == "0" {
			resolveErr = fmt.Errorf("unit %s has no MainPID", unit)
			return match
		}

		return pid
	})

	if resolveErr != nil {
		return "", resolveErr
	}

	return out, nil
}

// runJailed runs `terrarium jail -- <args...>` and returns exit code
// plus combined output.
func runJailed(ctx context.Context, args ...string) (int, string, error) {
	fullArgs := append([]string{"jail", "--"}, args...)

	//nolint:gosec // args from test spec
	out, err := exec.CommandContext(ctx, "terrarium", fullArgs...).CombinedOutput()
	if err == nil {
		return 0, string(out), nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), string(out), nil
	}

	return -1, string(out), err
}

// assertJailProfileAttached runs a process under `terrarium jail` and
// verifies the resulting AppArmor label matches [assertion.Expected],
// accepting the bare form or a ":root://" prefix.
func assertJailProfileAttached(ctx context.Context, a assertion) result {
	// Try the apparmor-specific path first, fall back to the generic.
	script := `if [ -r /proc/self/attr/apparmor/current ]; then
  cat /proc/self/attr/apparmor/current
else
  cat /proc/self/attr/current
fi`

	code, out, err := runJailed(ctx, "sh", "-c", script)
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("running jail: %v", err)}
	}

	if code != 0 {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("jail exit %d: %s", code, out)}
	}

	label := strings.TrimRight(strings.TrimRight(out, "\n"), " ")

	idx := strings.Index(label, " (")
	if idx > 0 {
		label = label[:idx]
	}

	want := a.Expected
	accepted := []string{want, ":root://" + want}

	if slices.Contains(accepted, label) {
		return result{Status: statusPass, Desc: a.Desc, Detail: label}
	}

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: fmt.Sprintf("expected label %s (bare or :root://), got %s", want, label),
	}
}

// expectJailNonzero runs `terrarium jail -- <argv...>` and passes when
// the child exits nonzero. failDetail formats the failure message when
// the child unexpectedly exits zero.
func expectJailNonzero(ctx context.Context, a assertion, argv []string, failDetail func(out string) string) result {
	code, out, err := runJailed(ctx, argv...)
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("running jail: %v", err)}
	}

	if code != 0 {
		return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("exit %d", code)}
	}

	maybeDebugDump(ctx)

	return result{Status: statusFail, Desc: a.Desc, Detail: failDetail(strings.TrimSpace(out))}
}

// assertJailPathDenied runs `terrarium jail -- sh -c "<op> <File>"`
// and requires a nonzero exit.
func assertJailPathDenied(ctx context.Context, a assertion) result {
	var script string

	switch a.Op {
	case "read":
		script = fmt.Sprintf("cat %q >/dev/null", a.File)
	case "write":
		script = fmt.Sprintf(": > %q", a.File)
	default:
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("unknown op %q", a.Op)}
	}

	return expectJailNonzero(ctx, a, []string{"sh", "-c", script}, func(out string) string {
		return fmt.Sprintf("expected nonzero exit, got 0: %s", out)
	})
}

// assertJailSignalDenied resolves any mainpid:<unit> tokens in
// [assertion.Cmd] and runs the resulting command under `terrarium
// jail`. Success is a nonzero exit.
func assertJailSignalDenied(ctx context.Context, a assertion) result {
	cmd, err := resolvePIDSentinel(ctx, a.Cmd)
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: err.Error()}
	}

	return expectJailNonzero(ctx, a, []string{"sh", "-c", cmd}, func(out string) string {
		return fmt.Sprintf("expected nonzero exit, got 0: %s", out)
	})
}

// assertJailNftDenied runs `terrarium jail -- nft <args...>` and
// requires a nonzero exit.
func assertJailNftDenied(ctx context.Context, a assertion) result {
	return expectJailNonzero(ctx, a, append([]string{"nft"}, a.Args...), func(out string) string {
		return fmt.Sprintf("nft succeeded inside jail (SECURITY VIOLATION): %s", out)
	})
}

// assertJailExecDenied runs `terrarium jail -- sh -c "<Cmd>"` and
// requires a nonzero exit. Cmd may contain mainpid:<unit> sentinels.
func assertJailExecDenied(ctx context.Context, a assertion) result {
	cmd, err := resolvePIDSentinel(ctx, a.Cmd)
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: err.Error()}
	}

	return expectJailNonzero(ctx, a, []string{"sh", "-c", cmd}, func(out string) string {
		return fmt.Sprintf("expected nonzero exit, got 0: %s", out)
	})
}

// assertJailExecAllowed runs `terrarium jail -- sh -c "<Cmd>"` and
// requires exit 0. Positive regression guard for denies that must not
// over-reach into benign operations.
func assertJailExecAllowed(ctx context.Context, a assertion) result {
	code, out, err := runJailed(ctx, "sh", "-c", a.Cmd)
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("running jail: %v", err)}
	}

	if code == 0 {
		return result{Status: statusPass, Desc: a.Desc}
	}

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: fmt.Sprintf("expected exit 0, got %d: %s", code, strings.TrimSpace(out)),
	}
}

// assertJailSelfProcReadAllowed runs `readlink /proc/self/fd/0` under
// the jail and requires exit 0. Guards against a future
// `deny /proc/[0-9]*/fd/** r` edit silently blocking self-introspection.
func assertJailSelfProcReadAllowed(ctx context.Context, a assertion) result {
	code, out, err := runJailed(ctx, "readlink", "/proc/self/fd/0")
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("running jail: %v", err)}
	}

	if code == 0 {
		return result{Status: statusPass, Desc: a.Desc, Detail: strings.TrimSpace(out)}
	}

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: fmt.Sprintf("expected exit 0, got %d: %s", code, strings.TrimSpace(out)),
	}
}

// assertJailRefusesNesting runs `terrarium jail -- terrarium jail --
// /bin/true`. The inner invocation must exit nonzero with an
// ErrAlreadyConfined-style message on stderr.
func assertJailRefusesNesting(ctx context.Context, a assertion) result {
	code, out, err := runJailed(ctx, "terrarium", "jail", "--", "/bin/true")
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("running jail: %v", err)}
	}

	if code == 0 {
		return result{Status: statusFail, Desc: a.Desc, Detail: "nested jail exited 0 -- confinement not attached"}
	}

	if !strings.Contains(out, "already confined") {
		return result{
			Status: statusFail, Desc: a.Desc,
			Detail: fmt.Sprintf("exit %d but stderr missing ErrAlreadyConfined: %s", code, strings.TrimSpace(out)),
		}
	}

	return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("exit %d", code)}
}

// assertApparmorProfileParses runs `apparmor_parser -Q -r <File>`
// against the named profile. Catches silent regressions from
// abstractions/base changes on every test run.
func assertApparmorProfileParses(ctx context.Context, a assertion) result {
	cmd := exec.CommandContext(ctx, "apparmor_parser", "-Q", "-r", a.File) //nolint:gosec // path from test spec

	out, err := cmd.CombinedOutput()
	if err != nil {
		return result{
			Status: statusFail, Desc: a.Desc,
			Detail: fmt.Sprintf("apparmor_parser -Q -r %s: %v\n%s", a.File, err, strings.TrimSpace(string(out))),
		}
	}

	return result{Status: statusPass, Desc: a.Desc}
}

// assertLockdownIntegrityMode verifies the kernel lockdown is in
// integrity mode.
func assertLockdownIntegrityMode(_ context.Context, a assertion) result {
	data, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("reading lockdown: %v", err)}
	}

	content := string(data)
	if strings.Contains(content, "[integrity]") {
		return result{Status: statusPass, Desc: a.Desc, Detail: strings.TrimSpace(content)}
	}

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: fmt.Sprintf("expected [integrity] mode, got %q", strings.TrimSpace(content)),
	}
}

// assertLockdownModprobeDenied expects `modprobe dummy` to fail
// because lockdown=integrity blocks unsigned module loads.
func assertLockdownModprobeDenied(ctx context.Context, a assertion) result {
	cmd := exec.CommandContext(ctx, "modprobe", "dummy")

	out, err := cmd.CombinedOutput()
	if err == nil {
		maybeDebugDump(ctx)

		return result{
			Status: statusFail, Desc: a.Desc,
			Detail: fmt.Sprintf(
				"modprobe dummy succeeded -- lockdown not effective: %s",
				strings.TrimSpace(string(out)),
			),
		}
	}

	return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("modprobe rejected: %v", err)}
}

// assertLockdownDevmemDenied expects reading /dev/mem to fail.
func assertLockdownDevmemDenied(_ context.Context, a assertion) result {
	f, err := os.Open("/dev/mem")
	if err != nil {
		return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("open rejected: %v", err)}
	}

	defer func() {
		err := f.Close()
		if err != nil {
			slog.Warn("closing /dev/mem", "err", err)
		}
	}()

	buf := make([]byte, 1)

	_, err = f.Read(buf)
	if err != nil {
		return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("read rejected: %v", err)}
	}

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: "reading /dev/mem succeeded -- lockdown not effective",
	}
}

// assertInitSubcommandRegistered runs `terrarium init --help`, which
// must exit 0 and print usage. Cheaper and safer than invoking `init
// -- /bin/true` (a daemon entrypoint).
func assertInitSubcommandRegistered(ctx context.Context, a assertion) result {
	cmd := exec.CommandContext(ctx, "terrarium", "init", "--help")

	out, err := cmd.CombinedOutput()
	if err != nil {
		return result{
			Status: statusFail, Desc: a.Desc,
			Detail: fmt.Sprintf("terrarium init --help: %v\n%s", err, strings.TrimSpace(string(out))),
		}
	}

	if !regexp.MustCompile(`(?i)usage`).Match(out) {
		return result{
			Status: statusFail, Desc: a.Desc,
			Detail: fmt.Sprintf("no usage in output: %s", strings.TrimSpace(string(out))),
		}
	}

	return result{Status: statusPass, Desc: a.Desc}
}
