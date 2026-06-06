package status

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// clockTicksPerSecond is the _SC_CLK_TCK value used to convert
// /proc/<pid>/stat starttime from clock ticks to seconds. The Linux
// default has been 100 since 2.6; golang.org/x/sys/unix does not
// expose Sysconf on Linux, so hardcoding avoids cgo. Systems with a
// non-default CONFIG_HZ (embedded kernels, some custom builds) will
// render an incorrect uptime, but those targets are out of scope.
const clockTicksPerSecond = 100

// collectProcess gathers daemon liveness and Envoy child discovery.
// All PID file read errors are reported on [ProcessSection.Err]
// except [fs.ErrNotExist], which maps to [DaemonNotRunning] so a
// missing PID file reads as "the daemon is not running" rather than
// "something went wrong."
func collectProcess(pidFile string) ProcessSection {
	s := ProcessSection{
		Daemon: DaemonProcess{PIDFile: pidFile},
	}

	pid, err := readPIDFile(pidFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		s.Daemon.State = DaemonNotRunning
		return s

	case errors.Is(err, fs.ErrPermission):
		s.Daemon.State = DaemonUnknown
		s.Err = err

		return s

	case err != nil:
		s.Daemon.State = DaemonUnknown
		s.Err = err

		return s
	}

	s.Daemon.PID = pid

	alive, err := processAlive(pid)
	if err != nil {
		s.Daemon.State = DaemonUnknown
		s.Err = err

		return s
	}

	if !alive {
		s.Daemon.State = DaemonNotRunning
		s.Daemon.Stale = true

		return s
	}

	s.Daemon.State = DaemonRunning

	uptime, err := processUptime(pid)
	if err == nil {
		s.Daemon.Uptime = uptime
		s.Daemon.UptimeOK = true
	}

	s.Envoy = findEnvoyChild(pid)

	return s
}

// readPIDFile reads and parses a PID file. A file that does not exist
// yields an error that wraps [fs.ErrNotExist] so the caller can
// distinguish "no daemon" from "permission denied."
func readPIDFile(path string) (int, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path.
	if err != nil {
		return 0, fmt.Errorf("reading PID file %s: %w", path, err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parsing PID file %s: %w", path, err)
	}

	return pid, nil
}

// processAlive reports whether the given PID is a live process. It
// checks /proc/<pid> first so a non-existent PID never looks alive,
// then uses signal 0 as a belt-and-suspenders liveness check.
// EPERM from signal 0 is treated as alive, because the kernel only
// denies signals to processes it already knows about.
func processAlive(pid int) (bool, error) {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}

		return false, fmt.Errorf("stat /proc/%d: %w", pid, err)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return false, fmt.Errorf("finding process %d: %w", pid, err)
	}

	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true, nil
	}

	if errors.Is(err, syscall.ESRCH) {
		return false, nil
	}

	if errors.Is(err, syscall.EPERM) {
		return true, nil
	}

	return false, fmt.Errorf("signaling process %d: %w", pid, err)
}

// processUptime returns the running duration of pid computed from
// /proc/<pid>/stat's starttime field (clock ticks since boot) and
// /proc/uptime's total uptime. Returns an error if either source
// fails to parse.
func processUptime(pid int) (time.Duration, error) {
	starttime, err := readProcStarttime(pid)
	if err != nil {
		return 0, err
	}

	bootElapsed, err := readSystemUptime()
	if err != nil {
		return 0, err
	}

	procSeconds := float64(starttime) / float64(clockTicksPerSecond)

	dur := time.Duration((bootElapsed - procSeconds) * float64(time.Second))
	if dur < 0 {
		return 0, fmt.Errorf("negative uptime for pid %d", pid)
	}

	return dur, nil
}

// readProcStarttime reads /proc/<pid>/stat and returns its starttime
// field. See [parseProcStarttime] for the parsing algorithm.
func readProcStarttime(pid int) (uint64, error) {
	path := fmt.Sprintf("/proc/%d/stat", pid)

	data, err := os.ReadFile(path) //nolint:gosec // well-known /proc path.
	if err != nil {
		return 0, fmt.Errorf("reading %s: %w", path, err)
	}

	return parseProcStarttime(string(data))
}

// parseProcStarttime extracts field 22 (starttime, clock ticks since
// boot) from a /proc/<pid>/stat line. The comm field (pid's
// executable name) may contain spaces and parentheses, so the parser
// uses the "last ')' in the line wins" algorithm: the rightmost ')'
// ends comm, and everything after it splits cleanly on single
// spaces.
func parseProcStarttime(line string) (uint64, error) {
	line = strings.TrimRight(line, "\n")

	endComm := strings.LastIndexByte(line, ')')
	if endComm == -1 || endComm+2 >= len(line) {
		return 0, fmt.Errorf("malformed /proc stat line")
	}

	// After "(comm)", a single space separator precedes state.
	tail := strings.Fields(line[endComm+2:])

	// Field 22 (starttime) is the 20th entry in the post-')' tail:
	// pid and (comm) are consumed before the split, so field 3
	// (state) is index 0, field 22 (starttime) is index 19.
	const starttimeTailIndex = 19

	if len(tail) <= starttimeTailIndex {
		return 0, fmt.Errorf("truncated /proc stat line (%d fields)", len(tail))
	}

	starttime, err := strconv.ParseUint(tail[starttimeTailIndex], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing /proc stat starttime: %w", err)
	}

	return starttime, nil
}

// readSystemUptime parses /proc/uptime and returns the first field
// (total seconds since boot) as a float.
func readSystemUptime() (float64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, fmt.Errorf("reading /proc/uptime: %w", err)
	}

	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, errors.New("empty /proc/uptime")
	}

	uptime, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, fmt.Errorf("parsing /proc/uptime: %w", err)
	}

	return uptime, nil
}

// findEnvoyChild looks for an Envoy subprocess beneath the daemon PID
// using /proc/<pid>/task/<pid>/children. The file contains a
// space-separated list of child PIDs. We confirm each candidate by
// reading /proc/<child>/comm, which matches exactly "envoy" when the
// child is the upstream binary. Returns an [EnvoyProcess] whose
// State encodes which of these paths failed: a missing children file
// (indicating CONFIG_PROC_CHILDREN may not be compiled in) produces
// [DaemonUnknown], while a successful match produces [DaemonRunning].
func findEnvoyChild(daemonPID int) EnvoyProcess {
	childrenPath := fmt.Sprintf("/proc/%d/task/%d/children", daemonPID, daemonPID)

	data, err := os.ReadFile(childrenPath) //nolint:gosec // well-known /proc path.
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return EnvoyProcess{State: DaemonUnknown}
		}

		return EnvoyProcess{State: DaemonUnknown, Err: err}
	}

	for field := range strings.FieldsSeq(string(data)) {
		pid, err := strconv.Atoi(field)
		if err != nil {
			continue
		}

		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			// Child exited between the children read and now. A
			// race; don't retry.
			continue
		}

		if strings.TrimSpace(string(comm)) == "envoy" {
			return EnvoyProcess{State: DaemonRunning, PID: pid}
		}
	}

	return EnvoyProcess{State: DaemonUnknown}
}
