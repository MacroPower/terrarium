package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// envoyGuardCommand is the first argument of the terrarium process
// that runs [envoyGuardMain] in place of the command tree.
const envoyGuardCommand = "envoy-guard"

// envoyGuardReady is the text that the guard process writes to its
// stdout after it ignores the signals of [envoyGuardIgnoredSignals].
// [startEnvoyGuard] returns only after it has read that text.
const envoyGuardReady = "ready\n"

// envoyGuardIgnoredSignals are the signals that the guard process
// ignores. Go ends or stops a process on each of them by default. A Go
// program can ignore each of them when another process sends it.
//
// The guard process runs the terrarium binary, so it has the name of
// the proxy. A signal sent by that name, such as with
// `pkill -QUIT terrarium`, reaches the proxy and the guard process
// together. When such a signal kills the proxy, a guard process that
// the signal ended or stopped leaves Envoy behind. A guard process that
// ignores the signals also leaves the proxy to stop Envoy gracefully
// after a SIGTERM or a SIGINT.
//
// A fault of the guard process itself still ends it. Go does not let a
// program ignore a SIGSEGV, a SIGBUS, a SIGFPE, or a SIGILL that its
// own code raises.
var envoyGuardIgnoredSignals = []os.Signal{
	syscall.SIGHUP,
	syscall.SIGINT,
	syscall.SIGQUIT,
	syscall.SIGILL,
	syscall.SIGTRAP,
	syscall.SIGABRT,
	syscall.SIGBUS,
	syscall.SIGFPE,
	syscall.SIGSEGV,
	syscall.SIGSYS,
	syscall.SIGTERM,
	syscall.SIGTSTP,
	syscall.SIGTTIN,
	syscall.SIGTTOU,
}

// envoyGuard is a process that kills the Envoy of a proxy when the
// proxy dies without a shutdown. [Proxy] starts one on the systems
// whose kernel has no parent-death signal.
//
// The guard process leads a process group of its own, and the proxy
// starts Envoy in that group with [envoyGuard.procAttr]. The guard
// process reads a pipe, and the proxy holds the one write end of that
// pipe. The kernel closes that end when the proxy dies, whichever
// signal or fault ends the proxy. The read of the guard process then
// ends, and the guard process sends SIGKILL to its group. See
// [envoyGuardMain] for the process.
//
// The guard process runs before Envoy starts, so a proxy that dies at
// any moment leaves no Envoy behind. The guard process ignores the
// signals of [envoyGuardIgnoredSignals], so few signals end or stop
// the proxy and the guard process together. Those signals are SIGKILL,
// SIGSTOP, and the signals of one system, such as the SIGEMT of macOS.
// Each of them leaves Envoy running without a guard. So does each of
// them sent to the guard process alone, and so does a fault of the
// guard process.
//
// Start instances with [startEnvoyGuard], and stop them with
// [envoyGuard.stop].
type envoyGuard struct {
	cmd *exec.Cmd

	// The write end of the pipe that the guard process reads. The
	// proxy never writes to it.
	pipe *os.File
}

// startEnvoyGuard starts a guard process and returns its
// [*envoyGuard]. The process runs the executable of the caller with
// the argument [envoyGuardCommand], so that executable must run
// [envoyGuardMain] for that argument.
//
// The function returns after the guard process has written
// [envoyGuardReady], so the guard process ignores the signals of
// [envoyGuardIgnoredSignals] before the caller starts Envoy. When the
// guard process exits or writes other text first, startEnvoyGuard
// kills it and returns an error.
//
// The guard process outlives ctx. The caller must stop it with
// [envoyGuard.stop]. The caller must also keep the returned
// [*envoyGuard] reachable until then. When the garbage collector
// frees it, the finalizer of the pipe closes the write end of the
// guard pipe. The guard process then kills its group.
func startEnvoyGuard(ctx context.Context) (*envoyGuard, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("finding the terrarium executable for the envoy guard: %w", err)
	}

	return startEnvoyGuardProcess(ctx, exe)
}

// startEnvoyGuardProcess starts the executable exe with the argument
// [envoyGuardCommand] as a guard process, as [startEnvoyGuard] does
// for the executable of the caller.
func startEnvoyGuardProcess(ctx context.Context, exe string) (*envoyGuard, error) {
	// Each end of both pipes closes on exec. No other child of the
	// proxy therefore holds the write end of the guard pipe open
	// after the proxy dies.
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("creating the pipe of the envoy guard: %w", err)
	}

	readyR, readyW, err := os.Pipe()
	if err != nil {
		closePipeEnd(ctx, r, "read end of the envoy guard pipe")
		closePipeEnd(ctx, w, "write end of the envoy guard pipe")

		return nil, fmt.Errorf("creating the ready pipe of the envoy guard: %w", err)
	}

	// The guard process ends with its group, not with ctx. Its stdout
	// is the ready pipe and it has no stderr, so it never writes to a
	// terminal from its background process group.
	//
	//nolint:gosec // G204: the executable of this process.
	cmd := exec.CommandContext(context.WithoutCancel(ctx), exe, envoyGuardCommand)
	cmd.Stdin = r
	cmd.Stdout = readyW
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err = cmd.Start()

	// The guard process holds its own copies of these ends.
	closePipeEnd(ctx, r, "read end of the envoy guard pipe")
	closePipeEnd(ctx, readyW, "write end of the envoy guard ready pipe")

	if err != nil {
		closePipeEnd(ctx, readyR, "read end of the envoy guard ready pipe")
		closePipeEnd(ctx, w, "write end of the envoy guard pipe")

		return nil, fmt.Errorf("starting the envoy guard %s: %w", exe, err)
	}

	guard := &envoyGuard{cmd: cmd, pipe: w}

	// The read ends with an EOF when the guard process exits before
	// it writes.
	buf := make([]byte, len(envoyGuardReady))
	_, err = io.ReadFull(readyR, buf)

	closePipeEnd(ctx, readyR, "read end of the envoy guard ready pipe")

	if err == nil && string(buf) != envoyGuardReady {
		err = fmt.Errorf("unexpected output %q", buf)
	}

	if err != nil {
		guard.stop(ctx)

		return nil, fmt.Errorf("waiting for the envoy guard %s: %w", exe, err)
	}

	return guard, nil
}

// closePipeEnd closes the pipe end f, and logs the error of the close
// with the name of the pipe end name.
func closePipeEnd(ctx context.Context, f *os.File, name string) {
	err := f.Close()
	if err != nil {
		slog.DebugContext(ctx, "closing an envoy guard pipe end",
			slog.String("pipe", name),
			slog.Any("err", err),
		)
	}
}

// procAttr returns the process attributes that start a process in the
// process group of the guard. The guard kills each process of that
// group when the calling process dies, and [envoyGuard.stop] kills
// them as well.
//
// The group exists until [envoyGuard.stop] reaps the guard process,
// even after the guard process has died. A process that starts with
// these attributes after a SIGKILL or a fault of the guard process
// therefore starts without an error and runs without a guard.
func (g *envoyGuard) procAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pgid: g.cmd.Process.Pid}
}

// stop sends SIGKILL to each process in the group of the guard, and
// waits until the guard process has exited. A caller that wants a
// graceful stop of Envoy must therefore stop Envoy first.
//
// The signal comes from stop itself, so stop does not depend on the
// read of the guard process. The process ID of the guard names its
// group until stop has waited for the process. The signal therefore
// never reaches a process outside the group.
func (g *envoyGuard) stop(ctx context.Context) {
	err := syscall.Kill(-g.cmd.Process.Pid, syscall.SIGKILL)
	if err != nil && !errors.Is(err, syscall.ESRCH) {
		slog.WarnContext(ctx, "killing the process group of the envoy guard", slog.Any("err", err))
	}

	// Without the signal, the closed pipe still ends the read of the
	// guard process.
	closePipeEnd(ctx, g.pipe, "write end of the envoy guard pipe")

	// The wait reports the signal that killed the guard process.
	err = g.cmd.Wait()

	var exitErr *exec.ExitError

	if err != nil && !errors.As(err, &exitErr) {
		slog.DebugContext(ctx, "waiting for the envoy guard", slog.Any("err", err))
	}
}

// envoyGuardMain is the entrypoint of the guard process of an
// [envoyGuard]. It ignores the signals of [envoyGuardIgnoredSignals],
// writes [envoyGuardReady] to stdout, and reads stdin until the read
// ends. Then it sends SIGKILL to each process of its own process
// group, which includes itself. It does not return.
//
// The read ends when each write end of the pipe on stdin has closed.
// The process that started the guard holds the only write end, so the
// read ends when that process closes the pipe or dies. An error also
// ends the read, because a guard that cannot read the pipe cannot
// learn that the process died.
//
// The process must lead its process group, as the process of
// [startEnvoyGuard] does. For every other process, envoyGuardMain
// exits with status 1 and sends no signal. The check keeps the signal
// away from the group of a shell or a script that runs the command by
// hand.
func envoyGuardMain() {
	if syscall.Getpgrp() != os.Getpid() {
		fmt.Fprintf(os.Stderr, "terrarium %s: this process does not lead its process group\n",
			envoyGuardCommand)
		os.Exit(1)
	}

	signal.Ignore(envoyGuardIgnoredSignals...)

	// The process that started the guard starts no process in the
	// group until it has read this text. A guard that cannot write
	// it therefore exits without a signal.
	_, err := os.Stdout.WriteString(envoyGuardReady)
	if err != nil {
		fmt.Fprintf(os.Stderr, "terrarium %s: writing stdout: %v\n", envoyGuardCommand, err)
		os.Exit(1)
	}

	_, err = io.Copy(io.Discard, os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "terrarium %s: reading stdin: %v\n", envoyGuardCommand, err)
	}

	err = syscall.Kill(0, syscall.SIGKILL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "terrarium %s: killing the process group: %v\n", envoyGuardCommand, err)
	}

	// The signal has killed this process unless the kill returned an
	// error.
	os.Exit(1)
}
