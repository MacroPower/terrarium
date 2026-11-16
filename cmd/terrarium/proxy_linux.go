package main

import "syscall"

// proxyEnvoyGuarded reports whether [Proxy] starts an [envoyGuard] for
// its Envoy. On Linux, the parent-death signal of the kernel does the
// work of the guard, so Proxy starts none.
const proxyEnvoyGuarded = false

// proxyEnvoyProcAttr returns the process attributes of the Envoy that
// [Proxy] runs. It does not read guard, which is nil on Linux.
//
// Envoy runs in a process group of its own. A terminal sends the signal
// of a Ctrl-C to each process of its foreground group, and Envoy stops
// at once on SIGINT. In the group of the proxy, Envoy therefore stops
// before the wait for its last events.
//
// Outside the group of the proxy, Envoy does not receive the signals
// that end the group. A SIGKILL that a shell sends to a job and the
// SIGQUIT of a Ctrl-\ are such signals. The kernel therefore sends
// SIGKILL to Envoy when the proxy dies, so Envoy does not outlive the
// proxy and hold the listen address. The kernel sends the signal when
// the thread that started Envoy exits, so [startEnvoyProcess] keeps
// that thread until Envoy has exited.
func proxyEnvoyProcAttr(_ *envoyGuard) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
