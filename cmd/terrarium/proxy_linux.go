package main

import "syscall"

// proxyEnvoyProcAttr returns the process attributes of the Envoy that
// [Proxy] runs.
//
// Envoy runs in a process group of its own. A terminal sends the signal
// of a Ctrl-C to each process of its foreground group, and Envoy stops
// at once on SIGINT. In the group of the proxy, Envoy therefore stops
// before the wait for its last events.
//
// The kernel sends SIGKILL to Envoy when the proxy dies. Outside the
// group of the proxy, Envoy does not receive the signals that end the
// group, such as a SIGKILL that a shell sends to a job or the SIGQUIT
// of a Ctrl-\. The signal of the kernel makes sure that Envoy does not
// outlive the proxy and hold the listen address. The kernel sends it
// when the thread that started Envoy exits, so [startEnvoyProcess]
// keeps that thread until Envoy has exited.
func proxyEnvoyProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
