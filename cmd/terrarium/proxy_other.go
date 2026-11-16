//go:build !linux

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
// Outside the group of the proxy, Envoy does not receive the signals
// that end the group, such as a SIGKILL that a shell sends to a job or
// the SIGQUIT of a Ctrl-\. Only Linux can make the kernel stop Envoy
// when the proxy dies, so on other systems Envoy keeps running after
// such a signal and holds the listen address.
func proxyEnvoyProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
