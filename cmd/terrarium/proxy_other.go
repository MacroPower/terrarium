//go:build !linux

package main

import "syscall"

// proxyEnvoyGuarded reports whether [Proxy] starts an [envoyGuard] for
// its Envoy. Only Linux can make the kernel stop Envoy when the proxy
// dies, so on every other system Proxy starts a guard.
const proxyEnvoyGuarded = true

// proxyEnvoyProcAttr returns the process attributes of the Envoy that
// [Proxy] runs with the guard process guard.
//
// Envoy runs in the process group of guard and not in the group of the
// proxy. A terminal sends the signal of a Ctrl-C to each process of its
// foreground group, and Envoy stops at once on SIGINT. In the group of
// the proxy, Envoy therefore stops before the wait for its last events.
//
// Outside the group of the proxy, Envoy does not receive the signals
// that end the group. A SIGKILL that a shell sends to a job and the
// SIGQUIT of a Ctrl-\ are such signals. The guard therefore kills
// Envoy when the proxy dies, so Envoy does not outlive the proxy and
// hold the listen address.
func proxyEnvoyProcAttr(guard *envoyGuard) *syscall.SysProcAttr {
	return guard.procAttr()
}
