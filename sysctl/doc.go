// Package sysctl provides synchronous read/write access to Linux kernel
// parameters through the /proc/sys filesystem.
//
// Parameter names are modeled as variadic string arguments matching the
// path components under /proc/sys. For example, the kernel parameter
// net.ipv4.ip_forward corresponds to the arguments "net", "ipv4",
// "ip_forward", which resolves to the file /proc/sys/net/ipv4/ip_forward.
//
// The implementation is inspired by Cilium's directSysctl, adapted to
// use the standard library without external filesystem abstractions.
package sysctl
