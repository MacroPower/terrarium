// Package status produces a read-only diagnostic view of a running
// [terrarium daemon] by introspecting file, process, and kernel state.
//
// Status has no IPC channel to the daemon. Every section reads its own
// source independently (PID file, /proc, nftables netlink, envoy.yaml,
// log files), and any one of them can fail without affecting the
// others. Section-level failures are stored on the [Report] rather
// than returned, so partial output (for example, envoy listeners and
// log tails when nftables access is denied) is always rendered.
//
// [terrarium daemon]: https://github.com/jacobcolvin/terrarium
package status
