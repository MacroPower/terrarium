// Package jail arms an AppArmor profile transition on the current
// thread and then calls execve to enter confinement. It implements
// the hidden "terrarium jail" subcommand, which trusted callers use
// to voluntarily downgrade into [terrarium.workload] before running
// untrusted code.
//
// The caller must hold [runtime.LockOSThread] before calling [Exec].
// The reason differs from [privdrop]: here, the write to
// /proc/self/attr/apparmor/exec is a per-thread arming that the kernel
// clears on any execve from that thread. Without the lock, the Go
// runtime may migrate the goroutine between the arming write and
// [syscall.Exec], leaving the transition on a thread that never runs
// the exec. Locking ensures the arming write and the final execve
// happen on the same OS thread.
//
// Composition constraints:
//
//   - Call [Exec] before any privilege drop. Once terrarium init has
//     dropped privileges, a transition into terrarium.workload requires
//     either being unconfined or holding CAP_MAC_ADMIN; both are gone
//     post-drop, so composing terrarium init -- terrarium jail -- cmd
//     fails.
//   - Composing terrarium jail -- terrarium init -- cmd is also
//     unsupported. terrarium init needs CAP_NET_ADMIN in its
//     inheritable/ambient sets to spawn envoy, and the workload profile
//     does not grant net_admin.
package jail
