// Package privdrop performs Linux privilege-dropping syscalls before
// execve, replacing the need for setpriv (util-linux).
//
// The caller must hold [runtime.LockOSThread] before calling [Exec],
// because capability syscalls (capset, prctl) are per-thread. Locking
// ensures all privilege manipulations and the final execve happen on
// the same OS thread.
//
// Two privilege-drop paths are supported:
//
//   - Ambient caps preserved (e.g. Envoy with CAP_NET_ADMIN): uses
//     PR_SET_KEEPCAPS across the UID transition, then sets inheritable
//     and ambient caps on the new identity.
//   - Full drop (e.g. user command): clears the bounding set and
//     inheritable caps while still root, sets PR_SET_NO_NEW_PRIVS,
//     then transitions UID. The kernel auto-clears permitted and
//     effective caps on the UID change.
package privdrop
