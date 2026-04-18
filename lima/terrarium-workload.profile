abi <abi/3.0>,

include <tunables/global>

profile terrarium.workload flags=(attach_disconnected,mediate_deleted) {
  include <abstractions/base>

  # --- Capability allow-list. Intentionally omitted caps: sys_module,
  # sys_admin, net_admin, mac_admin, mac_override, sys_boot, sys_rawio,
  # bpf, checkpoint_restore, linux_immutable, sys_time, audit_control,
  # wake_alarm, block_suspend, ipc_owner, mknod, audit_read, sys_pacct.
  # AppArmor's implicit-deny handles them once any capability rule exists.
  #
  # Granted caps that deserve a closer look -- each is backstopped by a
  # stricter in-profile rule so the workload cannot escalate beyond its
  # peer set:
  #
  #   sys_ptrace: cross-profile attach is blocked at the AppArmor layer
  #   by `ptrace peer=terrarium.workload` (see below), and
  #   `deny /proc/[0-9]*/mem rw` blocks the path-based route to other
  #   processes' memory. Caveat: CAP_SYS_PTRACE also unlocks
  #   process_vm_readv(2) / process_vm_writev(2), which are syscall-level
  #   and not path-mediated -- same-profile siblings share an intra-profile
  #   fd/memory introspection surface. Isolate sensitive fds at the
  #   application layer.
  #
  #   syslog: grants SYSLOG_ACTION_READ_ALL / SYSLOG_ACTION_CLEAR on the
  #   kernel ring buffer. The companion `deny /proc/sys/kernel/dmesg_restrict w`
  #   stops the workload from flipping the sysctl and widening read access
  #   for unconfined neighbors. (lockdown=integrity does not mediate
  #   syslog(2), so don't rely on it for this cap.)
  #
  #   perfmon: restores userspace perf event access under
  #   perf_event_paranoid=2. `deny /proc/sys/kernel/perf_event_paranoid w`
  #   keeps the workload from lowering the sysctl, and lockdown=integrity
  #   blocks the higher-risk perf paths (raw tracepoints, kernel address
  #   leaks).
  capability chown,
  capability dac_override,
  capability dac_read_search,
  capability fowner,
  capability fsetid,
  capability kill,
  capability setgid,
  capability setuid,
  capability setpcap,
  capability net_bind_service,
  capability net_raw,
  capability ipc_lock,
  capability sys_chroot,
  capability sys_nice,
  capability sys_ptrace,
  capability sys_resource,
  capability perfmon,
  capability sys_tty_config,
  capability lease,
  capability syslog,
  capability audit_write,

  # --- File baseline: broad read, same-profile exec. Reads are gated by
  # the targeted denies below (AppArmor's deny precedence ensures
  # /var/lib/terrarium/ca/** stays unreadable even with /** r).
  / r,
  /** r,
  /** ix,

  # --- Terrarium assets: deny writes; deny reads of secret material.
  deny /var/lib/terrarium/** wl,
  deny /var/lib/terrarium/ca/** r,
  deny /var/lib/terrarium/certs/** r,
  deny /run/terrarium/** wl,
  deny /etc/terrarium/** wl,
  deny /usr/local/share/ca-certificates/** wl,
  deny /etc/resolv.conf wl,
  deny /etc/dnsmasq-hosts wl,

  # --- Terrarium process introspection. Block env leakage and direct
  # memory access to the daemon. ASLR/layout (maps, smaps, numa_maps)
  # and kernel runtime-state surfaces (syscall, stack, wchan) are
  # readable -- they only help sophisticated exploit development,
  # which is out of scope for this profile.
  #
  # These wildcard denies intentionally match /proc/self/* too. AppArmor
  # cannot split a wildcard deny by pid (deny always wins over allow;
  # owner/@{pid} rules don't override deny), and the workload is root so
  # DAC is not a fallback. Workloads should read their own env via
  # environ(7) / libc rather than /proc/self/environ.
  deny /proc/[0-9]*/environ r,
  deny /proc/[0-9]*/mem rw,

  # --- Rebuild / nix-store manipulation.
  deny /etc/nixos/** wl,
  deny /var/lib/nixos/** wl,
  deny /nix/var/nix/profiles/** wl,
  deny /nix/var/nix/gcroots/** wl,
  deny /nix/store/** wl,
  deny /boot/** wl,

  # --- Systemd / dbus escape hatches.
  deny /etc/systemd/system/** wl,
  deny /run/systemd/system/** wl,
  deny /run/systemd/private rw,
  deny /run/systemd/notify w,
  deny /run/dbus/system_bus_socket rw,

  # --- Login / privilege paths.
  deny /etc/sudoers* wl,
  deny /etc/sudoers.d/** wl,
  deny /etc/pam.d/** wl,
  deny /etc/ssh/** wl,
  deny /root/.ssh/** wl,
  deny /etc/ld.so.preload wl,
  deny /etc/ld.so.cache wl,

  # --- Password-hash surfaces. Not DAC-enforced once /** r is granted.
  deny /etc/shadow* r,
  deny /etc/gshadow* r,
  deny /etc/security/opasswd* r,

  # --- AppArmor policy protection. `/proc/self/attr/** w` is defense in
  # depth -- the kernel already blocks cross-profile transitions without
  # cap_mac_admin, but a deny here gives a cleaner audit trail if someone
  # tries.
  deny /sys/kernel/security/apparmor/** w,
  deny /etc/apparmor.d/** wl,
  deny /etc/apparmor/** wl,
  deny /proc/self/attr/** w,
  deny /proc/thread-self/attr/** w,

  # --- Mount / kernel-path writes (cap deny is handled by the allow-list
  # omission; these are the path-side complements).
  deny mount,
  deny remount,
  deny umount,
  deny pivot_root,
  deny /sys/module/** wl,
  deny /proc/sysrq-trigger w,
  deny /proc/sys/kernel/modules_disabled w,
  deny /proc/sys/kernel/kexec_load_disabled w,
  deny /proc/sys/kernel/unprivileged_userns_clone w,
  deny /proc/sys/kernel/kptr_restrict w,
  deny /proc/sys/kernel/dmesg_restrict w,
  deny /proc/sys/kernel/perf_event_paranoid w,
  deny /proc/sys/vm/** w,
  deny /sys/fs/cgroup/** w,
  # Wildcard deny matches /proc/self/oom_score_adj too. AppArmor cannot
  # split a wildcard deny by pid and DAC is not a fallback for root, so
  # the workload cannot tune its own OOM score either.
  deny /proc/*/oom_score_adj w,
  deny /dev/mem rw,
  deny /dev/kmem rw,
  deny /dev/kmsg w,
  deny /dev/kvm rw,
  deny /dev/uio* rw,
  deny /dev/vfio/** rw,

  # --- nftables / netfilter. Ruleset mutation and enumeration require
  # CAP_NET_ADMIN (omitted from the allow-list above), so netlink
  # mediation is unnecessary here. These are the path-side backstops
  # against sysctl-style conntrack/netfilter tuning.
  deny /proc/net/nf_conntrack rw,
  deny /proc/net/nf_conntrack_expect rw,
  deny /proc/net/ip_conntrack rw,
  deny /proc/net/ip_conntrack_expect rw,
  deny /sys/module/nf_conntrack/** w,
  deny /proc/sys/net/netfilter/** w,
  deny /proc/sys/net/ipv4/conf/**/rp_filter w,
  deny /proc/sys/net/ipv6/conf/**/rp_filter w,

  # --- Peer protections. Same-profile allowed so normal process-tree
  # patterns (bash signalling its children, a shell pipeline's SIGPIPE,
  # Go runtime's SIGURG) work. Cross-profile defaults to deny because at
  # least one rule of each type is present.
  #
  # Peer name is left as the bare short form; on NixOS-loaded profiles
  # under a namespace (:root://terrarium.workload), the bare form may
  # fail to match. Hard gate #5 is an explicit same-profile signal/ptrace
  # test inside two jailed processes. If that gate fails, switch the peer
  # qualifier to the namespaced form or use @{profile_name} -- do NOT
  # relax to an unqualified allow.
  signal (send,receive) peer=terrarium.workload,
  signal (receive),
  ptrace (trace,tracedby) peer=terrarium.workload,
  ptrace (read,readby)   peer=terrarium.workload,
}
