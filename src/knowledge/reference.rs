//! The committed reference list of commands that take a command operand,
//! hand-curated from coreutils, util-linux, busybox and the shells' own
//! dispatch builtins. A test fails when a listed name has no
//! [`CommandSpec`](super::spec::CommandSpec), which closes the #638 class
//! of "a wrapper nobody classified" for every command named here.
//!
//! The test cannot discover wrappers upstream adds later: re-audit this
//! list at each release and whenever a wrapper bypass is filed. Left out on
//! purpose: commands whose program sits behind an option rather than in an
//! operand slot (`start-stop-daemon --exec`) and the tcpsvd/udpsvd
//! `IP PORT PROG` shape, which need roles this stage does not define.

pub(super) const EXEC_WRAPPER_REFERENCE: &[&str] = &[
    // coreutils
    "env",
    "nice",
    "nohup",
    "timeout",
    "stdbuf",
    "chroot",
    "runcon",
    // uutils multicall binary: `coreutils rm -rf /`
    "coreutils",
    // util-linux
    "chrt",
    "choom",
    "flock",
    "ionice",
    "nsenter",
    "prlimit",
    "runuser",
    "script",
    "setarch",
    "linux32",
    "linux64",
    "i386",
    "x86_64",
    "uname26",
    "setpriv",
    "setsid",
    "su",
    "taskset",
    "unshare",
    // busybox and runit applets
    "busybox",
    "toybox",
    "oils-for-unix",
    "oils_for_unix",
    "chpst",
    "envdir",
    "envuidgid",
    "setuidgid",
    "softlimit",
    // privilege wrappers
    "sudo",
    "doas",
    "pkexec",
    "run0",
    // GNU time, procps, findutils and other command runners
    "time",
    "watch",
    "xargs",
    "strace",
    "numactl",
    "caffeinate",
    "firejail",
    "systemd-run",
    "unbuffer",
    "arch",
    "sandbox-exec",
    "valgrind",
    "fakeroot",
    "rlwrap",
    // shell dispatch builtins
    "builtin",
    "command",
    "exec",
];
