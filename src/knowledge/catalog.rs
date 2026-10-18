//! The embedded command catalog: one [`CommandSpec`] per command (or group
//! of names sharing a grammar). Adding an exec wrapper is one entry here
//! plus its name in `reference::EXEC_WRAPPER_REFERENCE`.
//!
//! Grammar rules of thumb: an option listed with the wrong arity hides the
//! wrapped command, so only options with a documented arity are listed;
//! everything else stays unmodelled and floors to Ask. Optional values that
//! are attached only (`--mount[=file]`, `xargs -i[str]`, env's
//! `--block-signal[=sig]`) are `*_glued`, never separated values.

use super::spec::{ArgOrder, CommandSpec, CwdEffect, OptionGrammar, Slot};

const EXEC: Slot = Slot::Exec;
const BASE: OptionGrammar = OptionGrammar::EMPTY;

const SETARCH_OPTIONS: OptionGrammar = OptionGrammar {
    short_flags: "v34BFILRSTXZhV",
    long_flags: &[
        "verbose",
        "3gb",
        "4gb",
        "32bit",
        "fdpic-funcptrs",
        "short-inode",
        "addr-compat-layout",
        "addr-no-randomize",
        "whole-seconds",
        "sticky-timeouts",
        "read-implies-exec",
        "mmap-page-zero",
        "uname-2.6",
        "list",
        "help",
        "version",
    ],
    ..BASE
};

pub(super) static CATALOG: &[CommandSpec] = &[
    CommandSpec {
        names: &["env"],
        options: OptionGrammar {
            short_flags: "0iv",
            short_values: "uCSPa",
            long_flags: &[
                "ignore-environment",
                "null",
                "debug",
                "list-signal-handling",
                "help",
                "version",
            ],
            long_values: &["unset", "chdir", "split-string", "argv0"],
            long_glued: &["default-signal", "ignore-signal", "block-signal"],
            bare_dash_option: true,
            assignments: true,
            ..BASE
        },
        slots: &[
            EXEC,
            Slot::SplitString {
                short: 'S',
                long: "split-string",
            },
            Slot::Cwd {
                short: 'C',
                long: "chdir",
                effect: CwdEffect::Composed,
            },
        ],
    },
    CommandSpec {
        names: &["command"],
        options: OptionGrammar {
            short_flags: "pVv",
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["nohup"],
        options: OptionGrammar {
            long_flags: &["help", "version"],
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["nice"],
        options: OptionGrammar {
            short_values: "n",
            long_values: &["adjustment"],
            long_flags: &["help", "version"],
            numeric_option: true,
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["exec"],
        options: OptionGrammar {
            short_flags: "cl",
            short_values: "a",
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["stdbuf"],
        options: OptionGrammar {
            short_values: "ioe",
            long_values: &["input", "output", "error"],
            long_flags: &["help", "version"],
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["setsid"],
        options: OptionGrammar {
            short_flags: "cfwhV",
            long_flags: &["ctty", "fork", "wait", "help", "version"],
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["sudo"],
        options: OptionGrammar {
            short_flags: "AbBEeHiKklnPSsVv",
            short_values: "ugCDhpRrtTUac",
            long_flags: &[
                "askpass",
                "background",
                "bell",
                "edit",
                "set-home",
                "help",
                "login",
                "remove-timestamp",
                "reset-timestamp",
                "list",
                "non-interactive",
                "preserve-groups",
                "stdin",
                "shell",
                "version",
                "validate",
            ],
            long_values: &[
                "user",
                "group",
                "close-from",
                "chdir",
                "host",
                "prompt",
                "chroot",
                "role",
                "type",
                "command-timeout",
                "other-user",
                "auth-type",
                "login-class",
            ],
            long_glued: &["preserve-env"],
            ..BASE
        },
        slots: &[
            EXEC,
            Slot::Privilege,
            Slot::Cwd {
                short: 'D',
                long: "chdir",
                effect: CwdEffect::Relocates,
            },
            Slot::Cwd {
                short: 'R',
                long: "chroot",
                effect: CwdEffect::Relocates,
            },
            Slot::CwdSwitch {
                short: 'i',
                long: "login",
                effect: CwdEffect::Relocates,
            },
            Slot::CwdSwitch {
                short: 's',
                long: "shell",
                effect: CwdEffect::Relocates,
            },
        ],
    },
    CommandSpec {
        names: &["xargs"],
        options: OptionGrammar {
            short_flags: "0oprtx",
            short_values: "EIJLnPRSsad",
            short_glued: "eil",
            long_flags: &[
                "null",
                "open-tty",
                "interactive",
                "no-run-if-empty",
                "verbose",
                "exit",
                "show-limits",
                "help",
                "version",
            ],
            long_values: &[
                "arg-file",
                "delimiter",
                "max-args",
                "max-procs",
                "max-chars",
                "process-slot-var",
            ],
            long_glued: &["eof", "replace", "max-lines"],
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["doas"],
        options: OptionGrammar {
            short_flags: "Lns",
            short_values: "aCu",
            ..BASE
        },
        slots: &[EXEC, Slot::Privilege],
    },
    CommandSpec {
        names: &["su"],
        options: OptionGrammar {
            short_flags: "lmpfPVhL",
            short_values: "cgGsw",
            long_flags: &[
                "login",
                "preserve-environment",
                "fast",
                "pty",
                "help",
                "version",
            ],
            long_values: &[
                "command",
                "group",
                "supp-group",
                "shell",
                "whitelist-environment",
                "session-command",
            ],
            bare_dash_option: true,
            order: ArgOrder::PermuteUntilCommand,
            ..BASE
        },
        slots: &[
            EXEC,
            Slot::Privilege,
            Slot::Operands(1),
            Slot::ShellScript {
                short: Some('c'),
                long: Some("command"),
            },
            Slot::ShellScript {
                short: None,
                long: Some("session-command"),
            },
            Slot::CwdSwitch {
                short: 'l',
                long: "login",
                effect: CwdEffect::Relocates,
            },
            Slot::CwdBareDash {
                effect: CwdEffect::Relocates,
            },
        ],
    },
    CommandSpec {
        names: &["pkexec"],
        options: OptionGrammar {
            long_flags: &["disable-internal-agent", "keep-cwd", "version", "help"],
            long_values: &["user"],
            ..BASE
        },
        slots: &[EXEC, Slot::Privilege],
    },
    CommandSpec {
        names: &["run0"],
        options: OptionGrammar {
            short_flags: "h",
            short_values: "ugDM",
            long_flags: &[
                "no-ask-password",
                "slice-inherit",
                "empower",
                "pty",
                "help",
                "version",
            ],
            long_values: &[
                "unit",
                "property",
                "description",
                "slice",
                "user",
                "group",
                "nice",
                "chdir",
                "setenv",
                "machine",
                "background",
            ],
            ..BASE
        },
        slots: &[
            EXEC,
            Slot::Privilege,
            Slot::Cwd {
                short: 'D',
                long: "chdir",
                effect: CwdEffect::Relocates,
            },
            // Not only a non-root target: any `-u` is treated as running in
            // that user's home, so the exception fails closed.
            Slot::Cwd {
                short: 'u',
                long: "user",
                effect: CwdEffect::Relocates,
            },
        ],
    },
    CommandSpec {
        names: &["timeout"],
        options: OptionGrammar {
            short_flags: "fpv",
            short_values: "sk",
            long_flags: &[
                "foreground",
                "preserve-status",
                "verbose",
                "help",
                "version",
            ],
            long_values: &["signal", "kill-after"],
            ..BASE
        },
        slots: &[EXEC, Slot::Operands(1)],
    },
    CommandSpec {
        names: &["ionice"],
        options: OptionGrammar {
            short_flags: "thV",
            short_values: "cnpPu",
            long_flags: &["ignore", "help", "version"],
            long_values: &["class", "classdata", "pid", "pgid", "uid"],
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["flock"],
        options: OptionGrammar {
            short_flags: "sxunoFhVv",
            short_values: "wEc",
            long_flags: &[
                "shared",
                "exclusive",
                "unlock",
                "nonblock",
                "nb",
                "close",
                "no-fork",
                "verbose",
                "help",
                "version",
            ],
            long_values: &["timeout", "wait", "conflict-exit-code", "command"],
            ..BASE
        },
        slots: &[
            EXEC,
            Slot::Operands(1),
            Slot::ShellScript {
                short: Some('c'),
                long: Some("command"),
            },
        ],
    },
    CommandSpec {
        names: &["chrt"],
        options: OptionGrammar {
            short_flags: "bfiordRmpavhV",
            short_values: "TPD",
            long_flags: &[
                "batch",
                "fifo",
                "idle",
                "other",
                "rr",
                "deadline",
                "reset-on-fork",
                "max",
                "pid",
                "all-tasks",
                "verbose",
                "help",
                "version",
            ],
            long_values: &["sched-runtime", "sched-period", "sched-deadline"],
            ..BASE
        },
        slots: &[EXEC, Slot::Operands(1)],
    },
    CommandSpec {
        names: &["taskset"],
        options: OptionGrammar {
            short_flags: "apchV",
            long_flags: &["all-tasks", "pid", "cpu-list", "help", "version"],
            ..BASE
        },
        slots: &[EXEC, Slot::Operands(1)],
    },
    CommandSpec {
        names: &["busybox", "toybox"],
        options: OptionGrammar {
            long_flags: &["help", "install", "list", "list-full", "show", "version"],
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["coreutils"],
        options: OptionGrammar {
            short_flags: "hV",
            long_flags: &["help", "version", "list"],
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["builtin"],
        options: OptionGrammar {
            short_flags: "dlps",
            short_values: "f",
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["time"],
        options: OptionGrammar {
            short_flags: "apqvVlh",
            short_values: "fo",
            long_flags: &[
                "append",
                "portability",
                "quiet",
                "verbose",
                "version",
                "help",
            ],
            long_values: &["format", "output"],
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["caffeinate"],
        options: OptionGrammar {
            short_flags: "dimsu",
            short_values: "tw",
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["chroot"],
        options: OptionGrammar {
            short_values: "ugG",
            long_flags: &["skip-chdir", "help", "version"],
            long_values: &["userspec", "groups"],
            ..BASE
        },
        slots: &[EXEC, Slot::Operands(1)],
    },
    CommandSpec {
        names: &["unshare"],
        options: OptionGrammar {
            short_flags: "muinpUCTfrchV",
            short_values: "SGRwl",
            long_flags: &[
                "fork",
                "map-root-user",
                "map-current-user",
                "map-auto",
                "keep-caps",
                "help",
                "version",
            ],
            long_values: &[
                "setuid",
                "setgid",
                "root",
                "wd",
                "map-user",
                "map-group",
                "map-users",
                "map-groups",
                "setgroups",
                "propagation",
                "monotonic",
                "boottime",
                "load-interp",
            ],
            long_glued: &[
                "mount",
                "uts",
                "ipc",
                "net",
                "pid",
                "user",
                "cgroup",
                "time",
                "kill-child",
                "mount-proc",
            ],
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["runuser"],
        options: OptionGrammar {
            short_flags: "flmpPhV",
            short_values: "ugGswc",
            long_flags: &[
                "login",
                "fast",
                "preserve-environment",
                "pty",
                "help",
                "version",
            ],
            long_values: &[
                "user",
                "group",
                "supp-group",
                "shell",
                "whitelist-environment",
                "command",
                "session-command",
            ],
            ..BASE
        },
        slots: &[
            EXEC,
            Slot::Privilege,
            Slot::ShellScript {
                short: Some('c'),
                long: Some("command"),
            },
            Slot::ShellScript {
                short: None,
                long: Some("session-command"),
            },
        ],
    },
    CommandSpec {
        names: &["strace"],
        options: OptionGrammar {
            short_flags: "ACcdDfFhiknqrtTvVwxyYzZ",
            short_values: "oepsuEabIOPSXU",
            long_flags: &[
                "follow-forks",
                "output-separately",
                "summary-only",
                "summary",
                "debug",
                "help",
                "version",
                "instruction-pointer",
                "stack-traces",
                "syscall-number",
            ],
            long_values: &[
                "output",
                "trace",
                "signal",
                "status",
                "env",
                "user",
                "string-limit",
                "attach",
                "trace-path",
                "summary-sort-by",
                "summary-columns",
                "columns",
                "detach-on",
                "interruptible",
                "const-print-style",
                "abbrev",
                "verbose",
                "raw",
                "read",
                "write",
                "inject",
                "fault",
                "syscall-limit",
                "decode-pids",
            ],
            ..BASE
        },
        slots: &[
            EXEC,
            Slot::PipedOutput {
                short: 'o',
                long: "output",
            },
        ],
    },
    CommandSpec {
        names: &["watch"],
        options: OptionGrammar {
            // `-d` takes an optional glued value, so `-dx` is `-d` with
            // value `x`, never `-d -x`.
            short_flags: "bcCegprtwxhv",
            short_values: "nqs",
            short_glued: "d",
            long_flags: &[
                "beep", "color", "no-color", "errexit", "chgexit", "precise", "no-rerun",
                "no-title", "no-wrap", "exec", "help", "version",
            ],
            long_values: &["interval", "equexit", "shotsdir"],
            long_glued: &["differences"],
            ..BASE
        },
        slots: &[
            EXEC,
            Slot::OperandsAsShellScript {
                exec_short: 'x',
                exec_long: "exec",
            },
        ],
    },
    CommandSpec {
        names: &["setarch"],
        options: OptionGrammar {
            leading_operand: true,
            ..SETARCH_OPTIONS
        },
        slots: &[EXEC],
    },
    // The personality aliases take the same options but no ARCH operand.
    CommandSpec {
        names: &["linux32", "linux64", "i386", "x86_64", "uname26"],
        options: SETARCH_OPTIONS,
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["prlimit"],
        options: OptionGrammar {
            short_flags: "hV",
            short_values: "po",
            // Resource limits (`-n[=soft:hard]`, `--nofile[=...]`) are
            // optional-argument and `=`-joined, so a separate word is the
            // command, not a value.
            short_glued: "cdefilmnqrstuvxy",
            long_flags: &["noheadings", "raw", "verbose", "help", "version"],
            long_values: &["pid", "output"],
            long_glued: &[
                "core",
                "data",
                "nice",
                "fsize",
                "sigpending",
                "memlock",
                "rss",
                "nofile",
                "msgqueue",
                "rtprio",
                "stack",
                "cpu",
                "nproc",
                "as",
                "locks",
                "rttime",
            ],
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["firejail"],
        // Every firejail option is `--name` or `--name=value`; none takes a
        // separated value, so the option names need no enumeration.
        options: OptionGrammar {
            any_long_attached: true,
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["systemd-run"],
        options: OptionGrammar {
            short_flags: "rdtPqGSh",
            short_values: "upEMHC",
            long_flags: &[
                "system",
                "user",
                "scope",
                "remain-after-exit",
                "no-ask-password",
                "pty",
                "pipe",
                "wait",
                "collect",
                "quiet",
                "no-block",
                "send-sighup",
                "same-dir",
                "shell",
                "no-pager",
                "help",
                "version",
            ],
            long_values: &[
                "unit",
                "property",
                "setenv",
                "machine",
                "host",
                "uid",
                "gid",
                "nice",
                "working-directory",
                "description",
                "slice",
                "service-type",
                "on-active",
                "on-boot",
                "on-startup",
                "on-unit-active",
                "on-unit-inactive",
                "on-calendar",
                "timer-property",
                "capsule",
                "path-property",
                "socket-property",
                "job-mode",
            ],
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["unbuffer"],
        options: OptionGrammar {
            short_flags: "p",
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["numactl"],
        options: OptionGrammar {
            short_flags: "absHltdDuTh",
            short_values: "cCNmpiPwSfoLMI",
            long_flags: &[
                "all",
                "hardware",
                "show",
                "localalloc",
                "touch",
                "dump",
                "dump-nodes",
                "strict",
                "huge",
                "help",
                "version",
            ],
            long_values: &[
                "physcpubind",
                "cpubind",
                "cpunodebind",
                "membind",
                "preferred",
                "interleave",
                "preferred-many",
                "weighted-interleave",
                "shm",
                "file",
                "offset",
                "length",
                "shmmode",
                "shmid",
            ],
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["script"],
        options: OptionGrammar {
            // BSD `-F` is deliberately absent: a boolean on macOS but a
            // pipe path on older FreeBSD, so it stays unmodelled.
            short_flags: "adefkpqrhV",
            short_values: "cTEIOBmo",
            short_values_unless_dash: "t",
            long_flags: &[
                "append", "return", "flush", "force", "quiet", "help", "version",
            ],
            long_values: &[
                "command",
                "echo",
                "log-in",
                "log-out",
                "log-io",
                "log-timing",
                "logging-format",
                "output-limit",
            ],
            dash_command_unmodeled: true,
            ..BASE
        },
        slots: &[
            EXEC,
            Slot::Operands(1),
            Slot::ShellScript {
                short: Some('c'),
                long: Some("command"),
            },
        ],
    },
    // `make` runs no wrapped command; its entry only tells `-C` composition
    // how the cluster `-kC dir` is laid out (every short letter not listed as
    // a value-taker is boolean on GNU make).
    CommandSpec {
        names: &["make"],
        options: OptionGrammar {
            short_flags: "bmBdeikLnpqrRsStvw",
            short_values: "CfIjloW",
            long_values: &["directory"],
            ..BASE
        },
        slots: &[Slot::Cwd {
            short: 'C',
            long: "directory",
            effect: CwdEffect::Composed,
        }],
    },
    // Reference-list wrappers without an earlier table entry. The grammar is
    // deliberately small: anything else is unmodelled and floors to Ask,
    // while the wrapped command stays visible to rule matching.
    CommandSpec {
        names: &["nsenter"],
        options: OptionGrammar {
            short_flags: "FZeahV",
            short_values: "tSG",
            short_glued: "muinpCUTrw",
            long_flags: &[
                "no-fork",
                "follow-context",
                "preserve-credentials",
                "all",
                "help",
                "version",
            ],
            long_values: &["target", "setuid", "setgid"],
            long_glued: &[
                "mount", "uts", "ipc", "net", "pid", "cgroup", "time", "user", "root", "wd",
            ],
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["setpriv"],
        options: OptionGrammar {
            long_flags: &[
                "clear-groups",
                "keep-groups",
                "init-groups",
                "no-new-privs",
                "reset-env",
                "dump",
                "list-caps",
                "help",
                "version",
            ],
            long_values: &[
                "reuid",
                "regid",
                "ruid",
                "euid",
                "rgid",
                "egid",
                "groups",
                "inh-caps",
                "ambient-caps",
                "bounding-set",
                "securebits",
                "selinux-label",
                "apparmor-profile",
                "pdeathsig",
            ],
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["runcon"],
        options: OptionGrammar {
            long_flags: &["help", "version"],
            ..BASE
        },
        slots: &[EXEC, Slot::Operands(1)],
    },
    CommandSpec {
        names: &["choom"],
        options: OptionGrammar {
            short_flags: "hV",
            short_values: "np",
            long_flags: &["help", "version"],
            long_values: &["adjust", "pid"],
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["chpst"],
        options: OptionGrammar {
            short_flags: "vP012",
            short_values: "uUe/nmdopfc",
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["setuidgid", "envuidgid", "envdir"],
        options: BASE,
        slots: &[EXEC, Slot::Operands(1)],
    },
    CommandSpec {
        names: &["softlimit"],
        options: OptionGrammar {
            short_values: "acdflmoprst",
            ..BASE
        },
        slots: &[EXEC],
    },
    // macOS `arch`: architecture selectors are whole single-dash words.
    CommandSpec {
        names: &["arch"],
        options: OptionGrammar {
            short_flags: "ch",
            short_values: "de",
            dash_words: &[
                "x86_64", "x86_64h", "arm64", "arm64e", "i386", "ppc", "ppc64",
            ],
            dash_word_values: &["arch"],
            numeric_option: true,
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["sandbox-exec"],
        options: OptionGrammar {
            short_values: "nfpD",
            ..BASE
        },
        slots: &[EXEC],
    },
    // Every valgrind option is `--name[=value]`.
    CommandSpec {
        names: &["valgrind"],
        options: OptionGrammar {
            short_flags: "vqdh",
            any_long_attached: true,
            ..BASE
        },
        slots: &[EXEC],
    },
    CommandSpec {
        names: &["fakeroot"],
        options: OptionGrammar {
            short_flags: "uhv",
            short_values: "lfisb",
            long_flags: &["unknown-is-real", "help", "version"],
            long_values: &["lib", "faked", "fd-base"],
            ..BASE
        },
        slots: &[EXEC],
    },
    // Only options with a documented arity; the rest floor to Ask.
    CommandSpec {
        names: &["rlwrap"],
        options: OptionGrammar {
            short_flags: "AcFhiInNorRTUv",
            short_values: "bCDefgHlMOPqsStwz",
            short_glued: "apm",
            ..BASE
        },
        slots: &[EXEC],
    },
];
