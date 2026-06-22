//! Classification of syscalls into coarse categories.
//!
//! Categories drive colouring in the TUI, `--syscall`-by-category filtering and
//! per-category aggregation. The mapping mirrors the buckets strace uses for its
//! `-e trace=%file`, `%network`, ... selectors, derived here from an explicit
//! table plus prefix heuristics so that every one of the syscalls lands
//! somewhere sensible without hand-labelling each one.

/// Coarse syscall category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// Filesystem & file-descriptor I/O.
    Fs,
    /// Networking / sockets.
    Net,
    /// Memory management.
    Memory,
    /// Process & thread lifecycle.
    Process,
    /// Signal handling.
    Signal,
    /// Inter-process communication & synchronisation.
    Ipc,
    /// Time & timers.
    Time,
    /// Security, credentials & capabilities.
    Security,
    /// Generic system / kernel control.
    System,
    /// Anything not otherwise classified.
    Other,
}

impl Category {
    /// The variant identifier, used both for codegen (`crate::Category::Fs`) and
    /// for CLI parsing of `--category`.
    pub fn ident(self) -> &'static str {
        match self {
            Category::Fs => "Fs",
            Category::Net => "Net",
            Category::Memory => "Memory",
            Category::Process => "Process",
            Category::Signal => "Signal",
            Category::Ipc => "Ipc",
            Category::Time => "Time",
            Category::Security => "Security",
            Category::System => "System",
            Category::Other => "Other",
        }
    }
}

/// Classify a syscall by name.
pub fn categorize(name: &str) -> Category {
    if let Some(cat) = exact(name) {
        return cat;
    }
    by_prefix(name).unwrap_or(Category::Other)
}

/// Explicit overrides where prefixes would mislead.
fn exact(name: &str) -> Option<Category> {
    let cat = match name {
        // filesystem
        "read" | "write" | "open" | "openat" | "openat2" | "close" | "close_range" | "stat"
        | "fstat" | "lstat" | "newfstatat" | "statx" | "lseek" | "pread64" | "pwrite64"
        | "readv" | "writev" | "preadv" | "pwritev" | "preadv2" | "pwritev2" | "access"
        | "faccessat" | "faccessat2" | "dup" | "dup2" | "dup3" | "pipe" | "pipe2" | "getdents"
        | "getdents64" | "getcwd" | "chdir" | "fchdir" | "rename" | "renameat" | "renameat2"
        | "mkdir" | "mkdirat" | "rmdir" | "creat" | "link" | "linkat" | "unlink" | "unlinkat"
        | "symlink" | "symlinkat" | "readlink" | "readlinkat" | "chmod" | "fchmod" | "fchmodat"
        | "chown" | "fchown" | "lchown" | "fchownat" | "umask" | "truncate" | "ftruncate"
        | "fallocate" | "fadvise64" | "flock" | "fsync" | "fdatasync" | "sync" | "syncfs"
        | "sync_file_range" | "statfs" | "fstatfs" | "getxattr" | "lgetxattr" | "fgetxattr"
        | "setxattr" | "lsetxattr" | "fsetxattr" | "listxattr" | "llistxattr" | "flistxattr"
        | "removexattr" | "lremovexattr" | "fremovexattr" | "sendfile" | "copy_file_range"
        | "splice" | "tee" | "vmsplice" | "fcntl" | "mknod" | "mknodat" => Category::Fs,

        // networking
        "socket" | "socketpair" | "bind" | "listen" | "accept" | "accept4" | "connect"
        | "getsockname" | "getpeername" | "sendto" | "recvfrom" | "sendmsg" | "recvmsg"
        | "sendmmsg" | "recvmmsg" | "shutdown" | "setsockopt" | "getsockopt" | "sethostname"
        | "setdomainname" => Category::Net,

        // memory
        "mmap" | "munmap" | "mremap" | "mprotect" | "brk" | "msync" | "mincore" | "madvise"
        | "mlock" | "mlock2" | "munlock" | "mlockall" | "munlockall" | "mbind"
        | "set_mempolicy" | "get_mempolicy" | "migrate_pages" | "move_pages" | "memfd_create"
        | "memfd_secret" | "pkey_alloc" | "pkey_free" | "pkey_mprotect" | "remap_file_pages" => {
            Category::Memory
        }

        // process / threads
        "clone" | "clone3" | "fork" | "vfork" | "execve" | "execveat" | "exit" | "exit_group"
        | "wait4" | "waitid" | "getpid" | "getppid" | "gettid" | "set_tid_address"
        | "set_robust_list" | "get_robust_list" | "unshare" | "setns" | "prctl" | "arch_prctl"
        | "personality" | "getpgid" | "setpgid" | "getpgrp" | "getsid" | "setsid"
        | "getpriority" | "setpriority" => Category::Process,

        // signals
        "rt_sigaction" | "rt_sigprocmask" | "rt_sigreturn" | "rt_sigpending"
        | "rt_sigtimedwait" | "rt_sigqueueinfo" | "rt_tgsigqueueinfo" | "rt_sigsuspend"
        | "sigaltstack" | "kill" | "tkill" | "tgkill" | "pidfd_send_signal" | "signalfd"
        | "signalfd4" | "pause" | "restart_syscall" => Category::Signal,

        // ipc / synchronisation
        "futex" | "futex_waitv" | "get_robust_list2" | "eventfd" | "eventfd2" | "shmget"
        | "shmat" | "shmdt" | "shmctl" | "semget" | "semop" | "semtimedop" | "semctl"
        | "msgget" | "msgsnd" | "msgrcv" | "msgctl" | "mq_open" | "mq_unlink" | "mq_timedsend"
        | "mq_timedreceive" | "mq_notify" | "mq_getsetattr" | "process_vm_readv"
        | "process_vm_writev" | "pidfd_open" | "pidfd_getfd" => Category::Ipc,

        // time
        "nanosleep" | "clock_nanosleep" | "gettimeofday" | "settimeofday" | "time" | "times"
        | "getitimer" | "setitimer" | "alarm" | "adjtimex" | "clock_adjtime" => Category::Time,

        // security / credentials
        "setuid"
        | "setgid"
        | "setreuid"
        | "setregid"
        | "setresuid"
        | "setresgid"
        | "setfsuid"
        | "setfsgid"
        | "getuid"
        | "geteuid"
        | "getgid"
        | "getegid"
        | "getresuid"
        | "getresgid"
        | "getgroups"
        | "setgroups"
        | "capget"
        | "capset"
        | "seccomp"
        | "keyctl"
        | "add_key"
        | "request_key"
        | "landlock_create_ruleset"
        | "landlock_add_rule"
        | "landlock_restrict_self" => Category::Security,

        // generic system control
        "ioctl" | "uname" | "sysinfo" | "syslog" | "reboot" | "getrlimit" | "setrlimit"
        | "prlimit64" | "getrusage" | "sysctl" | "_sysctl" | "ptrace" | "bpf"
        | "perf_event_open" | "kcmp" | "getcpu" | "sysfs" | "ustat" | "quotactl"
        | "quotactl_fd" => Category::System,

        _ => return None,
    };
    Some(cat)
}

/// Heuristic fallback for the long tail of less common syscalls.
fn by_prefix(name: &str) -> Option<Category> {
    const RULES: &[(&str, Category)] = &[
        ("inotify", Category::Fs),
        ("fanotify", Category::Fs),
        ("epoll", Category::Fs),
        ("eventfd", Category::Ipc),
        ("io_uring", Category::Fs),
        ("io_", Category::Fs),
        ("aio_", Category::Fs),
        ("name_to_handle", Category::Fs),
        ("open_by_handle", Category::Fs),
        ("clock_", Category::Time),
        ("timer_", Category::Time),
        ("timerfd", Category::Time),
        ("sched_", Category::System),
        ("rt_sig", Category::Signal),
        ("sig", Category::Signal),
        ("sem", Category::Ipc),
        ("shm", Category::Ipc),
        ("msg", Category::Ipc),
        ("mq_", Category::Ipc),
        ("key", Category::Security),
        ("landlock", Category::Security),
        ("socket", Category::Net),
        ("get", Category::Process),
        ("set", Category::Process),
    ];
    RULES.iter().find(|(prefix, _)| name.starts_with(prefix)).map(|(_, cat)| *cat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_syscalls_are_classified() {
        assert_eq!(categorize("openat"), Category::Fs);
        assert_eq!(categorize("read"), Category::Fs);
        assert_eq!(categorize("connect"), Category::Net);
        assert_eq!(categorize("mmap"), Category::Memory);
        assert_eq!(categorize("execve"), Category::Process);
        assert_eq!(categorize("rt_sigaction"), Category::Signal);
        assert_eq!(categorize("futex"), Category::Ipc);
        assert_eq!(categorize("nanosleep"), Category::Time);
        assert_eq!(categorize("setuid"), Category::Security);
        assert_eq!(categorize("ioctl"), Category::System);
    }

    #[test]
    fn prefix_fallbacks_apply() {
        assert_eq!(categorize("clock_gettime"), Category::Time);
        assert_eq!(categorize("timer_create"), Category::Time);
        assert_eq!(categorize("sched_yield"), Category::System);
        assert_eq!(categorize("inotify_add_watch"), Category::Fs);
        assert_eq!(categorize("epoll_wait"), Category::Fs);
        assert_eq!(categorize("io_uring_setup"), Category::Fs);
    }

    #[test]
    fn unknown_is_other() {
        assert_eq!(categorize("totally_made_up_syscall"), Category::Other);
    }

    #[test]
    fn ident_matches_debug_name() {
        for cat in [
            Category::Fs,
            Category::Net,
            Category::Memory,
            Category::Process,
            Category::Signal,
            Category::Ipc,
            Category::Time,
            Category::Security,
            Category::System,
            Category::Other,
        ] {
            assert_eq!(cat.ident(), format!("{cat:?}"));
        }
    }
}
