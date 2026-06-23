//! Typed argument metadata for the most common syscalls.
//!
//! Hand-maintained table describing the prototype of every
//! syscall. syren keeps the table small and focused on
//! the hot-path syscalls.

/// The display/decoding kind of a single argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    /// A file descriptor (`int`). Rendered as a decimal, annotated with the
    /// resolved path when known.
    Fd,
    /// A `const char *` pathname. Rendered as a quoted string.
    Path,
    /// A `void *` data buffer. Rendered as a pointer (content capture is opt-in).
    Buf,
    /// A `size_t` / count. Rendered as a decimal.
    Size,
    /// A signed integer.
    Int,
    /// An unsigned integer.
    Uint,
    /// An opaque value best shown in hex (`ioctl` request, `fcntl` arg, ...).
    Hex,
    /// An `off_t` file offset.
    Offset,
    /// A bit-flag set (`open` flags, `mmap` prot, ...). Rendered in hex for now,
    /// with symbolic decoding layered on top in `syren-decode`.
    Flags,
    /// A generic pointer (structs we do not yet decode).
    Ptr,
}

impl ArgKind {
    /// The `syren_common::ArgType` variant identifier this kind maps to.
    pub fn ident(self) -> &'static str {
        match self {
            ArgKind::Fd => "Fd",
            ArgKind::Path => "Path",
            ArgKind::Buf => "Buf",
            ArgKind::Size => "Size",
            ArgKind::Int => "Int",
            ArgKind::Uint => "Uint",
            ArgKind::Hex => "Hex",
            ArgKind::Offset => "Offset",
            ArgKind::Flags => "Flags",
            ArgKind::Ptr => "Ptr",
        }
    }
}

/// One argument: a display name and its decoding kind.
#[derive(Debug, Clone, Copy)]
pub struct ArgMeta {
    /// Argument name as it appears in the man page (e.g. `pathname`).
    pub name: &'static str,
    /// How to decode/render the argument.
    pub kind: &'static str,
}

/// The prototype of a single syscall.
#[derive(Debug, Clone, Copy)]
pub struct SyscallMeta {
    /// Syscall name (matches the table entry).
    pub name: &'static str,
    /// Ordered arguments. An empty slice means "no metadata; render generically".
    pub args: &'static [ArgMeta],
}

/// Helper to keep the table below terse and readable.
const fn a(name: &'static str, kind: &'static str) -> ArgMeta {
    ArgMeta { name, kind }
}

/// Look up metadata for a syscall by name.
pub fn lookup(name: &str) -> Option<&'static SyscallMeta> {
    METADATA.iter().find(|m| m.name == name)
}

/// The full metadata table.
pub fn metadata() -> &'static [SyscallMeta] {
    METADATA
}

macro_rules! syscall_meta {
    ($name:literal => [ $( ($an:literal, $ak:expr) ),* $(,)? ]) => {
        SyscallMeta { name: $name, args: &[ $( a($an, stringify!($ak)) ),* ] }
    };
}

#[rustfmt::skip]
static METADATA: &[SyscallMeta] = &[
    // file IO
    syscall_meta!("read"        => [("fd", Fd), ("buf", Buf), ("count", Size)]),
    syscall_meta!("write"       => [("fd", Fd), ("buf", Buf), ("count", Size)]),
    syscall_meta!("pread64"     => [("fd", Fd), ("buf", Buf), ("count", Size), ("pos", Offset)]),
    syscall_meta!("pwrite64"    => [("fd", Fd), ("buf", Buf), ("count", Size), ("pos", Offset)]),
    syscall_meta!("readv"       => [("fd", Fd), ("iov", Ptr), ("iovcnt", Int)]),
    syscall_meta!("writev"      => [("fd", Fd), ("iov", Ptr), ("iovcnt", Int)]),
    syscall_meta!("open"        => [("filename", Path), ("flags", Flags), ("mode", Int)]),
    syscall_meta!("openat"      => [("dfd", Fd), ("filename", Path), ("flags", Flags), ("mode", Int)]),
    syscall_meta!("creat"       => [("pathname", Path), ("mode", Int)]),
    syscall_meta!("close"       => [("fd", Fd)]),
    syscall_meta!("lseek"       => [("fd", Fd), ("offset", Offset), ("whence", Int)]),
    syscall_meta!("dup"         => [("fildes", Fd)]),
    syscall_meta!("dup2"        => [("oldfd", Fd), ("newfd", Fd)]),
    syscall_meta!("dup3"        => [("oldfd", Fd), ("newfd", Fd), ("flags", Flags)]),
    syscall_meta!("pipe"        => [("filedes", Ptr)]),
    syscall_meta!("pipe2"       => [("filedes", Ptr), ("flags", Flags)]),
    syscall_meta!("fcntl"       => [("fd", Fd), ("cmd", Int), ("arg", Hex)]),
    syscall_meta!("ioctl"       => [("fd", Fd), ("request", Hex), ("arg", Hex)]),
    syscall_meta!("getdents64"  => [("fd", Fd), ("dirent", Ptr), ("count", Size)]),
    syscall_meta!("fsync"       => [("fd", Fd)]),
    syscall_meta!("fdatasync"   => [("fd", Fd)]),
    syscall_meta!("ftruncate"   => [("fd", Fd), ("length", Offset)]),
    syscall_meta!("truncate"    => [("path", Path), ("length", Offset)]),

    // metadata / paths
    syscall_meta!("stat"        => [("filename", Path), ("statbuf", Ptr)]),
    syscall_meta!("lstat"       => [("filename", Path), ("statbuf", Ptr)]),
    syscall_meta!("fstat"       => [("fd", Fd), ("statbuf", Ptr)]),
    syscall_meta!("newfstatat"  => [("dfd", Fd), ("filename", Path), ("statbuf", Ptr), ("flag", Flags)]),
    syscall_meta!("statx"       => [("dfd", Fd), ("path", Path), ("flags", Flags), ("mask", Uint), ("buf", Ptr)]),
    syscall_meta!("access"      => [("filename", Path), ("mode", Int)]),
    syscall_meta!("faccessat"   => [("dfd", Fd), ("filename", Path), ("mode", Int)]),
    syscall_meta!("faccessat2"  => [("dfd", Fd), ("filename", Path), ("mode", Int), ("flags", Flags)]),
    syscall_meta!("readlink"    => [("path", Path), ("buf", Buf), ("bufsiz", Size)]),
    syscall_meta!("readlinkat"  => [("dfd", Fd), ("path", Path), ("buf", Buf), ("bufsiz", Size)]),
    syscall_meta!("getcwd"      => [("buf", Buf), ("size", Size)]),
    syscall_meta!("chdir"       => [("filename", Path)]),
    syscall_meta!("fchdir"      => [("fd", Fd)]),
    syscall_meta!("rename"      => [("oldname", Path), ("newname", Path)]),
    syscall_meta!("renameat2"   => [("olddfd", Fd), ("oldname", Path), ("newdfd", Fd), ("newname", Path), ("flags", Flags)]),
    syscall_meta!("mkdir"       => [("pathname", Path), ("mode", Int)]),
    syscall_meta!("mkdirat"     => [("dfd", Fd), ("pathname", Path), ("mode", Int)]),
    syscall_meta!("rmdir"       => [("pathname", Path)]),
    syscall_meta!("unlink"      => [("pathname", Path)]),
    syscall_meta!("unlinkat"    => [("dfd", Fd), ("pathname", Path), ("flag", Flags)]),
    syscall_meta!("symlink"     => [("oldname", Path), ("newname", Path)]),
    syscall_meta!("chmod"       => [("filename", Path), ("mode", Int)]),
    syscall_meta!("fchmod"      => [("fd", Fd), ("mode", Int)]),
    syscall_meta!("umask"       => [("mask", Int)]),

    // memory
    syscall_meta!("mmap"        => [("addr", Ptr), ("len", Size), ("prot", Flags), ("flags", Flags), ("fd", Fd), ("off", Offset)]),
    syscall_meta!("munmap"      => [("addr", Ptr), ("len", Size)]),
    syscall_meta!("mprotect"    => [("addr", Ptr), ("len", Size), ("prot", Flags)]),
    syscall_meta!("mremap"      => [("addr", Ptr), ("old_len", Size), ("new_len", Size), ("flags", Flags), ("new_addr", Ptr)]),
    syscall_meta!("brk"         => [("brk", Ptr)]),
    syscall_meta!("madvise"     => [("addr", Ptr), ("len", Size), ("advice", Int)]),

    // process / threads
    syscall_meta!("execve"      => [("filename", Path), ("argv", Ptr), ("envp", Ptr)]),
    syscall_meta!("execveat"    => [("dfd", Fd), ("filename", Path), ("argv", Ptr), ("envp", Ptr), ("flags", Flags)]),
    syscall_meta!("clone"       => [("flags", Flags), ("stack", Ptr), ("parent_tid", Ptr), ("child_tid", Ptr), ("tls", Hex)]),
    syscall_meta!("wait4"       => [("pid", Int), ("stat_addr", Ptr), ("options", Flags), ("rusage", Ptr)]),
    syscall_meta!("exit"        => [("status", Int)]),
    syscall_meta!("exit_group"  => [("status", Int)]),
    syscall_meta!("getpid"      => []),
    syscall_meta!("getppid"     => []),
    syscall_meta!("gettid"      => []),
    syscall_meta!("set_tid_address" => [("tidptr", Ptr)]),
    syscall_meta!("set_robust_list" => [("head", Ptr), ("len", Size)]),
    syscall_meta!("prctl"       => [("option", Int), ("arg2", Hex), ("arg3", Hex), ("arg4", Hex), ("arg5", Hex)]),
    syscall_meta!("arch_prctl"  => [("code", Int), ("addr", Hex)]),
    syscall_meta!("rseq"        => [("rseq", Ptr), ("rseq_len", Uint), ("flags", Flags), ("sig", Uint)]),

    //  signals
    syscall_meta!("rt_sigaction"   => [("sig", Int), ("act", Ptr), ("oact", Ptr), ("sigsetsize", Size)]),
    syscall_meta!("rt_sigprocmask" => [("how", Int), ("set", Ptr), ("oset", Ptr), ("sigsetsize", Size)]),
    syscall_meta!("kill"           => [("pid", Int), ("sig", Int)]),
    syscall_meta!("tgkill"         => [("tgid", Int), ("pid", Int), ("sig", Int)]),

    // networking
    syscall_meta!("socket"      => [("family", Int), ("type", Int), ("protocol", Int)]),
    syscall_meta!("connect"     => [("fd", Fd), ("uservaddr", Ptr), ("addrlen", Int)]),
    syscall_meta!("accept"      => [("fd", Fd), ("upeer", Ptr), ("upeer_addrlen", Ptr)]),
    syscall_meta!("accept4"     => [("fd", Fd), ("upeer", Ptr), ("upeer_addrlen", Ptr), ("flags", Flags)]),
    syscall_meta!("bind"        => [("fd", Fd), ("umyaddr", Ptr), ("addrlen", Int)]),
    syscall_meta!("listen"      => [("fd", Fd), ("backlog", Int)]),
    syscall_meta!("sendto"      => [("fd", Fd), ("buff", Buf), ("len", Size), ("flags", Flags), ("addr", Ptr), ("addrlen", Int)]),
    syscall_meta!("recvfrom"    => [("fd", Fd), ("ubuf", Buf), ("size", Size), ("flags", Flags), ("addr", Ptr), ("addrlen", Ptr)]),
    syscall_meta!("setsockopt"  => [("fd", Fd), ("level", Int), ("optname", Int), ("optval", Ptr), ("optlen", Int)]),
    syscall_meta!("getsockopt"  => [("fd", Fd), ("level", Int), ("optname", Int), ("optval", Ptr), ("optlen", Ptr)]),

    // polling / events
    syscall_meta!("poll"        => [("ufds", Ptr), ("nfds", Uint), ("timeout", Int)]),
    syscall_meta!("ppoll"       => [("ufds", Ptr), ("nfds", Uint), ("tsp", Ptr), ("sigmask", Ptr), ("sigsetsize", Size)]),
    syscall_meta!("select"      => [("n", Int), ("inp", Ptr), ("outp", Ptr), ("exp", Ptr), ("tvp", Ptr)]),
    syscall_meta!("epoll_create1" => [("flags", Flags)]),
    syscall_meta!("epoll_ctl"   => [("epfd", Fd), ("op", Int), ("fd", Fd), ("event", Ptr)]),
    syscall_meta!("epoll_wait"  => [("epfd", Fd), ("events", Ptr), ("maxevents", Int), ("timeout", Int)]),
    syscall_meta!("eventfd2"    => [("count", Uint), ("flags", Flags)]),

    // time & sync
    syscall_meta!("nanosleep"     => [("rqtp", Ptr), ("rmtp", Ptr)]),
    syscall_meta!("clock_gettime" => [("which_clock", Int), ("tp", Ptr)]),
    syscall_meta!("clock_nanosleep" => [("which_clock", Int), ("flags", Flags), ("rqtp", Ptr), ("rmtp", Ptr)]),
    syscall_meta!("gettimeofday"  => [("tv", Ptr), ("tz", Ptr)]),
    syscall_meta!("futex"         => [("uaddr", Ptr), ("op", Flags), ("val", Uint), ("utime", Ptr), ("uaddr2", Ptr), ("val3", Uint)]),
    syscall_meta!("getrandom"     => [("buf", Buf), ("count", Size), ("flags", Flags)]),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_finds_known_syscall() {
        let read = lookup("read").expect("read must have metadata");
        assert_eq!(read.args.len(), 3);
        assert_eq!(read.args[0].name, "fd");
        assert_eq!(read.args[0].kind, "Fd");
        assert_eq!(read.args[2].kind, "Size");
    }

    #[test]
    fn lookup_misses_unknown_syscall() {
        assert!(lookup("definitely_not_a_syscall").is_none());
    }

    #[test]
    fn zero_arg_syscalls_are_representable() {
        assert_eq!(lookup("getpid").unwrap().args.len(), 0);
    }

    #[test]
    fn no_syscall_exceeds_six_args() {
        // The x86_64 ABI only passes six register arguments.
        for m in metadata() {
            assert!(m.args.len() <= 6, "{} has too many args", m.name);
        }
    }

    #[test]
    fn metadata_names_are_unique() {
        let mut names: Vec<_> = metadata().iter().map(|m| m.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate syscall metadata entry");
    }
}
