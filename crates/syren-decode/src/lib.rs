//! Turns the raw [`SyscallEvent`] produced by a tracing backend into
//! human-readable, serialisable [`DecodedSyscall`].
//!
//! Reading argument strings and buffers requires access to the traced process's
//! address space; that is abstracted behind the [`MemoryReader`].

mod consts;
mod flags;
mod render;

use std::borrow::Cow;

use serde::Serialize;
use syren_common::{ArgInfo, ArgType, SyscallEvent, errno};
pub use syren_common::{MemoryReader, NullMemory, ProcMemReader};

/// A single decoded argument.
#[derive(Debug, Clone, Serialize)]
pub struct DecodedArg {
    /// Argument name from the syscall metadata, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<&'static str>,
    /// strace-style rendering, e.g. `"/etc/passwd"` or `O_RDONLY|O_CLOEXEC`.
    pub value: String,
    /// The raw 64-bit register value, preserved for machine consumers.
    pub raw: u64,
}

/// A decoded error return.
#[derive(Debug, Clone, Serialize)]
pub struct DecodedError {
    /// Positive errno value.
    pub errno: i32,
    /// Symbolic name, e.g. `ENOENT`.
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
}

/// A fully decoded syscall, ready to format or serialise.
#[derive(Debug, Clone, Serialize)]
pub struct DecodedSyscall {
    /// Thread-group id.
    pub pid: u32,
    /// Thread id.
    pub tid: u32,
    /// Raw syscall number.
    pub nr: u64,
    /// Syscall name, or `syscall_<nr>` for unknown numbers.
    pub name: Cow<'static, str>,
    /// Decoded arguments.
    pub args: Vec<DecodedArg>,
    /// Raw return value (`-errno` on failure).
    pub retval: i64,
    /// Error detail when the syscall failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<DecodedError>,
    /// Wall-clock duration of the syscall (ns).
    pub duration_ns: u64,
    /// Monotonic timestamp of syscall entry (ns).
    pub ts_enter_ns: u64,
}

impl DecodedSyscall {
    /// The call signature `name(arg, arg, ...)` without the return value.
    pub fn signature(&self) -> String {
        let mut out = String::with_capacity(self.name.len() + 2 + self.args.len() * 8);
        out.push_str(&self.name);
        out.push('(');
        for (i, arg) in self.args.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&arg.value);
        }
        out.push(')');
        out
    }

    /// The return value rendered strace-style: `-1 ENOENT (No such file ...)`
    /// on error, a hex address for the memory syscalls, else a decimal number.
    pub fn retval_str(&self) -> String {
        match &self.error {
            Some(e) => format!("-1 {} ({})", e.name, e.description),
            None if returns_hex(&self.name) && self.retval > 0 => format!("{:#x}", self.retval),
            None => self.retval.to_string(),
        }
    }
}

/// Decode a raw syscall event into its rendered form, reading argument strings
/// and buffers through `mem`.
pub fn decode(ev: &SyscallEvent, mem: &dyn MemoryReader) -> DecodedSyscall {
    let name = syren_common::syscall_name(ev.nr);
    let args = match ev.info() {
        Some(info) if !info.args.is_empty() => decode_typed(&name, info.args, ev, mem),
        _ => decode_raw(ev),
    };
    let error = ev.errno().and_then(errno).map(|e| DecodedError {
        errno: e.number,
        name: e.name,
        description: e.description,
    });
    DecodedSyscall {
        pid: ev.pid,
        tid: ev.tid,
        nr: ev.nr,
        name,
        args,
        retval: ev.retval,
        error,
        duration_ns: ev.duration_ns,
        ts_enter_ns: ev.ts_enter_ns,
    }
}

fn decode_typed(
    syscall: &str,
    metas: &[ArgInfo],
    ev: &SyscallEvent,
    mem: &dyn MemoryReader,
) -> Vec<DecodedArg> {
    metas
        .iter()
        .enumerate()
        .map(|(i, meta)| DecodedArg {
            name: Some(meta.name),
            value: render_arg(syscall, metas, i, ev, mem),
            raw: ev.args[i],
        })
        .collect()
}

fn render_arg(
    syscall: &str,
    metas: &[ArgInfo],
    i: usize,
    ev: &SyscallEvent,
    mem: &dyn MemoryReader,
) -> String {
    let raw = ev.args[i];
    if let Some(symbolic) = consts::render(syscall, metas, i, ev) {
        return symbolic;
    }
    if syscall == "setsockopt" && metas[i].name == "optval" {
        return render_sockopt_optval(ev, mem);
    }
    match metas[i].ty {
        ArgType::Fd => render_fd(raw),
        ArgType::Path => render::read_cstr(mem, raw, render::PATH_CAP)
            .map(|b| render::quote_bytes(&b))
            .unwrap_or_else(|| ptr_or_null(raw)),
        ArgType::Buf => render_buf(metas, i, ev, mem),
        ArgType::Size | ArgType::Uint => raw.to_string(),
        ArgType::Int | ArgType::Offset => (raw as i64).to_string(),
        ArgType::Hex => format!("{raw:#x}"),
        ArgType::Flags => {
            flags::render(syscall, metas[i].name, raw).unwrap_or_else(|| format!("{raw:#x}"))
        }
        ArgType::Ptr => ptr_or_null(raw),
    }
}

fn render_fd(value: u64) -> String {
    // File descriptors are `int`s, so interpret the low 32 bits as signed. This
    // renders sentinels like `AT_FDCWD` (-100) and `-1` correctly whether the
    // caller zero- or sign-extended them into the 64-bit register.
    let fd = value as u32 as i32;
    if fd == -100 { "AT_FDCWD".to_string() } else { fd.to_string() }
}

fn ptr_or_null(value: u64) -> String {
    if value == 0 { "NULL".to_string() } else { format!("{value:#x}") }
}

fn render_buf(metas: &[ArgInfo], i: usize, ev: &SyscallEvent, mem: &dyn MemoryReader) -> String {
    let addr = ev.args[i];
    if addr == 0 {
        return "NULL".to_string();
    }
    let bound = metas
        .get(i + 1)
        .filter(|next| next.ty == ArgType::Size)
        .map_or(render::MAX_STR, |_| ev.args[i + 1] as usize);
    let want = bound.min(render::MAX_STR + 1);
    match mem.read(addr, want) {
        Some(bytes) if !bytes.is_empty() => render::quote_bytes(&bytes),
        _ => format!("{addr:#x}"),
    }
}

fn render_sockopt_optval(ev: &SyscallEvent, mem: &dyn MemoryReader) -> String {
    let addr = ev.args[3];
    if addr == 0 {
        return "NULL".to_string();
    }
    if ev.args[4] == 4 {
        if let Some(bytes) = mem.read(addr, 4) {
            if let Ok(word) = <[u8; 4]>::try_from(bytes.as_slice()) {
                return format!("[{}]", i32::from_ne_bytes(word));
            }
        }
    }

    format!("{addr:#x}")
}

fn decode_raw(ev: &SyscallEvent) -> Vec<DecodedArg> {
    match ev.args.iter().rposition(|&a| a != 0) {
        None => Vec::new(),
        Some(last) => ev.args[..=last]
            .iter()
            .map(|&raw| DecodedArg { name: None, value: format!("{raw:#x}"), raw })
            .collect(),
    }
}

fn returns_hex(name: &str) -> bool {
    matches!(name, "mmap" | "mmap2" | "brk" | "mremap" | "shmat")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct MockMem(HashMap<u64, Vec<u8>>);

    impl MemoryReader for MockMem {
        fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
            for (&base, bytes) in &self.0 {
                if addr >= base && addr < base + bytes.len() as u64 {
                    let off = (addr - base) as usize;
                    let end = (off + len).min(bytes.len());
                    return Some(bytes[off..end].to_vec());
                }
            }
            None
        }
    }

    fn mem(pairs: &[(u64, &[u8])]) -> MockMem {
        MockMem(pairs.iter().map(|(a, b)| (*a, b.to_vec())).collect())
    }

    fn ev(name: &str, args: [u64; 6], retval: i64) -> SyscallEvent {
        let nr = u64::from(syren_common::syscall_by_name(name).unwrap().number);
        SyscallEvent { pid: 7, tid: 7, nr, args, retval, ts_enter_ns: 0, duration_ns: 0 }
    }

    #[test]
    fn openat_with_path_and_flags() {
        let m = mem(&[(0x2000, b"/etc/passwd\0")]);
        // openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC)
        let d = decode(&ev("openat", [(-100i64) as u64, 0x2000, 0o2000000, 0, 0, 0], 3), &m);
        assert_eq!(d.name, "openat");
        // openat carries a 4th `mode` argument (shown as 0 for non-creating opens).
        assert_eq!(d.signature(), r#"openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC, 0)"#);
        assert_eq!(d.retval_str(), "3");
        assert!(d.error.is_none());
    }

    #[test]
    fn error_return_strace_style() {
        let m = mem(&[(0x3000, b"/nope\0")]);
        // openat(AT_FDCWD, "/nope", O_RDONLY) = -1 ENOENT
        let d = decode(&ev("openat", [(-100i64) as u64, 0x3000, 0, 0, 0, 0], -2), &m);
        assert_eq!(d.retval_str(), "-1 ENOENT (No such file or directory)");
        let err = d.error.unwrap();
        assert_eq!(err.errno, 2);
        assert_eq!(err.name, "ENOENT");
    }

    #[test]
    fn write_buffer_bounded_by_count() {
        let m = mem(&[(0x4000, b"hello world, this is a long line that exceeds the cap")]);
        // write(1, "hello", 5)
        let d = decode(&ev("write", [1, 0x4000, 5, 0, 0, 0], 5), &m);
        assert_eq!(d.signature(), r#"write(1, "hello", 5)"#);
    }

    #[test]
    fn zero_extended_fd_sentinels_render_signed() {
        // glibc often loads `int` fds with a 32-bit `mov`, zero-extending the
        // upper word (e.g. AT_FDCWD as 0x00000000_FFFFFF9C, not sign-extended).
        // Both AT_FDCWD and a `-1` fd must still render correctly.
        let m = mem(&[(0x2000, b"/x\0")]);
        let d = decode(&ev("openat", [0xFFFF_FF9C, 0x2000, 0, 0, 0, 0], 3), &m);
        assert_eq!(d.signature(), r#"openat(AT_FDCWD, "/x", O_RDONLY, 0)"#);

        let d = decode(&ev("mmap", [0, 4096, 0x3, 0x22, 0xFFFF_FFFF, 0], 0x1000), &NullMemory);
        assert_eq!(
            d.signature(),
            "mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
        );
    }

    #[test]
    fn unreadable_pointer_falls_back_to_hex() {
        let d = decode(&ev("openat", [(-100i64) as u64, 0xdead, 0, 0, 0, 0], -14), &NullMemory);
        assert_eq!(d.signature(), "openat(AT_FDCWD, 0xdead, O_RDONLY, 0)");
    }

    #[test]
    fn untyped_syscall_renders_registers_as_hex() {
        let getpid = decode(&ev("getpid", [0; 6], 1234), &NullMemory);
        assert_eq!(getpid.signature(), "getpid()");
        assert_eq!(getpid.retval_str(), "1234");
    }

    #[test]
    fn mmap_return_is_hex() {
        let d =
            decode(&ev("mmap", [0, 4096, 0x3, 0x22, (-1i64) as u64, 0], 0x7f00_1000), &NullMemory);
        assert_eq!(
            d.signature(),
            "mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)"
        );
        assert_eq!(d.retval_str(), "0x7f001000");
    }

    #[test]
    fn socket_renders_symbolic_constants() {
        let d = decode(&ev("socket", [10, 2, 0, 0, 0, 0], 3), &NullMemory);
        assert_eq!(d.signature(), "socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP)");
    }

    #[test]
    fn setsockopt_renders_level_optname_and_value() {
        let one = 1i32.to_ne_bytes();
        let m = mem(&[(0x5000, &one)]);
        let d = decode(&ev("setsockopt", [4, 6, 1, 0x5000, 4, 0], 0), &m);
        assert_eq!(d.signature(), "setsockopt(4, SOL_TCP, TCP_NODELAY, [1], 4)");
    }

    #[test]
    fn setsockopt_optval_falls_back_to_pointer_for_structs() {
        let d = decode(&ev("setsockopt", [4, 1, 13, 0xcafe, 8, 0], 0), &NullMemory);
        assert_eq!(d.signature(), "setsockopt(4, SOL_SOCKET, SO_LINGER, 0xcafe, 8)");
    }

    #[test]
    fn unknown_syscall_number() {
        let raw = SyscallEvent {
            pid: 1,
            tid: 1,
            nr: 999_999,
            args: [0; 6],
            retval: 0,
            ts_enter_ns: 0,
            duration_ns: 0,
        };
        let d = decode(&raw, &NullMemory);
        assert_eq!(d.name, "syscall_999999");
        assert_eq!(d.signature(), "syscall_999999()");
    }

    #[test]
    fn serialises_to_json() {
        let m = mem(&[(0x2000, b"/etc/passwd\0")]);
        let d = decode(&ev("openat", [(-100i64) as u64, 0x2000, 0, 0, 0, 0], 3), &m);
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains(r#""name":"openat""#));
        assert!(json.contains(r#"\"/etc/passwd\""#));
        assert!(json.contains(r#""retval":3"#));
    }
}
