/// Number of bytes captured in-kernel for a path argument (NUL terminated,
/// truncated past this length). Sized to fit the common case while keeping the
/// [`Record`] small enough to assemble on the modest BPF stack.
pub const CAP_BYTES: usize = 128;

/// Upper bound on syscall numbers the path-capture table covers. The x86-64
/// table tops out well below this; the slack leaves room for future numbers
/// without resizing the in-kernel `Array`.
pub const MAX_SYSCALLS: u32 = 512;

/// One completed syscall, paired from its enter/exit tracepoints in-kernel.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Record {
    /// Thread-group id (the userspace "process id").
    pub pid: u32,
    /// Thread id (the kernel task that made the call).
    pub tid: u32,
    /// Raw syscall number (`id` from `raw_syscalls:sys_enter`).
    pub nr: u64,
    /// The six raw arguments captured at syscall entry.
    pub args: [u64; 6],
    /// Return value (`ret` from `raw_syscalls:sys_exit`).
    pub retval: i64,
    /// Kernel-monotonic timestamp of entry (`bpf_ktime_get_ns`).
    pub ts_enter_ns: u64,
    /// Time spent inside the syscall (`exit - enter`), in nanoseconds.
    pub duration_ns: u64,
    /// Virtual address the [`cap`](Self::cap) bytes were read from, or `0` when
    /// nothing was captured.
    pub cap_addr: u64,
    /// Number of valid bytes in [`cap`](Self::cap).
    pub cap_len: u32,
    /// Padding so the record size is a multiple of 8.
    pub _pad: u32,
    /// Inline path capture; only the first [`cap_len`](Self::cap_len) bytes are
    /// meaningful.
    pub cap: [u8; CAP_BYTES],
}

impl Record {
    /// Size of the on-the-wire record, in bytes.
    pub const SIZE: usize = core::mem::size_of::<Record>();

    /// Reconstruct a record from raw ring-buffer bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Record> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        // SAFETY: `Record` is `#[repr(C)]`, so any byte pattern is a valid value.
        // We checked the length above and use an unaligned read since
        // the source slice may not be 8-byte aligned.
        Some(unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<Record>()) })
    }

    /// The captured path bytes, or an empty slice when nothing was captured.
    pub fn captured(&self) -> &[u8] {
        let len = (self.cap_len as usize).min(CAP_BYTES);
        &self.cap[..len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let mut rec = Record {
            pid: 42,
            tid: 99,
            nr: 257,
            args: [1, 2, 3, 4, 5, 6],
            retval: -2,
            ts_enter_ns: 1_000,
            duration_ns: 250,
            cap_addr: 0x2000,
            cap_len: 5,
            _pad: 0,
            cap: [0; CAP_BYTES],
        };
        rec.cap[..5].copy_from_slice(b"/etc\0");

        let bytes = unsafe {
            core::slice::from_raw_parts((&rec as *const Record).cast::<u8>(), Record::SIZE)
        };
        let back = Record::from_bytes(bytes).expect("full-size slice parses");

        assert_eq!(back.pid, 42);
        assert_eq!(back.nr, 257);
        assert_eq!(back.args, [1, 2, 3, 4, 5, 6]);
        assert_eq!(back.retval, -2);
        assert_eq!(back.duration_ns, 250);
        assert_eq!(back.captured(), b"/etc\0");
    }

    #[test]
    fn short_slice_is_rejected() {
        assert!(Record::from_bytes(&[0u8; 8]).is_none());
    }

    #[test]
    fn capture_length_is_clamped() {
        let rec = Record {
            pid: 0,
            tid: 0,
            nr: 0,
            args: [0; 6],
            retval: 0,
            ts_enter_ns: 0,
            duration_ns: 0,
            cap_addr: 0,
            cap_len: u32::MAX,
            _pad: 0,
            cap: [b'x'; CAP_BYTES],
        };
        assert_eq!(rec.captured().len(), CAP_BYTES);
    }
}
