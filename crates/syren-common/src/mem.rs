//! Reading a tracee's memory.
//!
//! Decoding string and buffer arguments means following pointers into the
//! traced process's address space. That capability is abstracted behind
//! [`MemoryReader`] so the decoder never has to know *which* backend produced
//! the bytes: the ptrace backend reads `/proc/<tid>/mem` of the stopped tracee,
//! while the eBPF backend can serve bytes it captured in-kernel — both look the
//! same to the decoder.

/// Reads bytes from a traced process's address space.
pub trait MemoryReader {
    /// Read up to `len` bytes starting at virtual address `addr`. Returns `None`
    /// when nothing could be read (unmapped page, gone process, ...).
    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>>;
}

/// A [`MemoryReader`] that never reads anything — used when no tracee memory is
/// available (e.g. decoding events after the process is gone). Pointers then
/// render as raw hex addresses.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullMemory;

impl MemoryReader for NullMemory {
    fn read(&self, _addr: u64, _len: usize) -> Option<Vec<u8>> {
        None
    }
}

/// A [`MemoryReader`] backed by `/proc/<pid>/mem`, the standard way to read a
/// stopped tracee's memory.
#[derive(Debug)]
pub struct ProcMemReader {
    file: std::fs::File,
}

impl ProcMemReader {
    /// Open `/proc/<pid>/mem` for reading. The caller must be the process's
    /// tracer (and the process stopped) for reads to succeed.
    pub fn open(pid: u32) -> std::io::Result<Self> {
        std::fs::File::open(format!("/proc/{pid}/mem")).map(|file| ProcMemReader { file })
    }
}

impl MemoryReader for ProcMemReader {
    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        use std::os::unix::fs::FileExt;
        let mut buf = vec![0u8; len];
        match self.file.read_at(&mut buf, addr) {
            Ok(0) | Err(_) => None,
            Ok(n) => {
                buf.truncate(n);
                Some(buf)
            }
        }
    }
}
