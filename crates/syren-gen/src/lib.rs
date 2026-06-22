//! Build-time code generation for [syren](https://github.com/uselessgoddess/syren).
//!
//! This crate is the heart of syren's "100% coverage without hand-written
//! parsers" approach. Instead of maintaining argument parsers by hand, syren *generates* its syscall table from two
//! pieces of existing metadata:
//!
//! 1. The kernel's [`syscall_64.tbl`](table) — the authoritative list of syscall
//!    numbers and names for the x86_64 ABI.
//! 2. A compact, strace-style [argument metadata](meta) table covering the hot
//!    syscalls, with everything else falling back to generic rendering.
//!
//! [`generate`] turns those into a Rust source file that `syren-common` includes
//! at build time, exposing a `SYSCALLS` table to the rest of the workspace.
//!
//! Keeping this crate dependency-free (std only) keeps it cheap as a
//! build-dependency.

pub mod category;
pub mod codegen;
pub mod meta;
pub mod table;

pub use category::{Category, categorize};
pub use codegen::generate;
pub use meta::{ArgKind, ArgMeta, SyscallMeta, lookup as lookup_meta};
pub use table::{Abi, SyscallEntry, parse_tbl};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_consistent_with_parse() {
        let tbl = "0\tcommon\tread\tsys_read\n1\tcommon\twrite\tsys_write\n";
        let entries = parse_tbl(tbl);
        let src = generate(tbl);
        assert!(src.contains(&format!("SYSCALL_COUNT: usize = {}", entries.len())));
        for e in &entries {
            assert!(src.contains(&format!("name: {:?}", e.name)));
        }
    }
}
