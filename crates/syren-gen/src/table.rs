//! Parser for the Linux kernel `syscall_64.tbl` format.
//!
//! The file lives at `arch/x86/entry/syscalls/syscall_64.tbl` in the kernel
//! tree. Each non-comment line has the shape:
//!
//! ```text
//! <number> <abi> <name> [<entry point> [<compat entry point>]]
//! ```
//!
//! Syscall numbers are an ABI contract, not creative expression, so vendoring
//! the table is the cleanest source of truth for "100% coverage" generation.

/// Which ABI a table entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abi {
    /// Available to both 64-bit and x32 callers.
    Common,
    /// 64-bit only.
    B64,
    /// x32 only — deliberately skipped by syren (we target the 64-bit ABI).
    X32,
}

impl Abi {
    fn parse(s: &str) -> Option<Abi> {
        match s {
            "common" => Some(Abi::Common),
            "64" => Some(Abi::B64),
            "x32" => Some(Abi::X32),
            _ => None,
        }
    }
}

/// A single parsed row of the syscall table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallEntry {
    /// The syscall number (`__NR_<name>`).
    pub number: u32,
    /// The ABI this entry belongs to.
    pub abi: Abi,
    /// The userspace syscall name (e.g. `openat`).
    pub name: String,
    /// The kernel entry point (e.g. `sys_openat`), when present.
    pub entry: Option<String>,
}

/// Parse the full `syscall_64.tbl` contents, keeping only the 64-bit ABI
/// (`common` + `64`) and skipping `x32` rows.
///
/// Entries are returned sorted by syscall number.
pub fn parse_tbl(input: &str) -> Vec<SyscallEntry> {
    let mut entries: Vec<SyscallEntry> =
        input.lines().filter_map(parse_line).filter(|e| e.abi != Abi::X32).collect();
    entries.sort_by_key(|e| e.number);
    entries
}

fn parse_line(line: &str) -> Option<SyscallEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let mut cols = line.split_whitespace();
    let number: u32 = cols.next()?.parse().ok()?;
    let abi = Abi::parse(cols.next()?)?;
    let name = cols.next()?.to_string();
    let entry = cols.next().map(str::to_string);

    Some(SyscallEntry { number, abi, name, entry })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# comment line
#
0\tcommon\tread\t\t\tsys_read
1\tcommon\twrite\t\t\tsys_write
2\tcommon\topen\t\t\tsys_open
59\tcommon\texecve\t\t\tsys_execve
   # indented comment
512\tx32\trt_sigaction\t\tcompat_sys_rt_sigaction
314\t64\tsched_setattr\t\tsys_sched_setattr
";

    #[test]
    fn parses_common_and_64_skips_x32() {
        let entries = parse_tbl(SAMPLE);
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["read", "write", "open", "execve", "sched_setattr"]);
        assert!(!names.contains(&"rt_sigaction"), "x32 rows must be skipped");
    }

    #[test]
    fn parses_numbers_entry_and_abi() {
        let entries = parse_tbl(SAMPLE);
        let execve = entries.iter().find(|e| e.name == "execve").unwrap();
        assert_eq!(execve.number, 59);
        assert_eq!(execve.abi, Abi::Common);
        assert_eq!(execve.entry.as_deref(), Some("sys_execve"));

        let sched = entries.iter().find(|e| e.name == "sched_setattr").unwrap();
        assert_eq!(sched.abi, Abi::B64);
    }

    #[test]
    fn result_is_sorted_by_number() {
        let entries = parse_tbl(SAMPLE);
        assert!(entries.windows(2).all(|w| w[0].number < w[1].number));
    }

    #[test]
    fn ignores_blank_and_comment_lines() {
        assert!(parse_tbl("\n\n# nothing here\n   \n").is_empty());
    }
}
