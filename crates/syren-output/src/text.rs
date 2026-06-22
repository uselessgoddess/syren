use std::io::{self, Write};

use crate::{Record, Sink};

/// Knobs for [`TextSink`].
#[derive(Debug, Clone, Default)]
pub struct TextOptions {
    /// Prefix each line with `[pid N]` (used when following forks/threads).
    pub show_pid: bool,
    /// Append the syscall duration as `<seconds>` (like strace `-T`).
    pub show_timing: bool,
}

/// Writes trace records as strace-style text.
pub struct TextSink<W> {
    out: W,
    opts: TextOptions,
}

impl<W> std::fmt::Debug for TextSink<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextSink").field("opts", &self.opts).finish_non_exhaustive()
    }
}

impl<W: Write> TextSink<W> {
    /// A sink with default options.
    pub fn new(out: W) -> Self {
        Self { out, opts: TextOptions::default() }
    }

    /// A sink with explicit options.
    pub fn with_options(out: W, opts: TextOptions) -> Self {
        Self { out, opts }
    }

    fn prefix(&mut self, pid: u32) -> io::Result<()> {
        if self.opts.show_pid {
            write!(self.out, "[pid {pid:>5}] ")?;
        }
        Ok(())
    }
}

impl<W: Write> Sink for TextSink<W> {
    fn record(&mut self, rec: Record<'_>) -> io::Result<()> {
        match rec {
            Record::Syscall(s) => {
                self.prefix(s.pid)?;
                write!(self.out, "{} = {}", s.signature(), s.retval_str())?;
                if self.opts.show_timing {
                    write!(self.out, " <{}>", fmt_secs(s.duration_ns))?;
                }
                writeln!(self.out)
            }
            Record::Exit { pid, code } => {
                self.prefix(pid)?;
                writeln!(self.out, "+++ exited with {code} +++")
            }
            Record::Signal { pid, signal } => {
                self.prefix(pid)?;
                writeln!(self.out, "--- {} ---", signal_name(signal))
            }
        }
    }
}

fn fmt_secs(ns: u64) -> String {
    format!("{:.6}", ns as f64 / 1_000_000_000.0)
}

fn signal_name(sig: i32) -> String {
    let name = match sig {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        17 => "SIGCHLD",
        18 => "SIGCONT",
        19 => "SIGSTOP",
        20 => "SIGTSTP",
        28 => "SIGWINCH",
        _ => return format!("signal {sig}"),
    };
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{arg, syscall};

    #[test]
    fn strace_line_and_exit() {
        let mut buf = Vec::new();
        {
            let mut sink = TextSink::new(&mut buf);
            let s = syscall("openat", vec![arg("dfd", "AT_FDCWD"), arg("filename", "\"/x\"")], 3);
            sink.record(Record::Syscall(&s)).unwrap();
            sink.record(Record::Exit { pid: 100, code: 0 }).unwrap();
        }
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(out, "openat(AT_FDCWD, \"/x\") = 3\n+++ exited with 0 +++\n");
    }

    #[test]
    fn timing_and_pid_prefix() {
        let mut buf = Vec::new();
        {
            let opts = TextOptions { show_pid: true, show_timing: true };
            let mut sink = TextSink::with_options(&mut buf, opts);
            let s = syscall("getpid", vec![], 100);
            sink.record(Record::Syscall(&s)).unwrap();
        }
        let out = String::from_utf8(buf).unwrap();
        assert!(out.starts_with("[pid   100] getpid() = 100 <0.0000"), "got {out:?}");
        assert!(out.trim_end().ends_with('>'), "got {out:?}");
    }

    #[test]
    fn signal_record_uses_name() {
        let mut buf = Vec::new();
        {
            let mut sink = TextSink::new(&mut buf);
            sink.record(Record::Signal { pid: 100, signal: 2 }).unwrap();
            sink.record(Record::Signal { pid: 100, signal: 99 }).unwrap();
        }
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(out, "--- SIGINT ---\n--- signal 99 ---\n");
    }
}
