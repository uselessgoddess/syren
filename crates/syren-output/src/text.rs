use std::borrow::Cow;
use std::io::{self, Write};

use syren_decode::DecodedSyscall;

use crate::{Record, Sink};

/// Knobs for [`TextSink`].
#[derive(Debug, Clone, Default)]
pub struct TextOptions {
    /// Prefix each line with `[pid N]` (used when following forks/threads).
    pub show_pid: bool,
    /// Append the syscall duration as `<seconds>` (like strace `-T`).
    pub show_timing: bool,
    /// Colourise the output with ANSI escapes.
    pub color: bool,
}

/// Writes trace records as strace-style text.
pub struct TextSink<W> {
    out: W,
    opts: TextOptions,
    palette: Palette,
}

impl<W> std::fmt::Debug for TextSink<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextSink").field("opts", &self.opts).finish_non_exhaustive()
    }
}

impl<W: Write> TextSink<W> {
    /// A sink with default options.
    pub fn new(out: W) -> Self {
        Self::with_options(out, TextOptions::default())
    }

    /// A sink with explicit options.
    pub fn with_options(out: W, opts: TextOptions) -> Self {
        let palette = Palette::new(opts.color);
        Self { out, opts, palette }
    }

    fn prefix(&mut self, pid: u32) -> io::Result<()> {
        if self.opts.show_pid {
            write!(self.out, "[pid {pid:>5}] ")?;
        }
        Ok(())
    }

    fn write_call(&mut self, s: &DecodedSyscall) -> io::Result<()> {
        let p = self.palette;
        write!(self.out, "{}{}{}(", p.name, s.name, p.reset)?;
        for (i, a) in s.args.iter().enumerate() {
            if i > 0 {
                write!(self.out, ", ")?;
            }
            write!(self.out, "{}", a.value)?;
        }
        let ret = s.retval_str();
        match &s.error {
            Some(_) => write!(self.out, ") = {}{ret}{}", p.error, p.reset),
            None => write!(self.out, ") = {ret}"),
        }
    }
}

impl<W: Write> Sink for TextSink<W> {
    fn record(&mut self, rec: Record<'_>) -> io::Result<()> {
        let p = self.palette;
        match rec {
            Record::Syscall(s) => {
                self.prefix(s.pid)?;
                self.write_call(s)?;
                if self.opts.show_timing {
                    write!(self.out, " <{}>", fmt_secs(s.duration_ns))?;
                }
                writeln!(self.out)
            }
            Record::Exit { pid, code } => {
                self.prefix(pid)?;
                writeln!(self.out, "{}+++ exited with {code} +++{}", p.meta, p.reset)
            }
            Record::Signal { pid, signal } => {
                self.prefix(pid)?;
                writeln!(self.out, "{}--- {} ---{}", p.meta, signal_name(signal), p.reset)
            }
        }
    }
}

fn fmt_secs(ns: u64) -> String {
    format!("{:.6}", ns as f64 / 1_000_000_000.0)
}

fn signal_name(sig: i32) -> Cow<'static, str> {
    match syren_common::signal_name(sig) {
        Some(name) => Cow::Borrowed(name),
        None => Cow::Owned(format!("signal {sig}")),
    }
}

#[derive(Debug, Clone, Copy)]
struct Palette {
    name: &'static str,
    error: &'static str,
    meta: &'static str,
    reset: &'static str,
}

impl Palette {
    const PLAIN: Palette = Palette { name: "", error: "", meta: "", reset: "" };
    const COLOR: Palette = Palette {
        name: "\x1b[36m",  // cyan: the syscall name
        error: "\x1b[31m", // red: failed return values
        meta: "\x1b[33m",  // yellow: exit/signal lines
        reset: "\x1b[0m",
    };

    fn new(color: bool) -> Palette {
        if color { Palette::COLOR } else { Palette::PLAIN }
    }
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
            let opts = TextOptions { show_pid: true, show_timing: true, color: false };
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

    #[test]
    fn color_wraps_name_and_meta() {
        let mut buf = Vec::new();
        {
            let opts = TextOptions { color: true, ..TextOptions::default() };
            let mut sink = TextSink::with_options(&mut buf, opts);
            let s = syscall("getpid", vec![], 100);
            sink.record(Record::Syscall(&s)).unwrap();
            sink.record(Record::Signal { pid: 100, signal: 9 }).unwrap();
        }
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(out, "\u{1b}[36mgetpid\u{1b}[0m() = 100\n\u{1b}[33m--- SIGKILL ---\u{1b}[0m\n");
    }
}
