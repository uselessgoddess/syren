//! Output formatters that turn a stream of trace [`Record`] into bytes.
//!
//! A driver (the CLI) decodes each tracer event into a [`DecodedSyscall`] and
//! feeds it — together with process lifecycle records — to a [`Sink`]. Three
//! sinks are provided:
//!
//! * [`TextSink`] — strace-style `name(args) = ret` lines (the default).
//! * [`JsonSink`] — newline-delimited JSON, one object per record.
//! * [`SummarySink`] — a `strace -c` style aggregate table printed on finish.
//!
//! Sinks write to any [`std::io::Write`].

mod json;
mod summary;
mod text;

use std::io;

pub use json::JsonSink;
pub use summary::SummarySink;
use syren_decode::DecodedSyscall;
pub use text::{TextOptions, TextSink};

/// One item in a trace stream: a completed syscall or a process lifecycle
/// change. Syscalls are borrowed to avoid copying the decoded arguments.
#[derive(Debug)]
pub enum Record<'a> {
    /// A decoded, completed syscall.
    Syscall(&'a DecodedSyscall),
    /// A traced process exited with the given status code.
    Exit {
        /// Thread-group id that exited.
        pid: u32,
        /// Exit status code.
        code: i32,
    },
    /// A signal was delivered to a traced process.
    Signal {
        /// Thread-group id receiving the signal.
        pid: u32,
        /// Signal number.
        signal: i32,
    },
}

/// A destination for trace records.
pub trait Sink {
    /// Write a single record.
    fn record(&mut self, rec: Record<'_>) -> io::Result<()>;

    /// Flush any buffered/aggregated output. Called once at end of stream.
    fn finish(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use syren_decode::{DecodedArg, DecodedSyscall};

    pub(crate) fn arg(name: &'static str, value: &str) -> DecodedArg {
        DecodedArg { name: Some(name), value: value.to_string(), raw: 0 }
    }

    pub(crate) fn syscall(
        name: &'static str,
        args: Vec<DecodedArg>,
        retval: i64,
    ) -> DecodedSyscall {
        DecodedSyscall {
            pid: 100,
            tid: 100,
            nr: 0,
            name: name.into(),
            args,
            retval,
            error: None,
            duration_ns: 1_500,
            ts_enter_ns: 0,
        }
    }
}
