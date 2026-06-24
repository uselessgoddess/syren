//! Events produced by the tracing backends.

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

use crate::{SyscallInfo, syscall_by_number};

/// A completed syscall: arguments captured on entry, paired with the return
/// value and timing captured on exit.
///
/// syren reports one event per *completed* syscall (strace style) rather than
/// separate enter/exit events, which keeps the common case (`name(args) = ret`)
/// cheap to format. Backends that observe enter and exit separately are
/// responsible for the pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct SyscallEvent {
    /// Thread-group id (the "process id" in userspace terms).
    pub pid: u32,
    /// Thread id (equals `pid` for single-threaded processes).
    pub tid: u32,
    /// Raw syscall number (`orig_rax`). May be out of table range for unknown
    /// or architecture-specific traps.
    pub nr: u64,
    /// The six raw register arguments, captured at syscall entry.
    pub args: [u64; 6],
    /// Return value (`rax`), sign-extended. Negative values in `-4095..0` are
    /// `-errno`.
    pub retval: i64,
    /// Monotonic timestamp of syscall entry.
    pub ts_enter_ns: u64,
    /// Wall-clock duration of the syscall, `ts_exit - ts_enter`.
    pub duration_ns: u64,
}

impl SyscallEvent {
    /// The static metadata for this syscall, if its number is in the table.
    pub fn info(&self) -> Option<&'static SyscallInfo> {
        u32::try_from(self.nr).ok().and_then(syscall_by_number)
    }

    /// `true` if the return value encodes an error.
    pub fn is_error(&self) -> bool {
        (-4095..0).contains(&self.retval)
    }

    /// The `errno` value if this syscall failed.
    pub fn errno(&self) -> Option<i32> {
        self.is_error().then(|| (-self.retval) as i32)
    }
}

/// A trace event: either a completed syscall or a process lifecycle change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", serde(tag = "type", rename_all = "snake_case"))]
pub enum Event {
    /// A completed syscall.
    Syscall(SyscallEvent),
    /// A traced process exited with the given status code.
    ProcessExit {
        /// The thread-group id that exited.
        pid: u32,
        /// Exit status code.
        code: i32,
    },
    /// A signal was delivered to a traced process.
    Signal {
        /// The thread-group id receiving the signal.
        pid: u32,
        /// Signal number.
        signal: i32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(nr: u64, retval: i64) -> SyscallEvent {
        SyscallEvent { pid: 1, tid: 1, nr, args: [0; 6], retval, ts_enter_ns: 0, duration_ns: 0 }
    }

    #[test]
    fn resolves_info_for_known_syscall() {
        assert_eq!(ev(0, 0).info().unwrap().name, "read");
        assert!(ev(999_999, 0).info().is_none());
    }

    #[test]
    fn error_detection() {
        assert!(!ev(0, 5).is_error());
        assert!(!ev(0, 0).is_error());
        assert!(ev(0, -2).is_error());
        assert_eq!(ev(0, -2).errno(), Some(2));
        assert_eq!(ev(0, 5).errno(), None);
        assert!(!ev(9, -4096).is_error());
    }

    #[test]
    #[cfg(feature = "std")]
    fn event_serializes_to_json() {
        let json = serde_json::to_string(&Event::Syscall(ev(0, 3))).unwrap();
        assert!(json.contains("\"type\":\"syscall\""));
        assert!(json.contains("\"nr\":0"));
    }
}
