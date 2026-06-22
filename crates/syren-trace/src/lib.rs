//! Tracing backends that turn a running (or spawned) program into a
//! stream of [`syren_common::Event`].
//!
//! Two backends are envisioned:
//!
//! * [`Backend::Ptrace`] — an unprivileged `ptrace(2)` engine. It needs no root,
//!   no kernel headers and no special toolchain, so it is the default and the
//!   one exercised in CI (see the `ptrace` module).
//! * [`Backend::Ebpf`] — the project's north-star engine, built on `raw_syscalls`
//!   tracepoints via aya. It is scaffolded behind the `ebpf` feature
//!   and not yet implemented.
//!
//! All backends are driven through the pull-based [`Tracer`] trait: call
//! [`Tracer::next_event`] in a loop until it yields `None`.

#[cfg(feature = "ebpf")]
mod ebpf;
mod ptrace;

use std::path::PathBuf;

pub use ptrace::PtraceTracer;
use syren_common::Event;

/// Result alias for tracing operations.
pub type Result<T> = std::result::Result<T, TraceError>;

/// Errors raised while setting up or running a tracer.
#[derive(Debug, thiserror::Error)]
pub enum TraceError {
    /// Spawning the target program failed.
    #[error("failed to spawn `{program}`: {source}")]
    Spawn {
        /// The program we tried to execute.
        program: String,
        /// The underlying OS error.
        source: std::io::Error,
    },

    /// A `ptrace`/`waitpid` system call failed.
    #[error("ptrace error: {0}")]
    Os(#[from] nix::Error),

    /// The requested backend is not compiled into this build.
    #[error("backend `{0}` is not available in this build")]
    BackendUnavailable(&'static str),

    /// Any other setup failure with a human-readable message.
    #[error("{0}")]
    Other(String),
}

/// What to trace: either a program syren spawns, or existing processes it
/// attaches to.
#[derive(Debug, Clone)]
pub enum Target {
    /// Spawn `program` (resolved via `PATH`) with `args` (argv\[1..\]) and trace
    /// it from its first instruction.
    Spawn {
        /// Executable to run.
        program: PathBuf,
        /// Arguments after argv\[0\].
        args: Vec<String>,
    },
    /// Attach to already-running processes by pid (`-p`).
    Attach {
        /// Process ids to attach to.
        pids: Vec<i32>,
    },
}

/// Backend-independent tracing knobs.
#[derive(Debug, Clone, Default)]
pub struct TraceOptions {
    /// Follow `fork`/`vfork`/`clone` into children and new threads (`-f`).
    pub follow_forks: bool,
}

/// Which tracing engine to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backend {
    /// Unprivileged `ptrace(2)` engine. Works without root; the default.
    #[default]
    Ptrace,
    /// eBPF engine backend (not yet implemented).
    Ebpf,
}

impl Backend {
    /// Stable lowercase name, used for CLI parsing and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Ptrace => "ptrace",
            Backend::Ebpf => "ebpf",
        }
    }
}

/// A backend that yields a stream of trace events.
///
/// The contract is pull-based and synchronous: each call blocks until the next
/// event is ready and returns `Ok(None)` once every traced task has exited.
pub trait Tracer {
    /// Produce the next trace event, or `None` when tracing is complete.
    fn next_event(&mut self) -> Result<Option<Event>>;

    /// The id of the "primary" traced process — the program syren spawned, or
    /// the first pid it attached to. Drivers use it to propagate that process's
    /// exit status as their own (like strace). `None` when there is no
    /// meaningful leader.
    fn leader(&self) -> Option<u32> {
        None
    }
}

/// Build a boxed [`Tracer`] for the requested backend, target and options.
pub fn tracer(backend: Backend, target: Target, options: TraceOptions) -> Result<Box<dyn Tracer>> {
    match backend {
        Backend::Ptrace => Ok(Box::new(PtraceTracer::new(target, options)?)),
        Backend::Ebpf => {
            #[cfg(feature = "ebpf")]
            {
                Ok(Box::new(ebpf::EbpfTracer::new(target, options)?))
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (target, options);
                Err(TraceError::BackendUnavailable("ebpf"))
            }
        }
    }
}
