use syren_common::Event;

use crate::{Result, Target, TraceError, TraceOptions, Tracer};

/// The (not yet implemented) eBPF tracer.
#[derive(Debug)]
pub(crate) struct EbpfTracer {
    _private: (),
}

impl EbpfTracer {
    /// Load and attach the BPF programs.
    pub(crate) fn new(_target: Target, _options: TraceOptions) -> Result<Self> {
        Err(TraceError::BackendUnavailable("ebpf"))
    }
}

impl Tracer for EbpfTracer {
    fn next_event(&mut self) -> Result<Option<Event>> {
        Err(TraceError::BackendUnavailable("ebpf"))
    }
}
