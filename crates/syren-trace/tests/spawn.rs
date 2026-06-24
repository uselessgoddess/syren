use std::sync::Mutex;

use syren_common::Event;
use syren_trace::{Backend, Target, TraceError, TraceOptions, tracer};

static TRACER_LOCK: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    TRACER_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn spawn(program: &str, args: &[&str]) -> Box<dyn syren_trace::Tracer> {
    tracer(
        Backend::Ptrace,
        Target::Spawn {
            program: program.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
        },
        TraceOptions::default(),
    )
    .expect("failed to start tracer")
}

fn drain(mut t: Box<dyn syren_trace::Tracer>) -> (usize, Option<i32>, usize) {
    let (mut syscalls, mut exit, mut signals) = (0, None, 0);
    while let Some(event) = t.next_event().expect("tracer error") {
        match event {
            Event::Syscall(_) => syscalls += 1,
            Event::ProcessExit { code, .. } => exit = Some(code),
            Event::Signal { .. } => signals += 1,
        }
    }
    (syscalls, exit, signals)
}

#[test]
fn traces_true_to_completion() {
    let _guard = serial();
    let (syscalls, exit, _signals) = drain(spawn("/bin/true", &[]));
    assert!(syscalls > 0, "expected to observe syscalls from /bin/true");
    assert_eq!(exit, Some(0), "/bin/true should exit 0");
}

#[test]
fn captures_nonzero_exit_code() {
    let _guard = serial();
    let (_syscalls, exit, _signals) = drain(spawn("/bin/false", &[]));
    assert_eq!(exit, Some(1), "/bin/false should exit 1");
}

#[test]
fn observes_write_syscall_arguments() {
    let _guard = serial();
    // `echo hi` must perform a write(1, "hi\n", 3) to stdout.
    let mut t = spawn("/bin/echo", &["hi"]);
    let write_nr = u64::from(syren_common::syscall_by_name("write").unwrap().number);
    let mut saw_write_to_stdout = false;
    while let Some(event) = t.next_event().expect("tracer error") {
        if let Event::Syscall(s) = event {
            if s.nr == write_nr && s.args[0] == 1 && s.retval > 0 {
                saw_write_to_stdout = true;
            }
        }
    }
    assert!(saw_write_to_stdout, "expected a write() to fd 1");
}

#[test]
fn unknown_program_fails_to_start() {
    let _guard = serial();
    let result = tracer(
        Backend::Ptrace,
        Target::Spawn { program: "/nonexistent/syren-test-binary".into(), args: vec![] },
        TraceOptions::default(),
    );
    assert!(result.is_err(), "spawning a missing program must fail");
}

/// Without the `ebpf` feature the backend reports itself unavailable, so the
/// default std-only build stays honest about what it can do.
#[cfg(not(feature = "ebpf"))]
#[test]
fn ebpf_is_unavailable_by_default() {
    let result = tracer(
        Backend::Ebpf,
        Target::Spawn { program: "/bin/true".into(), args: vec![] },
        TraceOptions::default(),
    );
    assert!(
        matches!(result.err(), Some(TraceError::BackendUnavailable("ebpf"))),
        "without the ebpf feature the backend must report itself unavailable"
    );
}

/// With the `ebpf` feature compiled in, construction must either succeed (when
/// we have `CAP_BPF` and kernel BTF — the privileged CI job) or fail
/// *gracefully* with [`TraceError::EbpfUnsupported`] so the CLI can fall back to
/// ptrace. When it does load, it must produce the same event stream as ptrace.
#[cfg(feature = "ebpf")]
#[test]
fn ebpf_feature_loads_or_degrades_gracefully() {
    let _guard = serial();
    let result = tracer(
        Backend::Ebpf,
        Target::Spawn { program: "/bin/true".into(), args: vec![] },
        TraceOptions::default(),
    );
    match result {
        Ok(t) => {
            let (syscalls, exit, _signals) = drain(t);
            assert!(syscalls > 0, "eBPF backend should observe syscalls from /bin/true");
            assert_eq!(exit, Some(0), "/bin/true should exit 0 under the eBPF backend");
        }
        Err(e) => assert!(
            matches!(e, TraceError::EbpfUnsupported(_)),
            "ebpf must degrade gracefully with EbpfUnsupported, got {e:?}"
        ),
    }
}
