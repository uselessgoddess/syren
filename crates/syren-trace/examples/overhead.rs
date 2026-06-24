use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use syren_common::Event;
use syren_trace::{Backend, Target, TraceError, TraceOptions, Tracer, tracer};

struct Run {
    wall: Duration,
    seen: u64,
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    if argv.first().map(String::as_str) == Some("--workload") {
        let n = argv.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        return workload(n);
    }

    let syscalls: u64 = argv.first().and_then(|s| s.parse().ok()).unwrap_or(200_000);
    let reps: u32 = argv.get(1).and_then(|s| s.parse().ok()).unwrap_or(3).max(1);

    let exe = std::env::current_exe().expect("locate own executable");
    let count = syscalls.to_string();

    println!("syscall-heavy workload: {syscalls} × getpid(), best of {reps}\n");
    println!(
        "{:<8} {:>11}  {:>8}  {:>10}  {:>13}",
        "backend", "wall (ms)", "vs base", "syscalls", "ns/syscall"
    );
    println!("{:-<8} {:->11}  {:->8}  {:->10}  {:->13}", "", "", "", "", "");

    let base = best(reps, || {
        let start = Instant::now();
        let status =
            Command::new(&exe).args(["--workload", &count]).status().expect("spawn workload");
        assert!(status.success(), "workload exited non-zero");
        start.elapsed()
    });
    println!("{:<8} {:>11.1}  {:>7.1}×  {:>10}  {:>13}", "none", ms(base), 1.0, "—", "—");

    report("ptrace", syscalls, base, trace_run(reps, Backend::Ptrace, &exe, &count));
    report("ebpf", syscalls, base, trace_run(reps, Backend::Ebpf, &exe, &count));
}

fn workload(n: u64) {
    if std::env::var_os("SYREN_BENCH_SELFARM").is_some() {
        unsafe { libc::syscall(libc::SYS_personality, syren_common::MAGIC) };
    }
    for _ in 0..n {
        std::hint::black_box(unsafe { libc::syscall(libc::SYS_getpid) });
    }
}

fn trace_run(reps: u32, backend: Backend, exe: &Path, count: &str) -> Result<Run, TraceError> {
    let mut best: Option<Run> = None;
    for _ in 0..reps {
        let target = Target::Spawn {
            program: exe.to_path_buf(),
            args: vec!["--workload".into(), count.into()],
        };
        let t = tracer(backend, target, TraceOptions::default())?;
        let start = Instant::now();
        let seen = drain(t);
        let wall = start.elapsed();
        if best.as_ref().is_none_or(|b| wall < b.wall) {
            best = Some(Run { wall, seen });
        }
    }
    Ok(best.expect("reps >= 1"))
}

fn drain(mut t: Box<dyn Tracer>) -> u64 {
    let mut syscalls = 0;
    while let Some(event) = t.next_event().expect("tracer error") {
        if matches!(event, Event::Syscall(_)) {
            syscalls += 1;
        }
    }
    syscalls
}

fn best(reps: u32, mut run: impl FnMut() -> Duration) -> Duration {
    (0..reps).map(|_| run()).min().expect("reps >= 1")
}

fn report(name: &str, syscalls: u64, base: Duration, run: Result<Run, TraceError>) {
    match run {
        Ok(r) => {
            let overhead = r.wall.as_secs_f64() / base.as_secs_f64();
            let per = r.wall.saturating_sub(base).as_nanos() as f64 / syscalls as f64;
            println!(
                "{name:<8} {:>11.1}  {overhead:>7.1}×  {:>10}  {per:>13.0}",
                ms(r.wall),
                r.seen
            );
        }
        Err(e) => println!("{name:<8} unavailable — {e}"),
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}
