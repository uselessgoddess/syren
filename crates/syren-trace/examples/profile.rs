use std::time::Instant;

use aya::programs::loaded_programs;
use aya::sys::{Stats, enable_stats};
use syren_common::Event;
use syren_trace::{Backend, Target, TraceOptions, tracer};

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("--workload") {
        let n: u64 = argv.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        unsafe { libc::syscall(libc::SYS_personality, syren_common::MAGIC) };
        for _ in 0..n {
            std::hint::black_box(unsafe { libc::syscall(libc::SYS_getpid) });
        }
        return;
    }

    let n: u64 = argv.first().and_then(|s| s.parse().ok()).unwrap_or(3_000_000);
    let _stats = enable_stats(Stats::RunTime).expect("enable bpf run-time stats (needs root)");

    let exe = std::env::current_exe().unwrap();
    let target = Target::Spawn { program: exe, args: vec!["--workload".into(), n.to_string()] };
    let mut t = tracer(Backend::Ebpf, target, TraceOptions::default()).expect("ebpf setup");

    let start = Instant::now();
    let mut seen = 0u64;
    while let Some(e) = t.next_event().expect("next") {
        if matches!(e, Event::Syscall(_)) {
            seen += 1;
        }
    }
    let wall = start.elapsed();

    eprintln!("\nworkload syscalls requested = {n}, traced = {seen}");
    eprintln!("wall (trace loop) = {:.1} ms", wall.as_secs_f64() * 1e3);
    eprintln!(
        "\n{:<22} {:>12} {:>14} {:>10} {:>10}",
        "program", "run_count", "run_time_ns", "avg_ns", "insns"
    );
    eprintln!("{:-<22} {:->12} {:->14} {:->10} {:->10}", "", "", "", "", "");
    for info in loaded_programs().flatten() {
        let name = info.name_as_str().unwrap_or("").to_string();
        if !["sys_enter", "sys_exit", "sched_proce", "sched_process_fork"]
            .iter()
            .any(|p| name.starts_with(p))
        {
            continue;
        }
        let cnt = info.run_count();
        let total = info.run_time().as_nanos() as u64;
        let avg = total.checked_div(cnt).unwrap_or(0);
        let insns = info.verified_instruction_count().unwrap_or(0);
        eprintln!("{name:<22} {cnt:>12} {total:>14} {avg:>10} {insns:>10}");
    }
    drop(t);
}
