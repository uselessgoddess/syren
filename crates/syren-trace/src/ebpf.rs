use std::collections::VecDeque;
use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use aya::maps::{Array, HashMap as BpfHashMap, MapData, RingBuf};
use aya::programs::TracePoint;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, execvp, fork};
use syren_common::ebpf::{MAX_SYSCALLS, Record};
use syren_common::{
    ArgType, Event, MemoryReader, ProcMemReader, SYSCALLS, SyscallEvent, SyscallInfo,
};

use crate::{Result, Target, TraceError, TraceOptions, Tracer};

static BPF_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/syren.bpf.o"));

#[derive(Debug, Clone)]
struct Capture {
    addr: u64,
    bytes: Vec<u8>,
}

pub(crate) struct EbpfTracer {
    /// Kept alive so the attached programs stay attached.
    _bpf: aya::Ebpf,
    ring: RingBuf<MapData>,
    leader: Option<u32>,
    baseline_ns: u64,
    child: Option<Pid>,
    watch: Vec<u32>,
    queue: VecDeque<(Event, Option<Capture>)>,
    current: Option<Capture>,
    finished: bool,
}

impl std::fmt::Debug for EbpfTracer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EbpfTracer")
            .field("leader", &self.leader)
            .field("child", &self.child)
            .field("watch", &self.watch)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl EbpfTracer {
    pub(crate) fn new(target: Target, options: TraceOptions) -> Result<Self> {
        probe()?;
        raise_memlock();

        let mut bpf = aya::Ebpf::load(BPF_OBJECT)
            .map_err(|e| TraceError::EbpfUnsupported(format!("loading BPF object: {e}")))?;

        attach_tracepoint(&mut bpf, "sys_enter", "raw_syscalls", "sys_enter")?;
        attach_tracepoint(&mut bpf, "sys_exit", "raw_syscalls", "sys_exit")?;
        if options.follow_forks {
            attach_tracepoint(&mut bpf, "sched_process_fork", "sched", "sched_process_fork")?;
        }

        populate_patharg(&mut bpf)?;

        let ring = bpf
            .take_map("EVENTS")
            .ok_or_else(|| TraceError::EbpfUnsupported("EVENTS map missing".into()))
            .and_then(|m| {
                RingBuf::try_from(m)
                    .map_err(|e| TraceError::EbpfUnsupported(format!("EVENTS ring buffer: {e}")))
            })?;

        let baseline_ns = monotonic_ns();

        let mut tracer = EbpfTracer {
            _bpf: bpf,
            ring,
            leader: None,
            baseline_ns,
            child: None,
            watch: Vec::new(),
            queue: VecDeque::new(),
            current: None,
            finished: false,
        };

        match target {
            Target::Spawn { program, args } => tracer.spawn(program, args)?,
            Target::Attach { pids } => tracer.attach(pids)?,
        }
        Ok(tracer)
    }

    fn spawn(&mut self, program: PathBuf, args: Vec<String>) -> Result<()> {
        resolve_program(&program)?;

        let prog_c = cstring(program.as_os_str().as_bytes())?;
        let argv: Vec<CString> = std::iter::once(Ok(prog_c.clone()))
            .chain(args.into_iter().map(|a| cstring(a.as_bytes())))
            .collect::<Result<_>>()?;

        // `O_CLOEXEC` so both ends vanish at the child's `execvp`.
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(TraceError::Other(format!("pipe2: {}", std::io::Error::last_os_error())));
        }
        let (read_fd, write_fd) = (fds[0], fds[1]);

        // SAFETY: between fork and exec the child only calls async-signal-safe
        // operations (`read`, `execvp`, `_exit`).
        match unsafe { fork() }? {
            ForkResult::Child => {
                let mut byte = [0u8; 1];
                // Block until the parent has armed the in-kernel filter.
                unsafe { libc::read(read_fd, byte.as_mut_ptr().cast(), 1) };
                let _ = execvp(&prog_c, &argv);
                // `execvp` only returns on failure.
                unsafe { libc::_exit(127) }
            }
            ForkResult::Parent { child } => {
                unsafe { libc::close(read_fd) };
                let tid = child.as_raw() as u32;
                self.leader = Some(tid);
                self.child = Some(child);
                // Arm the in-kernel filter *before* releasing the child, so its
                // very first syscall (the post-`execve` ones) is already traced.
                let armed = self.arm(&[tid]);
                unsafe {
                    libc::write(write_fd, [1u8].as_ptr().cast(), 1);
                    libc::close(write_fd);
                }
                armed?;
                tracing::debug!(pid = child.as_raw(), "spawned under eBPF tracing");
                Ok(())
            }
        }
    }

    fn attach(&mut self, pids: Vec<i32>) -> Result<()> {
        if pids.is_empty() {
            return Err(TraceError::Other("no pids supplied to attach to".into()));
        }
        self.leader = pids.first().map(|&p| p as u32);
        self.watch = pids.iter().map(|&p| p as u32).collect();
        self.arm(&self.watch.clone())?;
        Ok(())
    }

    /// Seed the kernel's `TARGETS` set with the given task ids.
    fn arm(&mut self, tids: &[u32]) -> Result<()> {
        let mut targets: BpfHashMap<_, u32, u8> = self
            ._bpf
            .map_mut("TARGETS")
            .ok_or_else(|| TraceError::EbpfUnsupported("TARGETS map missing".into()))
            .and_then(|m| {
                BpfHashMap::try_from(m)
                    .map_err(|e| TraceError::EbpfUnsupported(format!("TARGETS map: {e}")))
            })?;
        for &tid in tids {
            targets
                .insert(tid, 1u8, 0)
                .map_err(|e| TraceError::EbpfUnsupported(format!("seeding TARGETS: {e}")))?;
        }
        Ok(())
    }

    fn drain_ring(&mut self) {
        let baseline = self.baseline_ns;
        while let Some(item) = self.ring.next() {
            let Some(rec) = Record::from_bytes(&item) else { continue };
            let cap = (rec.cap_len > 0)
                .then(|| Capture { addr: rec.cap_addr, bytes: rec.captured().to_vec() });
            let event = Event::Syscall(record_to_event(&rec, baseline));
            self.queue.push_back((event, cap));
        }
    }

    fn liveness_done(&mut self) -> bool {
        if let Some(child) = self.child {
            match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, code)) => {
                    self.enqueue_exit(code);
                    true
                }
                Ok(WaitStatus::Signaled(_, sig, _)) => {
                    self.enqueue_exit(128 + sig as i32);
                    true
                }
                Ok(_) => false,
                Err(_) => {
                    self.enqueue_exit(0);
                    true
                }
            }
        } else if !self.watch.is_empty() {
            if self.watch.iter().all(|&p| !pid_alive(p)) {
                self.enqueue_exit(0);
                true
            } else {
                false
            }
        } else {
            true
        }
    }

    fn enqueue_exit(&mut self, code: i32) {
        self.drain_ring();
        if let Some(pid) = self.leader {
            self.queue.push_back((Event::ProcessExit { pid, code }, None));
        }
        self.finished = true;
    }

    fn wait_ring(&self, timeout_ms: i32) {
        let mut pfd = libc::pollfd { fd: self.ring.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    }
}

impl Tracer for EbpfTracer {
    fn next_event(&mut self) -> Result<Option<Event>> {
        loop {
            if let Some((event, cap)) = self.queue.pop_front() {
                self.current = cap;
                return Ok(Some(event));
            }
            self.drain_ring();
            if !self.queue.is_empty() {
                continue;
            }
            if self.finished {
                return Ok(None);
            }
            if self.liveness_done() {
                continue;
            }
            self.wait_ring(100);
        }
    }

    fn leader(&self) -> Option<u32> {
        self.leader
    }

    fn memory(&self, ev: &SyscallEvent) -> Box<dyn MemoryReader> {
        Box::new(EbpfMemory { tid: ev.tid, capture: self.current.clone() })
    }
}

/// A [`MemoryReader`] that serves the in-kernel path capture for the current
/// event, falling back to `/proc/<tid>/mem` for anything not captured.
#[derive(Debug)]
struct EbpfMemory {
    tid: u32,
    capture: Option<Capture>,
}

impl MemoryReader for EbpfMemory {
    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        if let Some(cap) = &self.capture {
            let end = cap.addr + cap.bytes.len() as u64;
            if addr >= cap.addr && addr < end {
                let off = (addr - cap.addr) as usize;
                let stop = (off + len).min(cap.bytes.len());
                return Some(cap.bytes[off..stop].to_vec());
            }
        }
        ProcMemReader::open(self.tid).ok().and_then(|m| m.read(addr, len))
    }
}

fn record_to_event(rec: &Record, baseline: u64) -> SyscallEvent {
    SyscallEvent {
        pid: rec.pid,
        tid: rec.tid,
        nr: rec.nr,
        args: rec.args,
        retval: rec.retval,
        ts_enter_ns: rec.ts_enter_ns.saturating_sub(baseline),
        duration_ns: rec.duration_ns,
    }
}

fn attach_tracepoint(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    category: &str,
    event: &str,
) -> Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut(prog_name)
        .ok_or_else(|| TraceError::EbpfUnsupported(format!("program `{prog_name}` missing")))?
        .try_into()
        .map_err(|e| {
            TraceError::EbpfUnsupported(format!("`{prog_name}` is not a tracepoint: {e}"))
        })?;
    program
        .load()
        .map_err(|e| TraceError::EbpfUnsupported(format!("loading `{prog_name}`: {e}")))?;
    program
        .attach(category, event)
        .map_err(|e| TraceError::EbpfUnsupported(format!("attaching `{prog_name}`: {e}")))?;
    Ok(())
}

fn populate_patharg(bpf: &mut aya::Ebpf) -> Result<()> {
    let mut patharg: Array<_, u8> = bpf
        .map_mut("PATHARG")
        .ok_or_else(|| TraceError::EbpfUnsupported("PATHARG map missing".into()))
        .and_then(|m| {
            Array::try_from(m).map_err(|e| TraceError::EbpfUnsupported(format!("PATHARG map: {e}")))
        })?;
    for s in SYSCALLS {
        if let Some(slot) = path_arg_slot(s) {
            patharg
                .set(s.number, slot, 0)
                .map_err(|e| TraceError::EbpfUnsupported(format!("PATHARG[{}]: {e}", s.number)))?;
        }
    }
    Ok(())
}

fn path_arg_slot(s: &SyscallInfo) -> Option<u8> {
    if s.name == "execve" || s.name == "execveat" {
        return None;
    }
    let idx = s.args.iter().position(|a| a.ty == ArgType::Path)?;
    (s.number < MAX_SYSCALLS && idx < 6).then_some((idx + 1) as u8)
}

fn probe() -> Result<()> {
    if !Path::new("/sys/kernel/btf/vmlinux").exists() {
        return Err(TraceError::EbpfUnsupported(
            "kernel BTF (/sys/kernel/btf/vmlinux) is required but missing".into(),
        ));
    }
    if !has_bpf_capability() {
        return Err(TraceError::EbpfUnsupported(
            "loading BPF needs root or CAP_BPF (try sudo)".into(),
        ));
    }
    Ok(())
}

fn has_bpf_capability() -> bool {
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    // CAP_SYS_ADMIN = 21, CAP_BPF = 39.
    let Some(eff) = read_cap_eff() else { return false };
    (eff >> 21) & 1 == 1 || (eff >> 39) & 1 == 1
}

fn read_cap_eff() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

/// Best-effort raise of `RLIMIT_MEMLOCK` for pre-5.11 kernels that charge BPF
/// memory against it. Harmless (and unnecessary) on modern kernels.
fn raise_memlock() {
    let lim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim) };
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

fn pid_alive(pid: u32) -> bool {
    if unsafe { libc::kill(pid as i32, 0) } == 0 {
        return true;
    }
    // EPERM means the process exists but we may not signal it.
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn resolve_program(program: &Path) -> Result<()> {
    let found = if program.as_os_str().as_bytes().contains(&b'/') {
        is_executable(program)
    } else {
        std::env::var_os("PATH")
            .map(|paths| std::env::split_paths(&paths).any(|dir| is_executable(&dir.join(program))))
            .unwrap_or(false)
    };
    if found {
        Ok(())
    } else {
        Err(TraceError::Spawn {
            program: program.display().to_string(),
            source: std::io::Error::from_raw_os_error(libc::ENOENT),
        })
    }
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn cstring(bytes: &[u8]) -> Result<CString> {
    CString::new(bytes)
        .map_err(|e| TraceError::Other(format!("invalid (NUL-containing) argument: {e}")))
}

#[cfg(test)]
mod tests {
    use syren_common::ebpf::{CAP_BYTES, Record};
    use syren_common::syscall_by_name;

    use super::*;

    fn record(nr: u64) -> Record {
        Record {
            pid: 100,
            tid: 101,
            nr,
            args: [1, 2, 3, 4, 5, 6],
            retval: -2,
            ts_enter_ns: 5_000,
            duration_ns: 250,
            cap_addr: 0,
            cap_len: 0,
            _pad: 0,
            cap: [0; CAP_BYTES],
        }
    }

    #[test]
    fn ebpf_is_parseable() {
        let object = aya_obj::Object::parse(BPF_OBJECT).expect("embedded BPF object parses");
        for program in ["sys_enter", "sys_exit", "sched_process_fork"] {
            assert!(object.programs.contains_key(program), "missing BPF program {program}");
        }
        for map in ["EVENTS", "ENTERS", "TARGETS", "PATHARG"] {
            assert!(object.maps.contains_key(map), "missing BPF map {map}");
        }
    }

    #[test]
    fn record_maps_onto_syscall_event() {
        let ev = record_to_event(&record(257), 1_000);
        assert_eq!(ev.pid, 100);
        assert_eq!(ev.tid, 101);
        assert_eq!(ev.nr, 257);
        assert_eq!(ev.args, [1, 2, 3, 4, 5, 6]);
        assert_eq!(ev.retval, -2);
        assert_eq!(ev.ts_enter_ns, 4_000);
        assert_eq!(ev.duration_ns, 250);
    }

    #[test]
    fn timestamp_never_underflows() {
        let ev = record_to_event(&record(0), 9_000);
        assert_eq!(ev.ts_enter_ns, 0);
    }

    #[test]
    fn selects_path_argument() {
        // open(filename, ...) -> arg 0 -> slot 1.
        assert_eq!(path_arg_slot(syscall_by_name("open").unwrap()), Some(1));
        // openat(dfd, filename, ...) -> arg 1 -> slot 2.
        assert_eq!(path_arg_slot(syscall_by_name("openat").unwrap()), Some(2));
        // access(filename, mode) -> arg 0 -> slot 1.
        assert_eq!(path_arg_slot(syscall_by_name("access").unwrap()), Some(1));
        // read has no path argument.
        assert_eq!(path_arg_slot(syscall_by_name("read").unwrap()), None);
    }

    #[test]
    fn execve_path_is_excluded() {
        let execve = syscall_by_name("execve").unwrap();
        assert!(execve.args.iter().any(|a| a.ty == ArgType::Path));
        assert_eq!(path_arg_slot(execve), None);
        assert_eq!(path_arg_slot(syscall_by_name("execveat").unwrap()), None);
    }

    #[test]
    fn memory_serves_captured_bytes() {
        let mem = EbpfMemory {
            tid: u32::MAX,
            capture: Some(Capture { addr: 0x4000, bytes: b"0123456789".to_vec() }),
        };
        assert_eq!(mem.read(0x4000, 4), Some(b"0123".to_vec()));
        assert_eq!(mem.read(0x4000 + 8, 999), Some(b"89".to_vec()));
        assert_eq!(mem.read(0x9999, 4), None);
    }

    #[test]
    fn memory_without_capture() {
        let mem = EbpfMemory { tid: u32::MAX, capture: None };
        assert_eq!(mem.read(0x4000, 4), None);
    }
}
