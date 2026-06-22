use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Instant;

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, execvp, fork};
use syren_common::{Event, SyscallEvent};

use crate::{Result, Target, TraceError, TraceOptions, Tracer};

#[derive(Debug, Clone, Copy)]
struct Inflight {
    nr: u64,
    args: [u64; 6],
    enter_ns: u64,
}

/// The `ptrace(2)` backend.
#[derive(Debug)]
pub struct PtraceTracer {
    start: Instant,
    follow: bool,
    live: HashSet<Pid>,
    inflight: HashMap<Pid, Inflight>,
    tgid: HashMap<Pid, u32>,
    pending_resume: Option<(Pid, Option<Signal>)>,
    leader: Option<u32>,
}

impl PtraceTracer {
    /// Set up the backend for `target`.
    pub fn new(target: Target, options: TraceOptions) -> Result<Self> {
        match target {
            Target::Spawn { program, args } => Self::spawn(program, args, options),
            Target::Attach { pids } => Self::attach(pids, options),
        }
    }

    fn empty(options: &TraceOptions) -> Self {
        PtraceTracer {
            start: Instant::now(),
            follow: options.follow_forks,
            live: HashSet::new(),
            inflight: HashMap::new(),
            tgid: HashMap::new(),
            pending_resume: None,
            leader: None,
        }
    }

    fn spawn(program: PathBuf, args: Vec<String>, options: TraceOptions) -> Result<Self> {
        let prog_c = cstring(program.as_os_str().as_bytes())?;
        let argv: Vec<CString> = std::iter::once(Ok(prog_c.clone()))
            .chain(args.into_iter().map(|a| cstring(a.as_bytes())))
            .collect::<Result<_>>()?;

        // SAFETY: between fork and exec the child only calls async-signal-safe
        // operations (`traceme`, `execvp`, `_exit`).
        match unsafe { fork() }? {
            ForkResult::Child => {
                let _ = ptrace::traceme();
                let _ = execvp(&prog_c, &argv);
                // `execvp` only returns on failure.
                unsafe { libc::_exit(127) }
            }
            ForkResult::Parent { child } => {
                let mut tracer = Self::empty(&options);
                match waitpid(child, None)? {
                    WaitStatus::Exited(..) | WaitStatus::Signaled(..) => {
                        return Err(TraceError::Spawn {
                            program: program.display().to_string(),
                            source: std::io::Error::from_raw_os_error(libc::ENOENT),
                        });
                    }
                    _ => {}
                }
                tracer.configure(child)?;
                tracer.live.insert(child);
                tracer.tgid.insert(child, child.as_raw() as u32);
                tracer.leader = Some(child.as_raw() as u32);
                ptrace::syscall(child, None)?;
                tracing::debug!(pid = child.as_raw(), "spawned and tracing");
                Ok(tracer)
            }
        }
    }

    fn attach(pids: Vec<i32>, options: TraceOptions) -> Result<Self> {
        if pids.is_empty() {
            return Err(TraceError::Other("no pids supplied to attach to".into()));
        }
        let mut tracer = Self::empty(&options);
        tracer.leader = pids.first().map(|&p| p as u32);
        for raw in pids {
            let pid = Pid::from_raw(raw);
            ptrace::attach(pid)?;
            waitpid(pid, None)?;
            tracer.configure(pid)?;
            tracer.live.insert(pid);
            ptrace::syscall(pid, None)?;
            tracing::debug!(pid = raw, "attached and tracing");
        }
        Ok(tracer)
    }

    fn configure(&self, pid: Pid) -> Result<()> {
        use ptrace::Options;
        let mut opts = Options::PTRACE_O_TRACESYSGOOD | Options::PTRACE_O_EXITKILL;
        if self.follow {
            opts |= Options::PTRACE_O_TRACEFORK
                | Options::PTRACE_O_TRACEVFORK
                | Options::PTRACE_O_TRACECLONE
                | Options::PTRACE_O_TRACEEXEC;
        }
        ptrace::setoptions(pid, opts)?;
        Ok(())
    }

    fn now_ns(&self) -> u64 {
        self.start.elapsed().as_nanos() as u64
    }

    fn tgid_of(&mut self, pid: Pid) -> u32 {
        if let Some(&t) = self.tgid.get(&pid) {
            return t;
        }
        let tgid = read_tgid(pid).unwrap_or_else(|| pid.as_raw() as u32);
        self.tgid.insert(pid, tgid);
        tgid
    }

    fn handle(&mut self, status: WaitStatus) -> Result<Option<Event>> {
        match status {
            WaitStatus::PtraceSyscall(pid) => self.on_syscall_stop(pid),

            WaitStatus::Exited(pid, code) => {
                let tgid = self.tgid_of(pid);
                self.forget(pid);
                tracing::debug!(pid = pid.as_raw(), code, "tracee exited");
                Ok(Some(Event::ProcessExit { pid: tgid, code }))
            }

            WaitStatus::Signaled(pid, sig, _core_dumped) => {
                let tgid = self.tgid_of(pid);
                self.forget(pid);
                Ok(Some(Event::ProcessExit { pid: tgid, code: 128 + sig as i32 }))
            }

            WaitStatus::PtraceEvent(pid, _sig, event) => {
                if event == libc::PTRACE_EVENT_EXEC {
                    self.inflight.remove(&pid);
                } else if self.follow
                    && matches!(
                        event,
                        libc::PTRACE_EVENT_FORK
                            | libc::PTRACE_EVENT_VFORK
                            | libc::PTRACE_EVENT_CLONE
                    )
                {
                    if let Ok(new) = ptrace::getevent(pid) {
                        let child = Pid::from_raw(new as i32);
                        self.live.insert(child);
                        tracing::debug!(parent = pid.as_raw(), child = new, "following new task");
                    }
                }
                ptrace::syscall(pid, None)?;
                Ok(None)
            }

            WaitStatus::Stopped(pid, sig) => {
                let deliver = match sig {
                    Signal::SIGSTOP | Signal::SIGTRAP => None,
                    other => Some(other),
                };
                ptrace::syscall(pid, deliver)?;
                match deliver {
                    Some(s) => {
                        let tgid = self.tgid_of(pid);
                        Ok(Some(Event::Signal { pid: tgid, signal: s as i32 }))
                    }
                    None => Ok(None),
                }
            }

            WaitStatus::Continued(_) | WaitStatus::StillAlive => Ok(None),
        }
    }

    fn on_syscall_stop(&mut self, pid: Pid) -> Result<Option<Event>> {
        if let Some(inflight) = self.inflight.remove(&pid) {
            let regs = ptrace::getregs(pid)?;
            let exit_ns = self.now_ns();
            self.pending_resume = Some((pid, None));
            let tgid = self.tgid_of(pid);
            Ok(Some(Event::Syscall(SyscallEvent {
                pid: tgid,
                tid: pid.as_raw() as u32,
                nr: inflight.nr,
                args: inflight.args,
                retval: regs.rax as i64,
                ts_enter_ns: inflight.enter_ns,
                duration_ns: exit_ns.saturating_sub(inflight.enter_ns),
            })))
        } else {
            let regs = ptrace::getregs(pid)?;
            self.inflight.insert(
                pid,
                Inflight {
                    nr: regs.orig_rax,
                    args: [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9],
                    enter_ns: self.now_ns(),
                },
            );
            ptrace::syscall(pid, None)?;
            Ok(None)
        }
    }

    fn forget(&mut self, pid: Pid) {
        self.live.remove(&pid);
        self.inflight.remove(&pid);
        self.tgid.remove(&pid);
    }
}

impl Tracer for PtraceTracer {
    fn next_event(&mut self) -> Result<Option<Event>> {
        loop {
            // Resume any task we left stopped at its syscall-exit on the
            // previous call (see `on_syscall_stop`).
            if let Some((pid, sig)) = self.pending_resume.take() {
                ptrace::syscall(pid, sig)?;
            }
            if self.live.is_empty() {
                return Ok(None);
            }
            let status = match waitpid(None, Some(WaitPidFlag::__WALL)) {
                Ok(status) => status,
                Err(nix::Error::ECHILD) => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            if let Some(event) = self.handle(status)? {
                return Ok(Some(event));
            }
        }
    }

    fn leader(&self) -> Option<u32> {
        self.leader
    }
}

fn cstring(bytes: &[u8]) -> Result<CString> {
    CString::new(bytes)
        .map_err(|e| TraceError::Other(format!("invalid (NUL-containing) argument: {e}")))
}

fn read_tgid(pid: Pid) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid.as_raw())).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:"))
        .and_then(|rest| rest.trim().parse().ok())
}
