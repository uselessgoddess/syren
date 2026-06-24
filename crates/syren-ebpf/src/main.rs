//! syren's in-kernel tracer.
//!
//! Two programs attach to the architecture-independent `raw_syscalls`
//! tracepoints — which fire for *every* syscall — and pair each `sys_enter`
//! with its `sys_exit` per task. A completed [`Record`] is streamed to
//! userspace over a ring buffer. A third program (`sched_process_fork`) is
//! attached only under `--follow` to pull new tasks into the traced set.
//!
//! Filtering is by *task id* (`tid`), so `--follow` reproduces ptrace's
//! semantics exactly: without it only the leader task is traced; with it, every
//! descendant task is added as it is created.

#![no_std]
#![no_main]

use aya_ebpf::helpers::gen::bpf_ktime_get_ns;
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes};
use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::{Array, HashMap, RingBuf};
use aya_ebpf::programs::TracePointContext;
use syren_common::ebpf::{CAP_BYTES, MAX_SYSCALLS, Record};

#[repr(C)]
#[derive(Clone, Copy)]
struct Enter {
    nr: u64,
    args: [u64; 6],
    ts: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawEnter {
    id: i64,
    args: [u64; 6],
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static ENTERS: HashMap<u32, Enter> = HashMap::with_max_entries(10_240, 0);

#[map]
static TARGETS: HashMap<u32, u8> = HashMap::with_max_entries(4_096, 0);

#[map]
static PATHARG: Array<u8> = Array::with_max_entries(MAX_SYSCALLS, 0);

#[tracepoint(category = "raw_syscalls", name = "sys_enter")]
pub fn sys_enter(ctx: TracePointContext) -> u32 {
    let _ = try_enter(&ctx);
    0
}

#[tracepoint(category = "raw_syscalls", name = "sys_exit")]
pub fn sys_exit(ctx: TracePointContext) -> u32 {
    let _ = try_exit(&ctx);
    0
}

#[tracepoint(category = "sched", name = "sched_process_fork")]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    let _ = try_fork(&ctx);
    0
}

#[inline(always)]
fn is_target(tid: u32) -> bool {
    // SAFETY: `get` only reads the map; the returned reference is dropped here.
    unsafe { TARGETS.get(&tid) }.is_some()
}

fn try_enter(ctx: &TracePointContext) -> Result<(), i64> {
    let tid = bpf_get_current_pid_tgid() as u32;
    #[cfg(feature = "bench-selfarm")]
    selfarm(ctx, tid);
    if !is_target(tid) {
        return Ok(());
    }
    // `raw_syscalls:sys_enter` layout: id@8, args[6]@16
    let raw: RawEnter = unsafe { ctx.read_at(8) }?;
    let enter = Enter { nr: raw.id as u64, args: raw.args, ts: unsafe { bpf_ktime_get_ns() } };
    let _ = ENTERS.insert(&tid, &enter, 0);
    Ok(())
}

fn try_exit(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let enter = match unsafe { ENTERS.get(&tid) } {
        Some(e) => *e,
        None => return Ok(()),
    };
    let _ = ENTERS.remove(&tid);

    // `raw_syscalls:sys_exit` layout: ret@16.
    let ret: i64 = unsafe { ctx.read_at(16) }.unwrap_or(0);
    let now = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<Record>(0) {
        Some(entry) => entry,
        None => return Ok(()),
    };
    let rec_ptr = entry.as_mut_ptr();
    // SAFETY: `rec_ptr` points at reserved ring storage;
    // we initialise every field before submitting.
    unsafe {
        let r = &mut *rec_ptr;
        r.pid = tgid;
        r.tid = tid;
        r.nr = enter.nr;
        r.args = enter.args;
        r.retval = ret;
        r.ts_enter_ns = enter.ts;
        r.duration_ns = now.saturating_sub(enter.ts);
        r.cap_addr = 0;
        r.cap_len = 0;
        r._pad = 0;
        capture_path(r, &enter);
    }
    entry.submit(0);
    Ok(())
}

#[inline(always)]
unsafe fn capture_path(r: &mut Record, enter: &Enter) {
    let nr = enter.nr as u32;
    if nr >= MAX_SYSCALLS {
        return;
    }
    let idx1 = match PATHARG.get(nr) {
        Some(&v) if v != 0 && (v as usize) <= 6 => v,
        _ => return,
    };
    let addr = enter.args[(idx1 - 1) as usize];
    if addr == 0 {
        return;
    }
    let dst =
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(r.cap).cast::<u8>(), CAP_BYTES);
    if let Ok(read) = bpf_probe_read_user_str_bytes(addr as *const u8, dst) {
        r.cap_addr = addr;
        let n = read.len();
        r.cap_len = if n < CAP_BYTES { (n + 1) as u32 } else { CAP_BYTES as u32 };
    }
}

#[cfg(feature = "bench-selfarm")]
#[inline(always)]
fn selfarm(ctx: &TracePointContext, tid: u32) {
    const MARKER_NR: u64 = 135; // x86-64 personality(2)
    let nr: u64 = unsafe { ctx.read_at::<i64>(8) }.unwrap_or(-1) as u64;
    if nr != MARKER_NR {
        return;
    }
    let arg0: u64 = unsafe { ctx.read_at(16) }.unwrap_or(0);
    if arg0 == syren_common::MAGIC {
        let _ = TARGETS.insert(&tid, &1u8, 0);
    }
}

fn try_fork(ctx: &TracePointContext) -> Result<(), i64> {
    // `sched:sched_process_fork` layout: parent_pid@24, child_pid@44.
    let parent: i32 = unsafe { ctx.read_at(24) }.unwrap_or(0);
    let child: i32 = unsafe { ctx.read_at(44) }.unwrap_or(0);
    if is_target(parent as u32) {
        let _ = TARGETS.insert(&(child as u32), &1u8, 0);
    }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
