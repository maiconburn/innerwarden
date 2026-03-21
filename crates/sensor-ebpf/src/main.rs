//! Inner Warden eBPF programs — kernel-level security monitoring.
//!
//! Tracepoints:
//!   - sys_enter_execve: captures every process execution
//!   - sys_enter_connect: captures outbound network connections
//!
//! Events are sent to userspace via a shared ring buffer.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use aya_log_ebpf::info;
use innerwarden_ebpf_types::{ExecveEvent, ConnectEvent, SyscallKind, MAX_COMM_LEN, MAX_FILENAME_LEN};

// ---------------------------------------------------------------------------
// Ring buffer — shared between all eBPF programs, read by userspace
// ---------------------------------------------------------------------------

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB ring buffer

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_execve
// ---------------------------------------------------------------------------
//
// Fires on every execve() syscall. Captures:
//   - PID, UID, parent PID
//   - Filename being executed
//   - Process comm name
//
// This is the most important tracepoint for security — every command
// execution on the system is visible here.

#[tracepoint]
pub fn innerwarden_execve(ctx: TracePointContext) -> u32 {
    match try_execve(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_execve(ctx: &TracePointContext) -> Result<(), i64> {
    // Read filename from tracepoint args
    // sys_enter_execve args: [filename, argv, envp]
    let filename_ptr: *const u8 = unsafe { ctx.read_at(16)? };

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;

    let ts = unsafe { bpf_ktime_get_ns() };

    // Reserve space in ring buffer
    let mut entry = match EVENTS.reserve::<ExecveEvent>(0) {
        Some(e) => e,
        None => return Ok(()), // ring buffer full — drop silently (fail-open)
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Execve as u32;
    event.pid = pid;
    event.tgid = tgid;
    event.uid = uid;
    event.gid = gid;
    event.ppid = 0; // resolved in userspace via /proc/<pid>/status
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.ts_ns = ts;
    event.argc = 0;

    // Read comm
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)].copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    // Read filename from user space
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename);
    }

    // Zero out argv (will be populated in future iteration)
    event.argv = [[0u8; 128]; 8];

    entry.submit(0);

    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_connect
// ---------------------------------------------------------------------------
//
// Fires on every connect() syscall. Captures:
//   - PID, UID
//   - Destination IP and port
//   - Process comm name
//
// Used to detect C2 callbacks, data exfiltration, and suspicious outbound
// connections from compromised processes.

#[tracepoint]
pub fn innerwarden_connect(ctx: TracePointContext) -> u32 {
    match try_connect(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_connect(ctx: &TracePointContext) -> Result<(), i64> {
    // sys_enter_connect args: [fd, uservaddr, addrlen]
    let addr_ptr: *const u8 = unsafe { ctx.read_at(24)? };

    // Read sockaddr_in (first 2 bytes = family, next 2 = port, next 4 = addr)
    let mut sa_buf = [0u8; 16];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(addr_ptr, &mut sa_buf);
    }

    let family = u16::from_ne_bytes([sa_buf[0], sa_buf[1]]);

    // Only track IPv4 (AF_INET = 2) for now
    if family != 2 {
        return Ok(());
    }

    let port = u16::from_be_bytes([sa_buf[2], sa_buf[3]]);
    let addr = u32::from_ne_bytes([sa_buf[4], sa_buf[5], sa_buf[6], sa_buf[7]]);

    // Skip loopback (127.x.x.x) and unspecified (0.0.0.0)
    let first_octet = sa_buf[4];
    if first_octet == 127 || addr == 0 {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    let mut entry = match EVENTS.reserve::<ConnectEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::Connect as u32;
    event.pid = pid;
    event.tgid = tgid;
    event.uid = uid;
    event.ppid = 0; // resolved in userspace
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.dst_addr = addr;
    event.dst_port = port;
    event.family = family;
    event.ts_ns = ts;

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)].copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);

    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: sys_enter_openat
// ---------------------------------------------------------------------------
//
// Monitors file access to sensitive paths. Only emits events for paths
// matching security-relevant prefixes to avoid flooding the ring buffer.

#[tracepoint]
pub fn innerwarden_openat(ctx: TracePointContext) -> u32 {
    match try_openat(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_openat(ctx: &TracePointContext) -> Result<(), i64> {
    // sys_enter_openat args: [dfd, filename, flags, mode]
    let filename_ptr: *const u8 = unsafe { ctx.read_at(24)? };

    let mut filename_buf = [0u8; 256];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut filename_buf);
    }

    // Only emit events for sensitive paths (kernel-space filtering)
    let is_sensitive = {
        let f = &filename_buf;
        // /etc/passwd, /etc/shadow, /etc/sudoers*
        (f[0] == b'/' && f[1] == b'e' && f[2] == b't' && f[3] == b'c' && f[4] == b'/')
        // /root/.ssh/
        || (f[0] == b'/' && f[1] == b'r' && f[2] == b'o' && f[3] == b'o' && f[4] == b't')
        // /home/*/.ssh/
        || (f[0] == b'/' && f[1] == b'h' && f[2] == b'o' && f[3] == b'm' && f[4] == b'e')
    };

    if !is_sensitive {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let flags: u32 = unsafe { ctx.read_at(32)? };

    let mut entry = match EVENTS.reserve::<innerwarden_ebpf_types::FileOpenEvent>(0) {
        Some(e) => e,
        None => return Ok(()),
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = innerwarden_ebpf_types::SyscallKind::FileOpen as u32;
    event.pid = pid;
    event.uid = uid;
    event.ppid = 0; // resolved in userspace
    event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    event.filename = filename_buf;
    event.flags = flags;
    event.ts_ns = ts;

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// Panic handler (required for no_std)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
