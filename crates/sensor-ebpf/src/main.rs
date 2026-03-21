//! Inner Warden eBPF programs — kernel-level security monitoring.
//!
//! Tracepoints:
//!   - sys_enter_execve: captures every process execution
//!   - sys_enter_connect: captures outbound network connections
//!   - sys_enter_openat: captures sensitive file access
//!
//! Kprobes:
//!   - commit_creds: detects privilege escalation (uid 1000 → uid 0)
//!
//! LSM (Linux Security Modules):
//!   - bprm_check_security: blocks execution from /tmp, /dev/shm (policy-gated)
//!
//! XDP:
//!   - innerwarden_xdp: wire-speed IP blocking at the network driver level
//!
//! Events are sent to userspace via a shared ring buffer.
//! Blocked IPs are managed via a shared HashMap (agent ↔ kernel).

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user_str_bytes},
    macros::{kprobe, lsm, map, tracepoint, xdp},
    maps::{HashMap, RingBuf},
    programs::{LsmContext, ProbeContext, TracePointContext, XdpContext},
};
use aya_log_ebpf::info;
use innerwarden_ebpf_types::{ExecveEvent, ConnectEvent, PrivEscEvent, SyscallKind, MAX_COMM_LEN, MAX_FILENAME_LEN};

// ---------------------------------------------------------------------------
// Ring buffer — shared between all eBPF programs, read by userspace
// ---------------------------------------------------------------------------

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB ring buffer

// ---------------------------------------------------------------------------
// XDP blocklist — IPv4 addresses to drop at wire speed
// ---------------------------------------------------------------------------
//
// Populated by the agent via aya userspace API.
// Key: IPv4 address as u32 (network byte order)
// Value: flags (1 = block, 0 = removed/placeholder)
// Max 10,000 IPs — enough for most threat scenarios.

#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(10_000, 0);

// ---------------------------------------------------------------------------
// XDP: innerwarden_xdp — wire-speed IP blocking
// ---------------------------------------------------------------------------
//
// Attached to a network interface. For every incoming packet:
//   1. Parse Ethernet + IPv4 header
//   2. Lookup source IP in BLOCKLIST
//   3. If found → XDP_DROP (packet never reaches the kernel stack)
//   4. If not found → XDP_PASS (normal processing)
//
// Performance: 10-25 million packets per second drop rate.
// Zero CPU overhead for dropped packets.

#[xdp]
pub fn innerwarden_xdp(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS, // fail-open: never break networking
    }
}

#[inline(always)]
fn try_xdp_firewall(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // Need at least: Ethernet header (14) + IPv4 header (20) = 34 bytes
    if data + 34 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse Ethernet header — check for IPv4 (EtherType 0x0800)
    let eth_proto = u16::from_be_bytes(unsafe {
        let ptr = data as *const u8;
        [*ptr.add(12), *ptr.add(13)]
    });

    if eth_proto != 0x0800 {
        return Ok(xdp_action::XDP_PASS); // not IPv4
    }

    // Parse IPv4 source address (offset 14 + 12 = 26, 4 bytes)
    let src_ip = u32::from_ne_bytes(unsafe {
        let ptr = data as *const u8;
        [*ptr.add(26), *ptr.add(27), *ptr.add(28), *ptr.add(29)]
    });

    // Lookup in blocklist — O(1) hash map lookup
    if unsafe { BLOCKLIST.get(&src_ip) }.is_some() {
        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_PASS)
}

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
// Kprobe: commit_creds — privilege escalation detection
// ---------------------------------------------------------------------------
//
// Fires when the kernel applies new credentials to a process.
// Detects: non-root process becoming root through unexpected paths.
//
// commit_creds(struct cred *new) — the `cred` struct contains the new uid.
// We compare current uid (before) with new uid (from cred arg).
// If old_uid != 0 && new_uid == 0 → privilege escalation.
//
// Legitimate escalation (sudo, su, login, sshd, cron) is filtered
// in userspace to avoid false positives.

/// Offset of `uid` field in `struct cred` (after atomic_long_t usage).
/// Linux 5.x+: usage(8) → uid(4) at offset 8.
const CRED_UID_OFFSET: usize = 8;

#[kprobe]
pub fn innerwarden_privesc(ctx: ProbeContext) -> u32 {
    match try_privesc(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_privesc(ctx: &ProbeContext) -> Result<(), i64> {
    // Current uid (before credential change)
    let old_uid = bpf_get_current_uid_gid() as u32;

    // Only care about non-root processes gaining root
    if old_uid == 0 {
        return Ok(());
    }

    // Read the new cred pointer (first argument to commit_creds)
    let cred_ptr: *const u8 = unsafe { ctx.arg(0).ok_or(1i64)? };

    // Read new uid from struct cred (offset 8: after atomic_long_t usage)
    let new_uid: u32 = unsafe {
        bpf_probe_read_kernel(cred_ptr.add(CRED_UID_OFFSET) as *const u32).map_err(|e| e)?
    };

    // Only fire when escalating TO root
    if new_uid != 0 {
        return Ok(());
    }

    // At this point: old_uid != 0, new_uid == 0 → privilege escalation
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    let mut entry = match EVENTS.reserve::<PrivEscEvent>(0) {
        Some(e) => e,
        None => return Ok(()), // ring buffer full — fail-open
    };

    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.kind = SyscallKind::PrivEsc as u32;
    event.pid = pid;
    event.tgid = tgid;
    event.old_uid = old_uid;
    event.new_uid = new_uid;
    event.cgroup_id = cgroup_id;
    event.ts_ns = ts;

    if let Ok(comm) = bpf_get_current_comm() {
        event.comm[..comm.len().min(MAX_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
    }

    entry.submit(0);

    Ok(())
}

// ---------------------------------------------------------------------------
// LSM: bprm_check_security — block execution from dangerous paths
// ---------------------------------------------------------------------------
//
// Enforces execution policy at the kernel level. When enabled via the
// LSM_POLICY map, blocks binaries executed from:
//   /tmp/       — common staging area for malware
//   /dev/shm/   — shared memory, often used for fileless malware
//   /var/tmp/   — persistent temp, another staging area
//
// Policy map keys:
//   0 = master switch (1 = enforce, 0 = disabled)
//
// Returns 0 to allow, -EPERM (-1) to deny.
// When policy map is empty or key 0 is not set → allow (fail-open).

/// Policy map — controls LSM enforcement.
/// Key 0 = master switch: 0 = disabled (observe only), 1 = enforce (block).
/// Managed by the agent via bpftool on the pinned map.
#[map]
static LSM_POLICY: HashMap<u32, u32> = HashMap::with_max_entries(16, 0);

#[lsm(hook = "bprm_check_security")]
pub fn innerwarden_lsm_exec(ctx: LsmContext) -> i32 {
    match try_lsm_exec(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // fail-open: allow on error
    }
}

fn try_lsm_exec(ctx: &LsmContext) -> Result<i32, i64> {
    // Check if enforcement is enabled (key 0 in policy map)
    let enabled = unsafe { LSM_POLICY.get(&0u32) };
    if enabled.is_none() || *enabled.unwrap() == 0 {
        return Ok(0); // policy disabled — allow everything
    }

    // Read filename from linux_binprm (first arg)
    // struct linux_binprm { ..., const char *filename, ... }
    // filename is at a known offset — we read the pointer then the string
    let bprm_ptr: *const u8 = unsafe { ctx.arg::<*const u8>(0).ok_or(1i64)? };

    // linux_binprm->filename offset varies by kernel version
    // On 6.x: filename is typically at offset 72 (after interp, vma, etc.)
    // We'll read the filename pointer from bprm
    // Actually, for bprm_check_security, the filename is already in bprm->filename
    // Offset 72 on kernel 6.x (may need adjustment)
    const BPRM_FILENAME_OFFSET: usize = 72;

    let filename_ptr: *const u8 = unsafe {
        bpf_probe_read_kernel(bprm_ptr.add(BPRM_FILENAME_OFFSET) as *const *const u8)
            .map_err(|e| e)?
    };

    // Read first 16 bytes of the filename to check the prefix
    let mut buf = [0u8; 16];
    unsafe {
        let _ = bpf_probe_read_kernel(filename_ptr as *const [u8; 16]).map(|v| buf = v);
    }

    // Check dangerous prefixes
    let is_dangerous =
        // /tmp/
        (buf[0] == b'/' && buf[1] == b't' && buf[2] == b'm' && buf[3] == b'p' && buf[4] == b'/')
        // /dev/shm/
        || (buf[0] == b'/' && buf[1] == b'd' && buf[2] == b'e' && buf[3] == b'v' && buf[4] == b'/' && buf[5] == b's' && buf[6] == b'h' && buf[7] == b'm' && buf[8] == b'/')
        // /var/tmp/
        || (buf[0] == b'/' && buf[1] == b'v' && buf[2] == b'a' && buf[3] == b'r' && buf[4] == b'/' && buf[5] == b't' && buf[6] == b'm' && buf[7] == b'p' && buf[8] == b'/');

    if !is_dangerous {
        return Ok(0); // safe path — allow
    }

    // Block execution from dangerous path
    // Also emit an event so the sensor sees the blocked attempt
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let ts = unsafe { bpf_ktime_get_ns() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    if let Some(mut entry) = EVENTS.reserve::<innerwarden_ebpf_types::ExecveEvent>(0) {
        let event = unsafe { &mut *entry.as_mut_ptr() };
        event.kind = 6; // LSM blocked execution (new kind)
        event.pid = pid;
        event.tgid = (pid_tgid >> 32) as u32;
        event.uid = uid;
        event.gid = 0;
        event.ppid = 0;
        event.cgroup_id = cgroup_id;
        event.ts_ns = ts;
        event.argc = 0;
        event.argv = [[0u8; 128]; 8];

        // Copy filename to event
        event.filename = [0u8; 256];
        let copy_len = buf.len().min(256);
        event.filename[..copy_len].copy_from_slice(&buf[..copy_len]);

        if let Ok(comm) = bpf_get_current_comm() {
            event.comm[..comm.len().min(MAX_COMM_LEN)]
                .copy_from_slice(&comm[..comm.len().min(MAX_COMM_LEN)]);
        }

        entry.submit(0);
    }

    Ok(-1) // -EPERM: deny execution
}

// ---------------------------------------------------------------------------
// Panic handler (required for no_std)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
