//! eBPF syscall collector — kernel-level visibility via tracepoints.
//!
//! Replaces (or complements) audit-based collection with zero-latency
//! kernel-level process execution and network connection monitoring.
//!
//! Requires: Linux kernel 5.8+, CAP_BPF + CAP_PERFMON (or root).
//! Gracefully disables itself when eBPF is not available.

#![allow(dead_code, unused_imports)]
// Functions are used only when compiled with --features ebpf

use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};
use std::net::Ipv4Addr;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Path to the eBPF bytecode file (compiled separately).
/// In production, this could be embedded via include_bytes! in a build script.
const EBPF_OBJ_PATH: &str = "/usr/local/lib/innerwarden/innerwarden-ebpf";
const EBPF_OBJ_PATH_DEV: &str =
    "crates/sensor-ebpf/target/bpfel-unknown-none/release/innerwarden-ebpf";

/// Check if eBPF is available on this system.
pub fn is_ebpf_available() -> bool {
    if cfg!(not(target_os = "linux")) {
        return false;
    }

    // Kernel version >= 5.8
    if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        let parts: Vec<u32> = release
            .trim()
            .split('.')
            .take(2)
            .filter_map(|p| p.parse().ok())
            .collect();
        if parts.len() >= 2 && (parts[0] < 5 || (parts[0] == 5 && parts[1] < 8)) {
            return false;
        }
    } else {
        return false;
    }

    // BTF available
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        return false;
    }

    // eBPF bytecode exists
    std::path::Path::new(EBPF_OBJ_PATH).exists() || std::path::Path::new(EBPF_OBJ_PATH_DEV).exists()
}

/// Find the eBPF bytecode file.
fn find_ebpf_obj() -> Option<String> {
    if std::path::Path::new(EBPF_OBJ_PATH).exists() {
        Some(EBPF_OBJ_PATH.to_string())
    } else if std::path::Path::new(EBPF_OBJ_PATH_DEV).exists() {
        Some(EBPF_OBJ_PATH_DEV.to_string())
    } else {
        None
    }
}

/// Resolve parent PID from /proc/<pid>/status. Best-effort (returns 0 on failure).
fn resolve_ppid(pid: u32) -> u32 {
    let path = format!("/proc/{pid}/status");
    if let Ok(content) = std::fs::read_to_string(&path) {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("PPid:\t") {
                return val.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

/// Extract container ID from /proc/<pid>/cgroup. Returns None for host processes.
fn resolve_container_id(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/cgroup");
    let content = std::fs::read_to_string(&path).ok()?;
    for line in content.lines() {
        // Docker: 0::/docker/<container_id>
        // Podman: 0::/libpod-<container_id>.scope
        // k8s:    0::/kubepods/besteffort/pod<uuid>/<container_id>
        if let Some(rest) = line.split("docker/").nth(1) {
            let id = rest.split('/').next().unwrap_or(rest);
            if id.len() >= 12 {
                return Some(id[..12].to_string());
            }
        }
        if let Some(rest) = line.split("libpod-").nth(1) {
            let id = rest.split('.').next().unwrap_or(rest);
            if id.len() >= 12 {
                return Some(id[..12].to_string());
            }
        }
        if line.contains("kubepods") {
            // Last segment is the container ID
            if let Some(id) = line.rsplit('/').next() {
                if id.len() >= 12 {
                    return Some(id[..12].to_string());
                }
            }
        }
    }
    None
}

/// Convert a kernel execve event to an Inner Warden Event.
#[allow(clippy::too_many_arguments)]
fn execve_to_event(
    pid: u32,
    uid: u32,
    ppid: u32,
    cgroup_id: u64,
    container_id: Option<&str>,
    comm: &str,
    filename: &str,
    host: &str,
) -> Event {
    let argv_json: Vec<serde_json::Value> = if filename.is_empty() {
        vec![serde_json::Value::String(comm.to_string())]
    } else {
        vec![serde_json::Value::String(filename.to_string())]
    };

    let mut details = serde_json::json!({
        "pid": pid,
        "uid": uid,
        "ppid": ppid,
        "comm": comm,
        "command": filename,
        "argv": argv_json,
        "argc": 1,
        "cgroup_id": cgroup_id,
    });
    if let Some(cid) = container_id {
        details["container_id"] = serde_json::Value::String(cid.to_string());
    }

    let mut tags = vec!["ebpf".to_string(), "exec".to_string()];
    let mut entities = vec![];
    if let Some(cid) = container_id {
        tags.push("container".to_string());
        entities.push(EntityRef::container(cid));
    }

    Event {
        ts: chrono::Utc::now(),
        host: host.to_string(),
        source: "ebpf".to_string(),
        kind: "shell.command_exec".to_string(),
        severity: Severity::Info,
        summary: format!("Shell command executed: {filename}"),
        details,
        tags,
        entities,
    }
}

/// Convert a kernel connect event to an Inner Warden Event.
#[allow(clippy::too_many_arguments)]
fn connect_to_event(
    pid: u32,
    uid: u32,
    ppid: u32,
    cgroup_id: u64,
    container_id: Option<&str>,
    comm: &str,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    host: &str,
) -> Event {
    let mut details = serde_json::json!({
        "pid": pid,
        "uid": uid,
        "ppid": ppid,
        "comm": comm,
        "dst_ip": dst_ip.to_string(),
        "dst_port": dst_port,
        "cgroup_id": cgroup_id,
    });
    if let Some(cid) = container_id {
        details["container_id"] = serde_json::Value::String(cid.to_string());
    }

    let mut tags = vec!["ebpf".to_string(), "network".to_string()];
    let mut entities = vec![EntityRef::ip(dst_ip.to_string())];
    if let Some(cid) = container_id {
        tags.push("container".to_string());
        entities.push(EntityRef::container(cid));
    }

    Event {
        ts: chrono::Utc::now(),
        host: host.to_string(),
        source: "ebpf".to_string(),
        kind: "network.outbound_connect".to_string(),
        severity: if dst_port == 4444 || dst_port == 1337 || dst_port == 31337 {
            Severity::High
        } else {
            Severity::Info
        },
        summary: format!("{comm} (pid={pid}) connecting to {dst_ip}:{dst_port}"),
        details,
        tags,
        entities,
    }
}

/// Convert a kernel file open event to an Inner Warden Event.
#[allow(clippy::too_many_arguments)]
fn file_open_to_event(
    pid: u32,
    uid: u32,
    ppid: u32,
    cgroup_id: u64,
    container_id: Option<&str>,
    comm: &str,
    filename: &str,
    flags: u32,
    host: &str,
) -> Event {
    let is_write = flags & 0x3 != 0; // O_WRONLY or O_RDWR

    let mut details = serde_json::json!({
        "pid": pid,
        "uid": uid,
        "ppid": ppid,
        "comm": comm,
        "filename": filename,
        "flags": flags,
        "write": is_write,
        "cgroup_id": cgroup_id,
    });
    if let Some(cid) = container_id {
        details["container_id"] = serde_json::Value::String(cid.to_string());
    }

    let mut tags = vec!["ebpf".to_string(), "file".to_string()];
    let mut entities = vec![];
    if let Some(cid) = container_id {
        tags.push("container".to_string());
        entities.push(EntityRef::container(cid));
    }

    Event {
        ts: chrono::Utc::now(),
        host: host.to_string(),
        source: "ebpf".to_string(),
        kind: if is_write {
            "file.write_access".to_string()
        } else {
            "file.read_access".to_string()
        },
        severity: if is_write
            && (filename.contains("shadow")
                || filename.contains("sudoers")
                || filename.contains("authorized_keys"))
        {
            Severity::High
        } else {
            Severity::Info
        },
        summary: format!(
            "{comm} (pid={pid}) {} {filename}",
            if is_write { "writing" } else { "reading" }
        ),
        details,
        tags,
        entities,
    }
}

/// Extract a null-terminated string from a byte slice.
fn bytes_to_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

/// Start the eBPF collector. Loads programs, attaches tracepoints, reads ring buffer.
///
/// Events flow through the same mpsc channel as all other collectors.
#[cfg(feature = "ebpf")]
pub async fn run(tx: mpsc::Sender<Event>, host: String) {
    use aya::maps::RingBuf;
    use aya::programs::TracePoint;
    use aya::Ebpf;

    if !is_ebpf_available() {
        warn!("eBPF not available — falling back to audit-based collection");
        return;
    }

    let obj_path = match find_ebpf_obj() {
        Some(p) => p,
        None => {
            warn!("eBPF bytecode not found — skipping eBPF collector");
            return;
        }
    };

    info!(path = %obj_path, "eBPF collector: loading bytecode");

    let bytes = match std::fs::read(&obj_path) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to read eBPF bytecode");
            return;
        }
    };

    let mut bpf = match Ebpf::load(&bytes) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to load eBPF programs into kernel (need root or CAP_BPF)");
            return;
        }
    };

    // Attach execve tracepoint
    match bpf.program_mut("innerwarden_execve") {
        Some(prog) => {
            let tp: &mut TracePoint = match prog.try_into() {
                Ok(t) => t,
                Err(e) => {
                    warn!(error = %e, "innerwarden_execve: not a tracepoint program");
                    return;
                }
            };
            if let Err(e) = tp.load() {
                warn!(error = %e, "innerwarden_execve: failed to load");
                return;
            }
            if let Err(e) = tp.attach("syscalls", "sys_enter_execve") {
                warn!(error = %e, "innerwarden_execve: failed to attach");
                return;
            }
            info!("eBPF: innerwarden_execve → sys_enter_execve ✅");
        }
        None => {
            warn!("eBPF: innerwarden_execve program not found in bytecode");
        }
    }

    // Attach connect tracepoint
    match bpf.program_mut("innerwarden_connect") {
        Some(prog) => {
            let tp: &mut TracePoint = match prog.try_into() {
                Ok(t) => t,
                Err(e) => {
                    warn!(error = %e, "innerwarden_connect: not a tracepoint program");
                    return;
                }
            };
            if let Err(e) = tp.load() {
                warn!(error = %e, "innerwarden_connect: failed to load");
                return;
            }
            if let Err(e) = tp.attach("syscalls", "sys_enter_connect") {
                warn!(error = %e, "innerwarden_connect: failed to attach");
                return;
            }
            info!("eBPF: innerwarden_connect → sys_enter_connect ✅");
        }
        None => {
            warn!("eBPF: innerwarden_connect program not found in bytecode");
        }
    }

    // Attach openat tracepoint (file access monitoring — non-critical)
    if let Some(prog) = bpf.program_mut("innerwarden_openat") {
        if let Ok(tp) = TryInto::<&mut TracePoint>::try_into(prog) {
            if tp.load().is_ok() {
                if let Err(e) = tp.attach("syscalls", "sys_enter_openat") {
                    warn!(error = %e, "innerwarden_openat: failed to attach");
                } else {
                    info!("eBPF: innerwarden_openat → sys_enter_openat ✅");
                }
            }
        }
    }

    // Read from ring buffer
    let mut ring_buf = match RingBuf::try_from(bpf.map_mut("EVENTS").unwrap()) {
        Ok(rb) => rb,
        Err(e) => {
            warn!(error = %e, "eBPF: failed to open ring buffer");
            return;
        }
    };

    info!("eBPF collector active — kernel-level syscall monitoring (execve + connect + openat)");

    loop {
        while let Some(item) = ring_buf.next() {
            let data: &[u8] = &item;
            if data.len() < 4 {
                continue;
            }

            let kind = u32::from_ne_bytes(data[0..4].try_into().unwrap());

            let event = match kind {
                // ExecveEvent layout (#[repr(C)]):
                //   kind(4) pid(4) tgid(4) uid(4) gid(4) ppid(4) cgroup_id(8) comm(64) filename(256)
                //   Offsets: 0  4  8  12  16  20  24  32..96  96..352
                1 if data.len() >= 352 => {
                    let pid = u32::from_ne_bytes(data[4..8].try_into().unwrap());
                    let uid = u32::from_ne_bytes(data[12..16].try_into().unwrap());
                    let cgroup_id = u64::from_ne_bytes(data[24..32].try_into().unwrap());
                    let comm = bytes_to_string(&data[32..96]);
                    let filename = bytes_to_string(&data[96..352]);

                    if comm.starts_with("innerwarden") {
                        continue;
                    }

                    let ppid = resolve_ppid(pid);
                    let container_id = resolve_container_id(pid);

                    Some(execve_to_event(
                        pid,
                        uid,
                        ppid,
                        cgroup_id,
                        container_id.as_deref(),
                        &comm,
                        &filename,
                        &host,
                    ))
                }
                // ConnectEvent layout (#[repr(C)]):
                //   kind(4) pid(4) tgid(4) uid(4) ppid(4) _pad(4) cgroup_id(8) comm(64)
                //   dst_addr(4) dst_port(2) family(2) ts_ns(8)
                //   Offsets: 0  4  8  12  16  20  24  32..96  96  100  102
                2 if data.len() >= 104 => {
                    let pid = u32::from_ne_bytes(data[4..8].try_into().unwrap());
                    let uid = u32::from_ne_bytes(data[12..16].try_into().unwrap());
                    let cgroup_id = u64::from_ne_bytes(data[24..32].try_into().unwrap());
                    let comm = bytes_to_string(&data[32..96]);
                    let addr = u32::from_ne_bytes(data[96..100].try_into().unwrap());
                    let port = u16::from_ne_bytes(data[100..102].try_into().unwrap());

                    let ip = Ipv4Addr::from(addr);

                    if ip.is_loopback() || ip.is_private() || ip.is_unspecified() {
                        continue;
                    }

                    let ppid = resolve_ppid(pid);
                    let container_id = resolve_container_id(pid);

                    Some(connect_to_event(
                        pid,
                        uid,
                        ppid,
                        cgroup_id,
                        container_id.as_deref(),
                        &comm,
                        ip,
                        port,
                        &host,
                    ))
                }
                // FileOpenEvent layout (#[repr(C)]):
                //   kind(4) pid(4) uid(4) ppid(4) cgroup_id(8) comm(64) filename(256) flags(4)
                //   Offsets: 0  4  8  12  16  24..88  88..344  344
                3 if data.len() >= 348 => {
                    let pid = u32::from_ne_bytes(data[4..8].try_into().unwrap());
                    let uid = u32::from_ne_bytes(data[8..12].try_into().unwrap());
                    let cgroup_id = u64::from_ne_bytes(data[16..24].try_into().unwrap());
                    let comm = bytes_to_string(&data[24..88]);
                    let filename = bytes_to_string(&data[88..344]);
                    let flags = u32::from_ne_bytes(data[344..348].try_into().unwrap());

                    if comm.starts_with("innerwarden") {
                        continue;
                    }

                    let ppid = resolve_ppid(pid);
                    let container_id = resolve_container_id(pid);

                    Some(file_open_to_event(
                        pid,
                        uid,
                        ppid,
                        cgroup_id,
                        container_id.as_deref(),
                        &comm,
                        &filename,
                        flags,
                        &host,
                    ))
                }
                _ => None,
            };

            if let Some(ev) = event {
                if tx.send(ev).await.is_err() {
                    warn!("eBPF collector: channel closed, stopping");
                    return;
                }
            }
        }

        // Poll interval — 100ms is fast enough for security, low CPU
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Fallback when ebpf feature is not enabled.
#[cfg(not(feature = "ebpf"))]
pub async fn run(_tx: mpsc::Sender<Event>, _host: String) {
    if is_ebpf_available() {
        info!("eBPF is available but the sensor was compiled without --features ebpf");
        info!("Rebuild with: cargo build --features ebpf -p innerwarden-sensor");
    }
    // Silently return — other collectors handle detection
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execve_event_maps_to_shell_command_exec() {
        let event = execve_to_event(1234, 0, 1, 0, None, "bash", "/usr/bin/curl", "test-host");
        assert_eq!(event.source, "ebpf");
        assert_eq!(event.kind, "shell.command_exec");
        assert!(event.summary.contains("curl"));
        assert_eq!(event.details["pid"], 1234);
        assert_eq!(event.details["ppid"], 1);
    }

    #[test]
    fn execve_event_with_container() {
        let event = execve_to_event(
            1234,
            0,
            1,
            12345,
            Some("abc123def456"),
            "bash",
            "/usr/bin/curl",
            "test-host",
        );
        assert_eq!(event.details["container_id"], "abc123def456");
        assert_eq!(event.details["cgroup_id"], 12345);
        assert!(event.tags.contains(&"container".to_string()));
    }

    #[test]
    fn connect_event_high_severity_for_reverse_shell_ports() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let event = connect_to_event(5678, 1000, 1, 0, None, "nc", ip, 4444, "test-host");
        assert_eq!(event.severity, Severity::High);

        let event_normal = connect_to_event(5678, 1000, 1, 0, None, "curl", ip, 443, "test-host");
        assert_eq!(event_normal.severity, Severity::Info);
    }

    #[test]
    fn connect_event_with_container() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let event = connect_to_event(
            5678,
            1000,
            1,
            99999,
            Some("container123"),
            "nc",
            ip,
            4444,
            "test-host",
        );
        assert_eq!(event.details["container_id"], "container123");
        assert!(event.tags.contains(&"container".to_string()));
    }

    #[test]
    fn file_open_event_write_to_shadow() {
        let event = file_open_to_event(
            100,
            0,
            1,
            0,
            None,
            "vim",
            "/etc/shadow",
            0x1, // O_WRONLY
            "test-host",
        );
        assert_eq!(event.kind, "file.write_access");
        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.details["ppid"], 1);
    }

    #[test]
    fn file_open_event_read_normal() {
        let event = file_open_to_event(
            100,
            1000,
            1,
            0,
            None,
            "cat",
            "/etc/passwd",
            0x0, // O_RDONLY
            "test-host",
        );
        assert_eq!(event.kind, "file.read_access");
        assert_eq!(event.severity, Severity::Info);
    }

    #[test]
    fn bytes_to_string_handles_null_terminator() {
        let buf = b"hello\0world\0\0\0";
        assert_eq!(bytes_to_string(buf), "hello");
    }

    #[test]
    fn ebpf_availability_on_non_linux() {
        if cfg!(target_os = "macos") {
            assert!(!is_ebpf_available());
        }
    }

    #[test]
    fn resolve_ppid_nonexistent_process() {
        // PID 999999999 shouldn't exist
        assert_eq!(resolve_ppid(999_999_999), 0);
    }

    #[test]
    fn resolve_container_id_host_process() {
        // Host process shouldn't have a container ID
        // (pid 1 is always the init process on the host)
        if cfg!(target_os = "linux") {
            assert!(resolve_container_id(1).is_none());
        }
    }
}
