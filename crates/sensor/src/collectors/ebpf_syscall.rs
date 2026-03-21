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

/// Convert a kernel execve event to an Inner Warden Event.
fn execve_to_event(pid: u32, uid: u32, ppid: u32, comm: &str, filename: &str, host: &str) -> Event {
    // Map to shell.command_exec kind so existing execution_guard detector works
    let argv_json: Vec<serde_json::Value> = if filename.is_empty() {
        vec![serde_json::Value::String(comm.to_string())]
    } else {
        vec![serde_json::Value::String(filename.to_string())]
    };

    Event {
        ts: chrono::Utc::now(),
        host: host.to_string(),
        source: "ebpf".to_string(),
        kind: "shell.command_exec".to_string(),
        severity: Severity::Info,
        summary: format!("Shell command executed: {filename}"),
        details: serde_json::json!({
            "pid": pid,
            "uid": uid,
            "ppid": ppid,
            "comm": comm,
            "command": filename,
            "argv": argv_json,
            "argc": 1,
        }),
        tags: vec!["ebpf".to_string(), "exec".to_string()],
        entities: vec![],
    }
}

/// Convert a kernel connect event to an Inner Warden Event.
fn connect_to_event(
    pid: u32,
    uid: u32,
    comm: &str,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    host: &str,
) -> Event {
    Event {
        ts: chrono::Utc::now(),
        host: host.to_string(),
        source: "ebpf".to_string(),
        kind: "network.outbound_connect".to_string(),
        severity: if dst_port == 4444 || dst_port == 1337 || dst_port == 31337 {
            Severity::High // common reverse shell ports
        } else {
            Severity::Info
        },
        summary: format!("{comm} (pid={pid}) connecting to {dst_ip}:{dst_port}"),
        details: serde_json::json!({
            "pid": pid,
            "uid": uid,
            "comm": comm,
            "dst_ip": dst_ip.to_string(),
            "dst_port": dst_port,
        }),
        tags: vec!["ebpf".to_string(), "network".to_string()],
        entities: vec![EntityRef::ip(dst_ip.to_string())],
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

    // Read from ring buffer
    let mut ring_buf = match RingBuf::try_from(bpf.map_mut("EVENTS").unwrap()) {
        Ok(rb) => rb,
        Err(e) => {
            warn!(error = %e, "eBPF: failed to open ring buffer");
            return;
        }
    };

    info!("eBPF collector active — kernel-level syscall monitoring running");

    loop {
        while let Some(item) = ring_buf.next() {
            let data: &[u8] = &item;
            if data.len() < 4 {
                continue;
            }

            let kind = u32::from_ne_bytes(data[0..4].try_into().unwrap());

            let event = match kind {
                // ExecveEvent: kind(4) + pid(4) + tgid(4) + uid(4) + gid(4) + ppid(4) + comm(64) + filename(256)
                1 if data.len() >= 340 => {
                    let pid = u32::from_ne_bytes(data[4..8].try_into().unwrap());
                    let uid = u32::from_ne_bytes(data[16..20].try_into().unwrap());
                    let ppid = u32::from_ne_bytes(data[20..24].try_into().unwrap());
                    let comm = bytes_to_string(&data[24..88]);
                    let filename = bytes_to_string(&data[88..344]);

                    // Skip innerwarden's own processes to avoid self-loop
                    if comm.starts_with("innerwarden") {
                        continue;
                    }

                    Some(execve_to_event(pid, uid, ppid, &comm, &filename, &host))
                }
                // ConnectEvent: kind(4) + pid(4) + tgid(4) + uid(4) + comm(64) + dst_addr(4) + dst_port(2) + family(2)
                2 if data.len() >= 84 => {
                    let pid = u32::from_ne_bytes(data[4..8].try_into().unwrap());
                    let uid = u32::from_ne_bytes(data[16..20].try_into().unwrap());
                    let comm = bytes_to_string(&data[20..84]);
                    let addr = u32::from_ne_bytes(data[84..88].try_into().unwrap());
                    let port = u16::from_ne_bytes(data[88..90].try_into().unwrap());

                    let ip = Ipv4Addr::from(addr);

                    // Skip private/loopback
                    if ip.is_loopback() || ip.is_private() || ip.is_unspecified() {
                        continue;
                    }

                    Some(connect_to_event(pid, uid, &comm, ip, port, &host))
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
        let event = execve_to_event(1234, 0, 1, "bash", "/usr/bin/curl", "test-host");
        assert_eq!(event.source, "ebpf");
        assert_eq!(event.kind, "shell.command_exec");
        assert!(event.summary.contains("curl"));
        assert_eq!(event.details["pid"], 1234);
    }

    #[test]
    fn connect_event_high_severity_for_reverse_shell_ports() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let event = connect_to_event(5678, 1000, "nc", ip, 4444, "test-host");
        assert_eq!(event.severity, Severity::High);

        let event_normal = connect_to_event(5678, 1000, "curl", ip, 443, "test-host");
        assert_eq!(event_normal.severity, Severity::Info);
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
}
