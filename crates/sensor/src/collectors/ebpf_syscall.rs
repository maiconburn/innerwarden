//! eBPF syscall collector — reads events from kernel-space ring buffer.
//!
//! This collector replaces (or complements) the audit-based exec_audit collector
//! with zero-latency kernel-level visibility via eBPF tracepoints.
//!
//! Requires: Linux kernel 5.8+, CAP_BPF + CAP_PERFMON capabilities.
//!
//! When eBPF is not available (macOS, old kernels, missing caps), this collector
//! gracefully disables itself and the sensor falls back to audit-based collection.

// NOTE: This is the userspace stub. Full implementation requires:
// 1. Build sensor-ebpf crate (eBPF programs)
// 2. Load eBPF programs via Aya
// 3. Read from ring buffer and convert to Event structs
//
// The eBPF programs are compiled separately and embedded in the sensor binary
// via a build script. This file handles the userspace loading and event reading.

#![allow(dead_code)] // Stub — functions will be used when Aya integration is complete

use innerwarden_core::entities::EntityRef;
use innerwarden_core::event::{Event, Severity};
use std::net::Ipv4Addr;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Check if eBPF is available on this system.
pub fn is_ebpf_available() -> bool {
    // Check 1: Linux only
    if cfg!(not(target_os = "linux")) {
        return false;
    }

    // Check 2: Kernel version >= 5.8
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

    // Check 3: BTF available
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        return false;
    }

    true
}

/// Convert an eBPF ExecveEvent to an Inner Warden Event.
fn execve_to_event(pid: u32, uid: u32, ppid: u32, comm: &str, filename: &str, host: &str) -> Event {
    Event {
        ts: chrono::Utc::now(),
        host: host.to_string(),
        source: "ebpf".to_string(),
        kind: "process.exec".to_string(),
        severity: Severity::Info,
        summary: format!("Process execution: {filename} (pid={pid}, uid={uid}, parent={ppid})"),
        details: serde_json::json!({
            "pid": pid,
            "uid": uid,
            "ppid": ppid,
            "comm": comm,
            "filename": filename,
            "argv": [],
        }),
        tags: vec!["ebpf".to_string(), "exec".to_string()],
        entities: vec![],
    }
}

/// Convert an eBPF ConnectEvent to an Inner Warden Event.
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
        kind: "network.connect".to_string(),
        severity: Severity::Info,
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

/// Start the eBPF collector.
///
/// Loads eBPF programs, attaches to tracepoints, and reads events from
/// the ring buffer. Events are sent through the same mpsc channel as
/// all other collectors.
///
/// If eBPF is not available, logs a warning and returns immediately.
pub async fn run(_tx: mpsc::Sender<Event>, _host: String) {
    if !is_ebpf_available() {
        warn!("eBPF not available on this system — falling back to audit-based collection");
        return;
    }

    info!("eBPF collector starting — kernel-level syscall monitoring active");

    // TODO: Full implementation with Aya
    //
    // 1. Load embedded eBPF bytecode:
    //    let mut bpf = Ebpf::load(include_bytes_aligned!("../../sensor-ebpf/target/bpfel-unknown-none/release/innerwarden-ebpf"))?;
    //
    // 2. Attach tracepoints:
    //    let execve: &mut TracePoint = bpf.program_mut("innerwarden_execve").unwrap().try_into()?;
    //    execve.load()?;
    //    execve.attach("syscalls", "sys_enter_execve")?;
    //
    //    let connect: &mut TracePoint = bpf.program_mut("innerwarden_connect").unwrap().try_into()?;
    //    connect.load()?;
    //    connect.attach("syscalls", "sys_enter_connect")?;
    //
    // 3. Read from ring buffer:
    //    let mut ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;
    //    loop {
    //        while let Some(item) = ring_buf.next() {
    //            let kind = u32::from_ne_bytes(item[0..4].try_into().unwrap());
    //            match kind {
    //                1 => { /* ExecveEvent */ }
    //                2 => { /* ConnectEvent */ }
    //                _ => {}
    //            }
    //            tx.send(event).await.ok();
    //        }
    //        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    //    }

    info!("eBPF collector: stub loaded — full implementation pending sensor-ebpf crate build");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execve_event_has_correct_fields() {
        let event = execve_to_event(1234, 0, 1, "bash", "/usr/bin/curl", "test-host");
        assert_eq!(event.source, "ebpf");
        assert_eq!(event.kind, "process.exec");
        assert!(event.summary.contains("curl"));
        assert!(event.summary.contains("1234"));
        assert_eq!(event.details["pid"], 1234);
        assert_eq!(event.details["uid"], 0);
    }

    #[test]
    fn connect_event_has_correct_fields() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let event = connect_to_event(5678, 1000, "nc", ip, 4444, "test-host");
        assert_eq!(event.source, "ebpf");
        assert_eq!(event.kind, "network.connect");
        assert!(event.summary.contains("1.2.3.4:4444"));
        assert!(event.summary.contains("nc"));
        assert_eq!(event.details["dst_port"], 4444);
    }

    #[test]
    fn ebpf_availability_check() {
        // On macOS or CI, eBPF should not be available
        if cfg!(target_os = "macos") {
            assert!(!is_ebpf_available());
        }
        // On Linux, depends on kernel version and BTF
    }
}
