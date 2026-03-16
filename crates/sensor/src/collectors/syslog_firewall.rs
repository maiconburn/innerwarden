/// Syslog firewall DROP collector.
///
/// Tails `/var/log/syslog` or `/var/log/kern.log` and parses iptables/nftables
/// DROP log entries, emitting `network.connection_blocked` events that feed the
/// `port_scan` detector.
///
/// This collector targets servers that log firewall drops to syslog rather than
/// (or in addition to) journald. It understands:
/// - UFW block lines (`[UFW BLOCK]`)
/// - Raw iptables LOG lines (any kernel line containing `SRC=` + `DPT=`)
/// - nftables log lines (same key-value format as iptables)
///
/// All three formats share the same iptables netfilter key-value notation:
/// `SRC=1.2.3.4 DST=10.0.0.1 … PROTO=TCP SPT=12345 DPT=22`
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use chrono::Utc;
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
};
use tokio::sync::mpsc;
use tracing::warn;

pub struct SyslogFirewallCollector {
    path: String,
    host: String,
    start_offset: u64,
}

impl SyslogFirewallCollector {
    pub fn new(path: impl Into<String>, host: impl Into<String>, start_offset: u64) -> Self {
        Self {
            path: path.into(),
            host: host.into(),
            start_offset,
        }
    }

    pub async fn run(self, tx: mpsc::Sender<Event>, shared_offset: Arc<AtomicU64>) -> Result<()> {
        let path = self.path.clone();
        let host = self.host.clone();
        let mut offset = self.start_offset;

        loop {
            let file = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    warn!("syslog_firewall: cannot open {path}: {e:#}");
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            let mut reader = BufReader::new(file);
            if let Err(e) = reader.seek(SeekFrom::Start(offset)) {
                warn!("syslog_firewall: seek failed: {e:#}");
            }

            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break, // EOF — re-open to handle rotation
                    Ok(n) => {
                        offset += n as u64;
                        shared_offset.store(offset, Ordering::Relaxed);

                        let line = line.trim_end();
                        if line.is_empty() {
                            continue;
                        }

                        if let Some(entry) = parse_firewall_line(line) {
                            let event = build_event(entry, &host);
                            if tx.send(event).await.is_err() {
                                return Ok(());
                            }
                        }
                    }
                    Err(e) => {
                        warn!("syslog_firewall: read error: {e:#}");
                        break;
                    }
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

pub(crate) struct FirewallDrop {
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: String,
    pub in_iface: String,
}

/// Parse one syslog line containing an iptables/nftables DROP entry.
///
/// Recognised formats:
/// ```text
/// Jan 15 12:34:56 host kernel: [xxx] [UFW BLOCK] IN=eth0 ... SRC=1.2.3.4 DST=10.0.0.1 ... PROTO=TCP SPT=1234 DPT=22 ...
/// Jan 15 12:34:56 host kernel: [xxx] DROP IN=eth0 ... SRC=1.2.3.4 DST=10.0.0.1 ... PROTO=TCP SPT=1234 DPT=80 ...
/// ```
pub(crate) fn parse_firewall_line(line: &str) -> Option<FirewallDrop> {
    // Must be a kernel message
    if !line.contains("kernel:") {
        return None;
    }

    // Must look like a netfilter log line (has both SRC= and either DPT= or PROTO=ICMP)
    if !line.contains("SRC=") {
        return None;
    }

    let src_ip = extract_field(line, "SRC=")?.to_string();
    let dst_ip = extract_field(line, "DST=").unwrap_or("-").to_string();
    let proto = extract_field(line, "PROTO=").unwrap_or("TCP").to_string();
    let in_iface = extract_field(line, "IN=").unwrap_or("").to_string();

    // DPT= is absent for ICMP — skip those (no port to track for port-scan detection)
    let dst_port: u16 = extract_field(line, "DPT=")?.parse().ok()?;

    // Basic sanity: SRC must look like an IP (contains dots or colons for IPv6)
    if !src_ip.contains('.') && !src_ip.contains(':') {
        return None;
    }

    Some(FirewallDrop {
        src_ip,
        dst_ip,
        dst_port,
        proto,
        in_iface,
    })
}

/// Extract the value of a `KEY=VALUE` pair from a syslog line.
/// Value ends at the next whitespace (or end of string).
fn extract_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let start = line.find(key)? + key.len();
    let rest = &line[start..];
    let end = rest.find(' ').unwrap_or(rest.len());
    let value = &rest[..end];
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn build_event(drop: FirewallDrop, host: &str) -> Event {
    Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "syslog_firewall".to_string(),
        kind: "network.connection_blocked".to_string(),
        severity: Severity::Low,
        summary: format!(
            "Firewall DROP: {} → {}:{}",
            drop.src_ip, drop.dst_ip, drop.dst_port
        ),
        details: serde_json::json!({
            "src_ip":   drop.src_ip,
            "dst_ip":   drop.dst_ip,
            "dst_port": drop.dst_port,
            "proto":    drop.proto,
            "in_iface": drop.in_iface,
        }),
        tags: vec![
            "network".to_string(),
            "firewall".to_string(),
            "drop".to_string(),
        ],
        entities: vec![EntityRef::ip(&drop.src_ip)],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const UFW_LINE: &str = r#"Jan 15 12:34:56 web-01 kernel: [12345.678] [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:ab:cd:ef:00:0d:3a:12:34:56:08:00 SRC=203.0.113.10 DST=10.0.0.5 LEN=44 TOS=0x00 PREC=0x00 TTL=250 ID=54321 PROTO=TCP SPT=49876 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0"#;

    const IPTABLES_LINE: &str = r#"Jan 15 12:34:57 web-01 kernel: [12345.789] DROP IN=eth0 OUT= MAC=... SRC=198.51.100.5 DST=10.0.0.5 LEN=40 TOS=0x00 PREC=0x00 TTL=238 ID=9876 PROTO=TCP SPT=12345 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0"#;

    const NFTABLES_LINE: &str = r#"Jan 15 12:34:58 web-01 kernel: [12346.000] nft DROP: IN=eth0 OUT= MAC=... SRC=192.0.2.100 DST=10.0.0.5 LEN=48 TOS=0x00 PREC=0x00 TTL=128 PROTO=TCP SPT=54321 DPT=443 WINDOW=8192"#;

    const SSH_AUTH_LINE: &str =
        "Jan 15 12:34:56 web-01 sshd[1234]: Failed password for root from 1.2.3.4 port 54321 ssh2";

    const ICMP_LINE: &str = r#"Jan 15 12:34:56 web-01 kernel: [12345.678] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.10 DST=10.0.0.5 LEN=28 PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=1"#;

    #[test]
    fn parses_ufw_block_line() {
        let drop = parse_firewall_line(UFW_LINE).expect("should parse UFW line");
        assert_eq!(drop.src_ip, "203.0.113.10");
        assert_eq!(drop.dst_ip, "10.0.0.5");
        assert_eq!(drop.dst_port, 22);
        assert_eq!(drop.proto, "TCP");
        assert_eq!(drop.in_iface, "eth0");
    }

    #[test]
    fn parses_iptables_drop_line() {
        let drop = parse_firewall_line(IPTABLES_LINE).expect("should parse iptables line");
        assert_eq!(drop.src_ip, "198.51.100.5");
        assert_eq!(drop.dst_port, 80);
        assert_eq!(drop.proto, "TCP");
    }

    #[test]
    fn parses_nftables_drop_line() {
        let drop = parse_firewall_line(NFTABLES_LINE).expect("should parse nftables line");
        assert_eq!(drop.src_ip, "192.0.2.100");
        assert_eq!(drop.dst_port, 443);
    }

    #[test]
    fn ignores_non_kernel_lines() {
        assert!(parse_firewall_line(SSH_AUTH_LINE).is_none());
    }

    #[test]
    fn ignores_icmp_lines_without_dpt() {
        // ICMP has no DPT= — we skip it (no port concept for port-scan detection)
        assert!(parse_firewall_line(ICMP_LINE).is_none());
    }

    #[test]
    fn ignores_kernel_lines_without_src() {
        let line = "Jan 15 12:00:00 host kernel: [1.0] eth0: renamed from veth1234";
        assert!(parse_firewall_line(line).is_none());
    }

    #[test]
    fn build_event_kind_is_network_connection_blocked() {
        let drop = parse_firewall_line(UFW_LINE).unwrap();
        let ev = build_event(drop, "test-host");
        assert_eq!(ev.kind, "network.connection_blocked");
        assert_eq!(ev.source, "syslog_firewall");
        assert_eq!(ev.severity, Severity::Low);
        assert_eq!(ev.details["src_ip"], "203.0.113.10");
        assert_eq!(ev.details["dst_port"], 22);
    }

    #[test]
    fn event_entity_is_src_ip() {
        use innerwarden_core::entities::EntityType;
        let drop = parse_firewall_line(IPTABLES_LINE).unwrap();
        let ev = build_event(drop, "host");
        assert!(ev
            .entities
            .iter()
            .any(|e| e.r#type == EntityType::Ip && e.value == "198.51.100.5"));
    }

    #[test]
    fn extract_field_returns_none_for_absent_key() {
        assert!(extract_field("SRC=1.2.3.4 PROTO=TCP", "DPT=").is_none());
    }

    #[test]
    fn extract_field_handles_end_of_line() {
        // Value is last token — no trailing space
        assert_eq!(extract_field("SRC=1.2.3.4", "SRC="), Some("1.2.3.4"));
    }
}
