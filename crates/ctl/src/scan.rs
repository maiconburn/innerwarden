//! `innerwarden scan` — system probe + module advisor
//!
//! Scans the local machine, scores each built-in module, and shows a
//! prioritised recommendation list.  After printing the list it drops into
//! an interactive Q&A loop where the user can type a module name (or number)
//! to read its docs.

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;

// ---------------------------------------------------------------------------
// System probes
// ---------------------------------------------------------------------------

/// Results of probing the local machine.
#[derive(Default, Debug)]
#[allow(dead_code)]
pub struct SystemProbes {
    pub has_sshd: bool,
    pub has_docker: bool,
    pub has_nginx: bool,
    pub has_fail2ban: bool,
    pub has_falco: bool,
    pub has_suricata: bool,
    pub has_osquery: bool,
    pub has_wazuh: bool,
    pub has_ufw: bool,
    pub has_iptables: bool,
    pub has_nftables: bool,
    pub has_pf: bool,
    pub has_auditd: bool,
    pub has_sudo: bool,
    pub is_macos: bool,
    pub is_linux: bool,
    // log files
    pub has_auth_log: bool,
    pub has_nginx_error_log: bool,
    pub has_nginx_access_log: bool,
    pub has_falco_log: bool,
    pub has_suricata_eve: bool,
    pub has_osquery_log: bool,
    pub has_wazuh_alerts: bool,
    pub has_fail2ban_client: bool,
    pub has_crowdsec: bool,
}

fn probe_binary(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn probe_file(path: &str) -> bool {
    Path::new(path).exists()
}

fn probe_service_linux(name: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn probe_service_macos(name: &str) -> bool {
    // launchctl list | grep <name>
    Command::new("launchctl")
        .arg("list")
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|l| l.contains(name))
        })
        .unwrap_or(false)
}

fn detect_os() -> (bool, bool) {
    let output = Command::new("uname")
        .arg("-s")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    let s = output.trim();
    (s == "Darwin", s == "Linux")
}

fn probe_service(name: &str, is_macos: bool) -> bool {
    if is_macos {
        probe_service_macos(name)
    } else {
        probe_service_linux(name)
    }
}

/// Run all probes and return a populated [`SystemProbes`].
pub fn run_probes() -> SystemProbes {
    let (is_macos, is_linux) = detect_os();

    SystemProbes {
        has_sshd: probe_service("sshd", is_macos) || probe_binary("sshd"),
        has_docker: probe_file("/var/run/docker.sock") || probe_binary("docker"),
        has_nginx: probe_service("nginx", is_macos) || probe_binary("nginx"),
        has_fail2ban: probe_service("fail2ban", is_macos),
        has_falco: probe_service("falco", is_macos) || probe_binary("falco"),
        has_suricata: probe_service("suricata", is_macos) || probe_binary("suricata"),
        has_osquery: probe_service("osqueryd", is_macos) || probe_binary("osqueryi"),
        has_wazuh: probe_service("wazuh-agent", is_macos) || probe_binary("wazuh-agent"),
        has_ufw: probe_binary("ufw"),
        has_iptables: probe_binary("iptables"),
        has_nftables: probe_binary("nft"),
        has_pf: is_macos && probe_binary("pfctl"),
        has_auditd: probe_service("auditd", is_macos) || probe_binary("auditctl"),
        has_sudo: probe_binary("sudo"),
        is_macos,
        is_linux,
        // log files
        has_auth_log: probe_file("/var/log/auth.log"),
        has_nginx_error_log: probe_file("/var/log/nginx/error.log"),
        has_nginx_access_log: probe_file("/var/log/nginx/access.log"),
        has_falco_log: probe_file("/var/log/falco/falco.log"),
        has_suricata_eve: probe_file("/var/log/suricata/eve.json"),
        has_osquery_log: probe_file("/var/log/osquery/osqueryd.results.log"),
        has_wazuh_alerts: probe_file("/var/ossec/logs/alerts/alerts.json"),
        has_fail2ban_client: probe_binary("fail2ban-client"),
        has_crowdsec: probe_binary("cscli") || probe_binary("crowdsec"),
    }
}

/// Print the probe results section.
fn print_probes(p: &SystemProbes) {
    println!("Scanning your system...\n");

    let rows: &[(&str, bool)] = &[
        ("SSH daemon", p.has_sshd),
        ("Docker", p.has_docker),
        ("nginx", p.has_nginx),
        ("fail2ban", p.has_fail2ban),
        ("UFW firewall", p.has_ufw),
        ("iptables", p.has_iptables),
        ("nftables", p.has_nftables),
        ("Packet Filter (pf)", p.has_pf),
        ("auditd", p.has_auditd),
        ("sudo", p.has_sudo),
        ("Falco", p.has_falco),
        ("Suricata", p.has_suricata),
        ("osquery", p.has_osquery),
        ("Wazuh", p.has_wazuh),
        ("CrowdSec", p.has_crowdsec),
    ];

    for (label, found) in rows {
        if *found {
            println!("  {label:<28} running   \u{2713}");
        } else {
            println!("  {label:<28} \u{2500}         not found");
        }
    }
    println!();
}

// ---------------------------------------------------------------------------
// Module recommendation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum FindingSeverity {
    High,
    Medium,
    Low,
}

impl FindingSeverity {
    fn label(&self) -> &'static str {
        match self {
            FindingSeverity::High => "HIGH",
            FindingSeverity::Medium => "MEDIUM",
            FindingSeverity::Low => "LOW",
        }
    }
    pub fn order(&self) -> u8 {
        match self {
            FindingSeverity::High => 0,
            FindingSeverity::Medium => 1,
            FindingSeverity::Low => 2,
        }
    }
}

/// A concrete security finding discovered during the audit phase.
#[derive(Debug, Clone)]
pub struct ScanFinding {
    pub severity: FindingSeverity,
    /// Name of the affected resource (container name, config key, etc.)
    pub resource: String,
    /// One-line title.
    pub title: String,
    /// Explanation of the risk.
    pub detail: String,
    /// True when InnerWarden will monitor/alert on this automatically.
    pub iw_handles: bool,
    /// What the server admin needs to do manually (None if IW fully handles it).
    pub admin_action: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tier {
    Essential,
    Recommended,
    Optional,
    NotAvailable,
}

impl Tier {
    fn label(&self) -> &'static str {
        match self {
            Tier::Essential => "ESSENTIAL",
            Tier::Recommended => "RECOMMENDED",
            Tier::Optional => "OPTIONAL",
            Tier::NotAvailable => "NOT AVAILABLE",
        }
    }
    fn order(&self) -> u8 {
        match self {
            Tier::Essential => 0,
            Tier::Recommended => 1,
            Tier::Optional => 2,
            Tier::NotAvailable => 3,
        }
    }
}

/// Whether a module is fully built into InnerWarden or requires an external tool/service.
#[derive(Debug, Clone, PartialEq)]
pub enum IntegrationKind {
    /// Built into InnerWarden — reads logs/events already present on the host.
    /// Zero external dependencies, zero additional RAM or network cost.
    Native,
    /// Connects to an external tool or service that must be installed, configured,
    /// or registered separately. Adds coverage but increases operational complexity.
    External,
}

impl IntegrationKind {
    fn badge(&self) -> &'static str {
        match self {
            IntegrationKind::Native => "NATIVE  ",
            IntegrationKind::External => "EXTERNAL",
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ModuleRec {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub why: String,
    pub enable_hint: &'static str,
    pub stars: u8,
    pub tier: Tier,
    /// Tool that must be present; if absent the module is NotAvailable.
    pub needs_tool: Option<&'static str>,
    pub docs_path: &'static str,
    pub findings: Vec<ScanFinding>,
    /// Whether this is a native InnerWarden capability or an external integration.
    pub kind: IntegrationKind,
    /// Trade-off / cost explanation shown in the advisor section.
    pub cost_note: &'static str,
}

fn stars(n: u8) -> String {
    let filled = "\u{2605}".repeat(n as usize);
    let empty = "\u{2606}".repeat(5usize.saturating_sub(n as usize));
    format!("{filled}{empty}")
}

// ---------------------------------------------------------------------------
// Security audit probes (fail-silent — never panic, never require root)
// ---------------------------------------------------------------------------

/// Inspect all running Docker containers for security misconfigurations.
/// Requires `docker` CLI in PATH. Fail-silent on any error.
fn audit_docker() -> Vec<ScanFinding> {
    // Get running container IDs
    let ids_out = Command::new("docker").args(["ps", "-q"]).output().ok();
    let ids_out = match ids_out {
        Some(o) if o.status.success() => o,
        _ => return vec![],
    };
    let ids: Vec<String> = String::from_utf8_lossy(&ids_out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if ids.is_empty() {
        return vec![];
    }

    // docker inspect <id1> <id2> ...
    let mut cmd = Command::new("docker");
    cmd.arg("inspect");
    for id in &ids {
        cmd.arg(id);
    }
    let inspect_out = match cmd.output() {
        Ok(o) if o.status.success() => o,
        _ => return vec![],
    };
    let json_str = String::from_utf8_lossy(&inspect_out.stdout);
    let containers: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let arr = match containers.as_array() {
        Some(a) => a,
        None => return vec![],
    };

    let dangerous_caps = [
        "SYS_ADMIN",
        "NET_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "SYS_RAWIO",
    ];

    let mut findings = vec![];

    for container in arr {
        let name = container["Name"]
            .as_str()
            .unwrap_or("unknown")
            .trim_start_matches('/')
            .to_string();
        let host_cfg = &container["HostConfig"];

        // Check --privileged
        if host_cfg["Privileged"].as_bool().unwrap_or(false) {
            findings.push(ScanFinding {
                severity: FindingSeverity::High,
                resource: name.clone(),
                title: "container runs with --privileged".to_string(),
                detail: "A privileged container has unrestricted access to the host kernel. \
                         Any code running inside can mount the host filesystem and become root \
                         on the machine."
                    .to_string(),
                iw_handles: true,
                admin_action: Some(format!(
                    "Remove --privileged from {}. Identify which specific capabilities \
                     it needs and grant only those via --cap-add.",
                    name
                )),
            });
        }

        // Check docker.sock mount
        let binds = host_cfg["Binds"].as_array();
        let mounts = container["Mounts"].as_array();
        let has_sock = binds
            .map(|b| {
                b.iter()
                    .any(|v| v.as_str().unwrap_or("").contains("docker.sock"))
            })
            .unwrap_or(false)
            || mounts
                .map(|m| {
                    m.iter().any(|v| {
                        v["Source"].as_str().unwrap_or("").contains("docker.sock")
                            || v["Destination"]
                                .as_str()
                                .unwrap_or("")
                                .contains("docker.sock")
                    })
                })
                .unwrap_or(false);
        if has_sock {
            findings.push(ScanFinding {
                severity: FindingSeverity::High,
                resource: name.clone(),
                title: "docker.sock mounted inside container".to_string(),
                detail: "Mounting the Docker socket gives the container full control over the \
                         Docker daemon — it can create new privileged containers, stop others, \
                         and access any volume on the host. This is a common container escape \
                         vector."
                    .to_string(),
                iw_handles: true,
                admin_action: Some(format!(
                    "{} needs docker.sock to function (e.g. Portainer, Watchtower). \
                     Ensure it is not internet-exposed and requires strong authentication. \
                     Consider scoping access with a Docker socket proxy \
                     (github.com/Tecnativa/docker-socket-proxy).",
                    name
                )),
            });
        }

        // Check dangerous caps
        let cap_add = host_cfg["CapAdd"].as_array();
        if let Some(caps) = cap_add {
            for cap in caps {
                let cap_str = cap.as_str().unwrap_or("");
                if dangerous_caps.contains(&cap_str) {
                    findings.push(ScanFinding {
                        severity: FindingSeverity::Medium,
                        resource: name.clone(),
                        title: format!("dangerous capability: {cap_str}"),
                        detail: format!(
                            "{} has {cap_str} added. This capability can be abused to \
                             interfere with the host kernel or other processes.",
                            name
                        ),
                        iw_handles: true,
                        admin_action: Some(format!(
                            "Audit why {} needs {cap_str}. If not strictly required, \
                             remove it from the container definition.",
                            name
                        )),
                    });
                }
            }
        }
    }

    findings
}

/// Parse SSH config text (from `sshd -T` output or sshd_config file) and return findings.
/// Extracted as a separate function so tests can call it directly.
pub(crate) fn parse_ssh_config(config: &str) -> Vec<ScanFinding> {
    let lower = config.to_lowercase();
    let active_lines: Vec<&str> = lower
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect();

    let mut findings = vec![];

    // PasswordAuthentication
    let password_auth_on = active_lines.iter().any(|l| {
        let l = l.trim();
        l.starts_with("passwordauthentication") && l.contains("yes")
    });
    if password_auth_on {
        findings.push(ScanFinding {
            severity: FindingSeverity::Medium,
            resource: "sshd".to_string(),
            title: "SSH password authentication is enabled".to_string(),
            detail: "Your SSH server accepts password logins. InnerWarden already blocks \
                     brute-force attempts, but disabling password auth eliminates the attack \
                     surface entirely — only key-based logins work."
                .to_string(),
            iw_handles: false,
            admin_action: Some(
                "Edit /etc/ssh/sshd_config and set:\n  \
                 PasswordAuthentication no\n\
                 Then reload: sudo systemctl reload ssh"
                    .to_string(),
            ),
        });
    }

    // PermitRootLogin
    let root_login_on = active_lines.iter().any(|l| {
        let l = l.trim();
        l.starts_with("permitrootlogin") && (l.contains(" yes") || l.ends_with("yes"))
    });
    if root_login_on {
        findings.push(ScanFinding {
            severity: FindingSeverity::High,
            resource: "sshd".to_string(),
            title: "SSH root login permitted".to_string(),
            detail: "Direct root SSH login is enabled. A successful brute-force against \
                     the root account gives the attacker immediate full control with no \
                     further escalation needed."
                .to_string(),
            iw_handles: false,
            admin_action: Some(
                "Edit /etc/ssh/sshd_config and set:\n  \
                 PermitRootLogin no\n\
                 Then reload: sudo systemctl reload ssh"
                    .to_string(),
            ),
        });
    }

    // X11Forwarding yes
    let x11_on = active_lines.iter().any(|l| {
        let l = l.trim();
        l.starts_with("x11forwarding") && l.contains("yes")
    });
    if x11_on {
        findings.push(ScanFinding {
            severity: FindingSeverity::Low,
            resource: "sshd".to_string(),
            title: "X11 forwarding enabled".to_string(),
            detail: "X11 forwarding tunnels graphical display sessions over SSH. Unless you \
                     actively use remote GUI applications, this is unnecessary attack surface."
                .to_string(),
            iw_handles: false,
            admin_action: Some(
                "In /etc/ssh/sshd_config set: X11Forwarding no\nThen: sudo systemctl reload ssh"
                    .to_string(),
            ),
        });
    }

    // MaxAuthTries — default 6 if not set; emit if > 4
    let max_auth_tries: u32 = active_lines
        .iter()
        .find_map(|l| {
            let l = l.trim();
            if l.starts_with("maxauthtries") {
                l.split_whitespace().nth(1).and_then(|v| v.parse().ok())
            } else {
                None
            }
        })
        .unwrap_or(6);
    if max_auth_tries > 4 {
        findings.push(ScanFinding {
            severity: FindingSeverity::Low,
            resource: "sshd".to_string(),
            title: "SSH allows many authentication attempts per connection".to_string(),
            detail: format!(
                "MaxAuthTries is currently {} (default is 6). This means an attacker gets \
                 {} tries per TCP connection before being disconnected. InnerWarden already \
                 detects and blocks brute-force, but lowering this adds another layer.",
                max_auth_tries, max_auth_tries
            ),
            iw_handles: true,
            admin_action: Some(
                "In /etc/ssh/sshd_config set: MaxAuthTries 3\nThen: sudo systemctl reload ssh"
                    .to_string(),
            ),
        });
    }

    // AllowTcpForwarding — emit unless explicitly set to "no"
    let tcp_fwd_disabled = active_lines.iter().any(|l| {
        let l = l.trim();
        l.starts_with("allowtcpforwarding") && l.contains("no")
    });
    if !tcp_fwd_disabled {
        findings.push(ScanFinding {
            severity: FindingSeverity::Low,
            resource: "sshd".to_string(),
            title: "TCP forwarding not explicitly disabled".to_string(),
            detail: "SSH TCP forwarding lets users tunnel arbitrary connections through your SSH \
                     server. If your users don't need to forward ports, disabling it reduces \
                     your exposure."
                .to_string(),
            iw_handles: false,
            admin_action: Some(
                "In /etc/ssh/sshd_config add: AllowTcpForwarding no\n\
                 Then: sudo systemctl reload ssh"
                    .to_string(),
            ),
        });
    }

    findings
}

/// Audit SSH daemon configuration for common misconfigurations.
/// Tries `sshd -T` first (requires sshd in PATH), falls back to reading
/// /etc/ssh/sshd_config directly. Fail-silent.
fn audit_ssh() -> Vec<ScanFinding> {
    // Try sshd -T for effective config
    let effective = Command::new("sshd")
        .args(["-T"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());

    // Fallback: read sshd_config file
    let from_file = if effective.is_none() {
        std::fs::read_to_string("/etc/ssh/sshd_config").ok()
    } else {
        None
    };

    let config = match effective.or(from_file) {
        Some(c) => c,
        None => return vec![],
    };

    parse_ssh_config(&config)
}

/// Read all nginx config files under /etc/nginx/ and return their concatenated content.
/// Fail-silent on any I/O error.
fn read_nginx_configs() -> String {
    let mut content = String::new();

    // Main config
    if let Ok(s) = std::fs::read_to_string("/etc/nginx/nginx.conf") {
        content.push_str(&s);
    }

    // conf.d/*.conf
    if let Ok(entries) = std::fs::read_dir("/etc/nginx/conf.d") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("conf") {
                if let Ok(s) = std::fs::read_to_string(&path) {
                    content.push_str(&s);
                }
            }
        }
    }

    // sites-enabled/*
    if let Ok(entries) = std::fs::read_dir("/etc/nginx/sites-enabled") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(s) = std::fs::read_to_string(&path) {
                    content.push_str(&s);
                }
            }
        }
    }

    content
}

/// Audit nginx configuration for common security misconfigurations. Fail-silent.
fn audit_nginx() -> Vec<ScanFinding> {
    let config = read_nginx_configs();
    if config.is_empty() {
        return vec![];
    }

    let mut findings = vec![];

    // server_tokens — emit if "server_tokens off" is NOT found anywhere
    if !config.contains("server_tokens off") {
        findings.push(ScanFinding {
            severity: FindingSeverity::Low,
            resource: "nginx".to_string(),
            title: "nginx version number exposed in HTTP headers".to_string(),
            detail: "By default nginx includes its version number in Server: response headers and \
                     error pages. This helps attackers identify which nginx CVEs might apply to \
                     your server."
                .to_string(),
            iw_handles: false,
            admin_action: Some(
                "In /etc/nginx/nginx.conf inside the http { } block, add:\n  server_tokens off;\n\
                 Then: sudo nginx -t && sudo systemctl reload nginx"
                    .to_string(),
            ),
        });
    }

    // No SSL/HTTPS — emit if ssl_certificate directive is NOT found anywhere
    if !config.contains("ssl_certificate") {
        findings.push(ScanFinding {
            severity: FindingSeverity::Medium,
            resource: "nginx".to_string(),
            title: "No HTTPS/SSL configured in nginx".to_string(),
            detail: "Your nginx server is serving traffic over HTTP without encryption. \
                     Credentials, session cookies, and data transmitted between your users and \
                     the server are visible to anyone on the network path."
                .to_string(),
            iw_handles: false,
            admin_action: Some(
                "Use Let's Encrypt for free SSL:\n\
                 \x20 sudo apt install certbot python3-certbot-nginx\n\
                 \x20 sudo certbot --nginx\n\
                 Certbot will automatically configure HTTPS and set up renewal."
                    .to_string(),
            ),
        });
    }

    // No rate limiting — emit if limit_req_zone is NOT found anywhere
    if !config.contains("limit_req_zone") {
        findings.push(ScanFinding {
            severity: FindingSeverity::Low,
            resource: "nginx".to_string(),
            title: "nginx has no rate limiting configured".to_string(),
            detail: "Without rate limiting, a single IP can send unlimited requests to any \
                     endpoint. InnerWarden detects and blocks abusive patterns, but native nginx \
                     rate limiting stops them before they reach your application."
                .to_string(),
            iw_handles: true,
            admin_action: Some(
                "In /etc/nginx/nginx.conf inside http { }, add:\n\
                 \x20 limit_req_zone $binary_remote_addr zone=general:10m rate=30r/m;\n\
                 Then in your server blocks, add to sensitive locations:\n\
                 \x20 limit_req zone=general burst=10 nodelay;"
                    .to_string(),
            ),
        });
    }

    findings
}

/// Audit fail2ban configuration for common security gaps. Fail-silent.
fn audit_fail2ban() -> Vec<ScanFinding> {
    let mut findings = vec![];

    // Check if sshd jail is active
    let status_out = Command::new("fail2ban-client")
        .arg("status")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();

    let sshd_jail_active = status_out
        .lines()
        .any(|l| l.contains("sshd") || l.contains("ssh"));

    if !sshd_jail_active {
        findings.push(ScanFinding {
            severity: FindingSeverity::Medium,
            resource: "fail2ban".to_string(),
            title: "fail2ban SSH jail not enabled".to_string(),
            detail: "fail2ban is running but the SSH jail is not active. The sshd jail \
                     automatically bans IPs after repeated failed SSH logins using fail2ban's \
                     own rules, complementing InnerWarden's detection."
                .to_string(),
            iw_handles: true,
            admin_action: Some(
                "Enable the sshd jail:\n\
                 \x20 sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local\n\
                 \x20 Edit /etc/fail2ban/jail.local and set [sshd] enabled = true\n\
                 \x20 sudo systemctl restart fail2ban"
                    .to_string(),
            ),
        });
    } else {
        // sshd jail exists — check bantime
        let bantime_out = Command::new("fail2ban-client")
            .args(["get", "sshd", "bantime"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();

        // Parse bantime value — may be a plain number or have extra text
        let bantime_secs: i64 = bantime_out
            .split_whitespace()
            .find_map(|tok| tok.parse().ok())
            .unwrap_or(0);

        if bantime_secs > 0 && bantime_secs < 3600 {
            findings.push(ScanFinding {
                severity: FindingSeverity::Low,
                resource: "fail2ban".to_string(),
                title: "fail2ban ban duration is less than 1 hour".to_string(),
                detail: format!(
                    "The current ban duration is {} seconds ({} minutes). Attackers often retry \
                     from the same IP after a short wait. A longer ban makes your server less \
                     worth targeting.",
                    bantime_secs,
                    bantime_secs / 60
                ),
                iw_handles: false,
                admin_action: Some(
                    "In /etc/fail2ban/jail.local under [sshd], set:\n\
                     \x20 bantime = 86400\n\
                     (24 hours). Or use bantime.increment = true for progressive bans.\n\
                     Then: sudo systemctl restart fail2ban"
                        .to_string(),
                ),
            });
        }
    }

    findings
}

/// Audit UFW firewall configuration for common misconfigurations. Fail-silent.
fn audit_ufw() -> Vec<ScanFinding> {
    let mut findings = vec![];

    let status_out = Command::new("ufw")
        .arg("status")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();

    if status_out.is_empty() {
        return vec![];
    }

    let ufw_active = status_out.contains("Status: active");

    if !ufw_active {
        findings.push(ScanFinding {
            severity: FindingSeverity::High,
            resource: "ufw".to_string(),
            title: "UFW firewall is installed but not active".to_string(),
            detail: "UFW is installed but not running. Your server has no active firewall, \
                     meaning all ports are accessible from the internet unless blocked at the \
                     network level."
                .to_string(),
            iw_handles: false,
            admin_action: Some(
                "Enable UFW:\n\
                 \x20 sudo ufw default deny incoming\n\
                 \x20 sudo ufw default allow outgoing\n\
                 \x20 sudo ufw allow ssh\n\
                 \x20 sudo ufw allow 80/tcp\n\
                 \x20 sudo ufw allow 443/tcp\n\
                 \x20 sudo ufw enable"
                    .to_string(),
            ),
        });
    } else {
        // UFW is active — check if outgoing is all-allowed (default allow outgoing)
        let all_outgoing_allowed = status_out.contains("Default: allow (outgoing)");
        if all_outgoing_allowed {
            findings.push(ScanFinding {
                severity: FindingSeverity::Low,
                resource: "ufw".to_string(),
                title: "All outbound connections are allowed".to_string(),
                detail: "Your firewall allows all outbound traffic. If malware or a compromised \
                         process runs on this server, it can freely connect to command-and-control \
                         servers, exfiltrate data, or scan other hosts. Restricting outbound \
                         traffic to only what your applications need is a strong defense-in-depth \
                         measure."
                    .to_string(),
                iw_handles: false,
                admin_action: Some(
                    "Audit which outbound connections your services actually need.\n\
                     For a web server, typical allowlist:\n\
                     \x20 sudo ufw default deny outgoing\n\
                     \x20 sudo ufw allow out 80/tcp\n\
                     \x20 sudo ufw allow out 443/tcp\n\
                     \x20 sudo ufw allow out 53/udp\n\
                     \x20 sudo ufw allow out 25/tcp  # if sending email\n\
                     This is advanced — only apply if you understand your app's network needs."
                        .to_string(),
                ),
            });
        }
    }

    findings
}

/// Audit general system-level security posture. Always runs. Fail-silent.
pub(crate) fn audit_system() -> Vec<ScanFinding> {
    let mut findings = vec![];

    // Automatic security updates
    let auto_upgrade_configured = {
        let f1 = std::fs::read_to_string("/etc/apt/apt.conf.d/20auto-upgrades")
            .unwrap_or_default()
            .contains("APT::Periodic::Unattended-Upgrade \"1\"");
        let f2 = std::fs::metadata("/etc/apt/apt.conf.d/50unattended-upgrades").is_ok();
        f1 && f2
    };
    if !auto_upgrade_configured {
        findings.push(ScanFinding {
            severity: FindingSeverity::Medium,
            resource: "system".to_string(),
            title: "Automatic security updates are not configured".to_string(),
            detail: "Without automatic updates, security patches must be applied manually. Most \
                     server compromises exploit known vulnerabilities that have patches available \
                     — often for weeks or months before the attack."
                .to_string(),
            iw_handles: false,
            admin_action: Some(
                "Enable automatic security updates:\n\
                 \x20 sudo apt install unattended-upgrades\n\
                 \x20 sudo dpkg-reconfigure --priority=low unattended-upgrades\n\
                 This installs security patches automatically without reboots."
                    .to_string(),
            ),
        });
    }

    // Services listening on 0.0.0.0 for dangerous ports
    let ss_out = Command::new("ss")
        .args(["-tlnp"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();

    if !ss_out.is_empty() {
        let dangerous_ports: &[(u16, &str)] = &[
            (3306, "MySQL"),
            (5432, "PostgreSQL"),
            (6379, "Redis"),
            (27017, "MongoDB"),
            (9200, "Elasticsearch"),
            (9300, "Elasticsearch cluster"),
            (5984, "CouchDB"),
            (11211, "Memcached"),
            (8080, "HTTP alternate"),
        ];

        for (port, service_name) in dangerous_ports {
            let needle = format!("0.0.0.0:{}", port);
            if ss_out.lines().any(|l| l.contains(&needle)) {
                findings.push(ScanFinding {
                    severity: FindingSeverity::Medium,
                    resource: format!("0.0.0.0:{}", port),
                    title: format!(
                        "Port {} ({}) listening on all interfaces (0.0.0.0)",
                        port, service_name
                    ),
                    detail: format!(
                        "A service on port {} ({}) is accessible from any IP address. If this is \
                         a database or internal service, it should only listen on localhost \
                         (127.0.0.1) or a private network interface.",
                        port, service_name
                    ),
                    iw_handles: false,
                    admin_action: Some(format!(
                        "Configure the service on port {} to bind to 127.0.0.1 instead of \
                         0.0.0.0.\nFor most services, look for a 'bind' or 'listen' directive in \
                         the service config.\nAlternatively, block it at the firewall:\n\
                         \x20 sudo ufw deny {}/tcp",
                        port, port
                    )),
                });
            }
        }
    }

    findings
}

/// Score every module against the probes and return sorted recommendations.
pub fn score_modules(p: &SystemProbes) -> Vec<ModuleRec> {
    let mut recs: Vec<ModuleRec> = vec![
        // ssh-protection
        {
            let ssh_findings = if p.has_sshd || p.has_auth_log {
                audit_ssh()
            } else {
                vec![]
            };
            let (tier, why, s) = if p.has_sshd || p.has_auth_log {
                (
                    Tier::Essential,
                    "sshd running. Automatically detects and blocks brute-force attacks."
                        .to_string(),
                    5,
                )
            } else {
                (
                    Tier::Optional,
                    "SSH daemon not detected. Enable if you run sshd.".to_string(),
                    2,
                )
            };
            ModuleRec {
                id: "ssh-protection",
                name: "SSH Brute-Force + Credential Stuffing",
                description: "Detects and blocks SSH brute-force and credential stuffing attacks.",
                why,
                enable_hint: "innerwarden enable block-ip",
                stars: s,
                tier,
                needs_tool: None,
                docs_path: "ssh-protection/docs/README.md",
                findings: ssh_findings,
                kind: IntegrationKind::Native,
                cost_note: "Zero cost. Reads auth.log/journald already present on your server. No extra RAM or network.",
            }
        },
        // network-defense
        {
            let has_fw = p.has_ufw || p.has_iptables || p.has_nftables;
            let ufw_findings = if p.has_ufw { audit_ufw() } else { vec![] };
            let (tier, why, s) = if has_fw && p.is_linux {
                (
                    Tier::Essential,
                    "Firewall detected. Tracks port scans and routes blocks through InnerWarden."
                        .to_string(),
                    4,
                )
            } else {
                (
                    Tier::Optional,
                    "No Linux firewall detected. Enable once you have ufw/iptables/nftables."
                        .to_string(),
                    2,
                )
            };
            ModuleRec {
                id: "network-defense",
                name: "Network Port-Scan Defense",
                description: "Detects port scans and blocks attacker IPs via firewall.",
                why,
                enable_hint: "innerwarden module install network-defense",
                stars: s,
                tier,
                needs_tool: None,
                docs_path: "network-defense/docs/README.md",
                findings: ufw_findings,
                kind: IntegrationKind::Native,
                cost_note: "Zero cost. Reads firewall logs already written by ufw/iptables/nftables.",
            }
        },
        // sudo-protection
        {
            let (tier, why, s) = if p.has_sudo {
                (
                    Tier::Recommended,
                    "sudo is present. Detects privilege-escalation abuse and suspends users."
                        .to_string(),
                    3,
                )
            } else {
                (
                    Tier::Optional,
                    "sudo not detected on this machine.".to_string(),
                    1,
                )
            };
            ModuleRec {
                id: "sudo-protection",
                name: "Sudo Abuse Detection",
                description: "Detects suspicious sudo bursts and temporarily suspends users.",
                why,
                enable_hint: "innerwarden enable sudo-protection",
                stars: s,
                tier,
                needs_tool: None,
                docs_path: "sudo-protection/docs/README.md",
                findings: vec![],
                kind: IntegrationKind::Native,
                cost_note: "Zero cost. Reads journald/auth.log already present on your server.",
            }
        },
        // file-integrity
        ModuleRec {
            id: "file-integrity",
            name: "File Integrity Monitor",
            description: "SHA-256 polling of critical files; alerts on unexpected changes.",
            why: "Monitors critical files (sshd_config, sudoers, etc.) for tampering.".to_string(),
            enable_hint: "innerwarden module install file-integrity",
            stars: 3,
            tier: Tier::Recommended,
            needs_tool: None,
            docs_path: "file-integrity/docs/README.md",
            findings: vec![],
            kind: IntegrationKind::Native,
            cost_note: "Zero cost. SHA-256 polling — minimal CPU every 60s, no external dependencies.",
        },
        // container-security
        {
            let docker_findings = if p.has_docker { audit_docker() } else { vec![] };
            let (tier, why, s, skip) = if p.has_docker {
                let n = docker_findings.len();
                let finding_summary = if n == 0 {
                    "No privilege escalation issues found in running containers.".to_string()
                } else {
                    format!(
                        "{n} security issue{} found — see findings below.",
                        if n == 1 { "" } else { "s" }
                    )
                };
                (
                    Tier::Essential,
                    format!("Docker detected. Monitors privileged containers, docker.sock mounts, dangerous caps. {finding_summary}"),
                    4,
                    false,
                )
            } else {
                (Tier::NotAvailable, "Docker not found.".to_string(), 1, true)
            };
            ModuleRec {
                id: "container-security",
                name: "Docker Lifecycle Events",
                description: "Tracks Docker container events; alerts on privileged/OOM containers.",
                why,
                enable_hint: "innerwarden enable container-security",
                stars: s,
                tier,
                needs_tool: if skip { Some("Docker") } else { None },
                docs_path: "container-security/docs/README.md",
                findings: docker_findings,
                kind: IntegrationKind::Native,
                cost_note: "Zero cost. Reads Docker Events API — Docker must already be running.",
            }
        },
        // search-protection (owns the nginx audit findings — nginx-error-monitor skips to avoid dups)
        {
            let nginx_findings_search = if p.has_nginx { audit_nginx() } else { vec![] };
            let (tier, why, s) = if p.has_nginx_access_log {
                (
                    Tier::Recommended,
                    "nginx access log found. Detects abusive automated crawlers on expensive routes.".to_string(),
                    3,
                )
            } else {
                (
                    Tier::NotAvailable,
                    "nginx access log not found.".to_string(),
                    1,
                )
            };
            ModuleRec {
                id: "search-protection",
                name: "nginx Search Abuse Detection",
                description:
                    "Detects automated high-cost scraping via nginx logs and rate-limits abusers.",
                why,
                enable_hint: "innerwarden module install search-protection",
                stars: s,
                tier,
                needs_tool: if p.has_nginx_access_log {
                    None
                } else {
                    Some("nginx")
                },
                docs_path: "search-protection/docs/README.md",
                findings: nginx_findings_search,
                kind: IntegrationKind::Native,
                cost_note: "Zero cost. Reads nginx access.log already written by nginx.",
            }
        },
        // nginx-error-monitor (no nginx audit here — findings already shown under search-protection)
        {
            let nginx_findings_error: Vec<ScanFinding> = vec![];
            let (tier, why, s) = if p.has_nginx_error_log {
                (
                    Tier::Recommended,
                    "nginx error log found. Surfaces 4xx/5xx spikes and server errors.".to_string(),
                    3,
                )
            } else {
                (
                    Tier::NotAvailable,
                    "nginx error log not found.".to_string(),
                    1,
                )
            };
            ModuleRec {
                id: "nginx-error-monitor",
                name: "nginx Error Monitor",
                description: "Alerts on sustained nginx error spikes (4xx/5xx).",
                why,
                enable_hint: "innerwarden module install nginx-error-monitor",
                stars: s,
                tier,
                needs_tool: if p.has_nginx_error_log {
                    None
                } else {
                    Some("nginx")
                },
                docs_path: "nginx-error-monitor/docs/README.md",
                findings: nginx_findings_error,
                kind: IntegrationKind::Native,
                cost_note: "Zero cost. Reads nginx error.log already written by nginx.",
            }
        },
        // execution-guard
        {
            let (tier, why, s) = if p.has_auditd || p.is_linux {
                (
                    Tier::Optional,
                    "auditd detected. AST-based shell command analysis with timeline correlation."
                        .to_string(),
                    2,
                )
            } else {
                (
                    Tier::Optional,
                    "Provides AST-based shell command analysis (requires auditd on Linux)."
                        .to_string(),
                    2,
                )
            };
            ModuleRec {
                id: "execution-guard",
                name: "Shell Execution Guard",
                description:
                    "AST analysis of shell commands; detects download→chmod→execute chains.",
                why,
                enable_hint: "innerwarden enable shell-audit",
                stars: s,
                tier,
                needs_tool: None,
                docs_path: "execution-guard/docs/README.md",
                findings: vec![],
                kind: IntegrationKind::Native,
                cost_note: "Zero external cost, but high privacy impact: every shell command is captured. \
                            Enable only with explicit host-owner consent. \
                            If Falco is active, prefer it for exec monitoring — Falco has lower privacy impact.",
            }
        },
        // fail2ban-integration
        {
            let fb_findings = if p.has_fail2ban && p.has_fail2ban_client {
                audit_fail2ban()
            } else {
                vec![]
            };
            let (tier, why, s, missing) = if p.has_fail2ban_client && p.has_fail2ban {
                (
                    Tier::Essential,
                    "fail2ban is active. Routes its bans through InnerWarden's audit trail."
                        .to_string(),
                    5,
                    false,
                )
            } else if p.has_fail2ban_client {
                (
                    Tier::Recommended,
                    "fail2ban-client found. Install to unify ban decisions in InnerWarden."
                        .to_string(),
                    3,
                    false,
                )
            } else {
                (
                    Tier::NotAvailable,
                    "fail2ban not found.".to_string(),
                    1,
                    true,
                )
            };
            ModuleRec {
                id: "fail2ban-integration",
                name: "fail2ban Integration",
                description: "Unified fail2ban ban decisions into InnerWarden's audit trail.",
                why,
                enable_hint: "innerwarden integrate fail2ban",
                stars: s,
                tier,
                needs_tool: if missing { Some("fail2ban") } else { None },
                docs_path: "fail2ban-integration/docs/README.md",
                findings: fb_findings,
                kind: IntegrationKind::External,
                cost_note: "Free and lightweight (~5MB RAM). Often already installed on servers. \
                            Adds ban deduplication but can overlap with InnerWarden's own block-ip decisions. \
                            Avoid setting AbuseIPDB auto_block_threshold when fail2ban is active to prevent competing auto-blocks.",
            }
        },
        // geoip-enrichment
        ModuleRec {
            id: "geoip-enrichment",
            name: "IP Geolocation Enrichment",
            description: "Adds country/ISP context to AI decisions — free, no API key needed.",
            why: "Free enrichment layer. Adds country/ISP context to every AI decision."
                .to_string(),
            enable_hint: "innerwarden integrate geoip",
            stars: 2,
            tier: Tier::Optional,
            needs_tool: None,
            docs_path: "geoip-enrichment/docs/README.md",
            findings: vec![],
            kind: IntegrationKind::Native,
            cost_note: "Free, no API key. Calls ip-api.com (rate-limited to 45 req/min). \
                        No extra RAM. First easy enrichment to add.",
        },
        // abuseipdb-enrichment
        ModuleRec {
            id: "abuseipdb-enrichment",
            name: "AbuseIPDB Reputation Scoring",
            description:
                "Queries AbuseIPDB for IP reputation; raises AI confidence on known-bad IPs.",
            why:
                "Requires a free API key at abuseipdb.com. Raises AI confidence for known-bad IPs."
                    .to_string(),
            enable_hint: "innerwarden integrate abuseipdb",
            stars: 2,
            tier: Tier::Optional,
            needs_tool: None,
            docs_path: "abuseipdb-enrichment/docs/README.md",
            findings: vec![],
            kind: IntegrationKind::External,
            cost_note: "Free plan: 1,000 req/day (one lookup per incident). \
                        Paid plans start at $50/mo for higher volume. \
                        The auto_block_threshold feature (bypass AI for known-bad IPs) is powerful \
                        but should not be combined with fail2ban auto-banning to avoid double-blocking.",
        },
        // falco-integration
        {
            let (tier, why, s, missing) = if p.has_falco_log {
                (
                    Tier::Essential,
                    "Falco log found. Routes eBPF/syscall alerts into InnerWarden for AI triage."
                        .to_string(),
                    5,
                    false,
                )
            } else {
                (Tier::NotAvailable, "Falco not found.".to_string(), 1, true)
            };
            ModuleRec {
                id: "falco-integration",
                name: "Falco eBPF/Syscall Integration",
                description: "Routes Falco runtime security alerts into InnerWarden for AI triage.",
                why,
                enable_hint: "innerwarden module install falco-integration",
                stars: s,
                tier,
                needs_tool: if missing {
                    Some("Falco (see https://falco.org)")
                } else {
                    None
                },
                docs_path: "falco-integration/docs/README.md",
                findings: vec![],
                kind: IntegrationKind::External,
                cost_note: "Free and open-source. Adds ~50MB RAM (eBPF probe) or ~100MB (kernel module). \
                            Very high value for syscall/container monitoring. \
                            If you enable Falco, disable execution-guard — they overlap on exec detection \
                            and will flood you with duplicate incidents.",
            }
        },
        // suricata-integration
        {
            let (tier, why, s, missing) = if p.has_suricata_eve {
                (
                    Tier::Essential,
                    "Suricata eve.json found. Routes IDS alerts into InnerWarden for AI triage."
                        .to_string(),
                    5,
                    false,
                )
            } else {
                (
                    Tier::NotAvailable,
                    "Suricata not found.".to_string(),
                    1,
                    true,
                )
            };
            ModuleRec {
                id: "suricata-integration",
                name: "Suricata Network IDS Integration",
                description: "Routes Suricata network alerts into InnerWarden for AI triage.",
                why,
                enable_hint: "innerwarden module install suricata-integration",
                stars: s,
                tier,
                needs_tool: if missing {
                    Some("Suricata (see https://suricata.io)")
                } else {
                    None
                },
                docs_path: "suricata-integration/docs/README.md",
                findings: vec![],
                kind: IntegrationKind::External,
                cost_note: "Free and open-source. Adds ~100–200MB RAM. Requires a network tap or span port. \
                            Very high value for network-layer detection (IDS signatures, protocol anomalies). \
                            Suricata's port-scan detection overlaps with InnerWarden's syslog_firewall detector — \
                            you can safely disable syslog_firewall once Suricata is active.",
            }
        },
        // osquery-integration
        {
            let (tier, why, s, missing) = if p.has_osquery_log {
                (
                    Tier::Recommended,
                    "osquery results log found. Surfaces host observability data (ports, users, crons)."
                        .to_string(),
                    3,
                    false,
                )
            } else {
                (
                    Tier::NotAvailable,
                    "osquery not found.".to_string(),
                    1,
                    true,
                )
            };
            ModuleRec {
                id: "osquery-integration",
                name: "osquery Host Observability",
                description: "Ingests osquery differential results for host-level visibility.",
                why,
                enable_hint: "innerwarden module install osquery-integration",
                stars: s,
                tier,
                needs_tool: if missing {
                    Some("osquery (see https://osquery.io)")
                } else {
                    None
                },
                docs_path: "osquery-integration/docs/README.md",
                findings: vec![],
                kind: IntegrationKind::External,
                cost_note: "Free and lightweight (~30MB RAM). Good for host-level queries \
                            (open ports, crontabs, user accounts, listening services). \
                            No incident passthrough — provides context and observability, not automated response.",
            }
        },
        // wazuh-integration
        {
            let (tier, why, s, missing) = if p.has_wazuh_alerts {
                (
                    Tier::Essential,
                    "Wazuh alerts log found. Routes HIDS/FIM alerts into InnerWarden for AI triage."
                        .to_string(),
                    5,
                    false,
                )
            } else {
                (Tier::NotAvailable, "Wazuh not found.".to_string(), 1, true)
            };
            ModuleRec {
                id: "wazuh-integration",
                name: "Wazuh HIDS Integration",
                description: "Routes Wazuh HIDS/FIM compliance alerts into InnerWarden.",
                why,
                enable_hint: "innerwarden module install wazuh-integration",
                stars: s,
                tier,
                needs_tool: if missing {
                    Some("Wazuh (see https://wazuh.com)")
                } else {
                    None
                },
                docs_path: "wazuh-integration/docs/README.md",
                findings: vec![],
                kind: IntegrationKind::External,
                cost_note: "Free (self-hosted) but heavyweight: Wazuh agent adds ~100MB RAM; \
                            the Wazuh manager server requires a separate machine (~2GB RAM). \
                            Best for compliance-driven environments (PCI-DSS, HIPAA). \
                            Note: Wazuh's SSH rules overlap with InnerWarden's ssh-protection — \
                            you may get duplicate SSH brute-force alerts. Consider disabling \
                            Wazuh's sshd rules or InnerWarden's auth_log collector when both are active.",
            }
        },
        // crowdsec-integration
        {
            let (tier, why, s, missing) = if p.has_crowdsec {
                (
                    Tier::Essential,
                    "CrowdSec detected. Routes ban decisions through InnerWarden's audit trail."
                        .to_string(),
                    5,
                    false,
                )
            } else {
                (
                    Tier::NotAvailable,
                    "CrowdSec not found.".to_string(),
                    1,
                    true,
                )
            };
            ModuleRec {
                id: "crowdsec-integration",
                name: "CrowdSec Integration",
                description: "Unifies CrowdSec community ban decisions into InnerWarden.",
                why,
                enable_hint: "innerwarden module install crowdsec-integration",
                stars: s,
                tier,
                needs_tool: if missing {
                    Some("CrowdSec (see https://crowdsec.net)")
                } else {
                    None
                },
                docs_path: "crowdsec-integration/docs/README.md",
                findings: vec![],
                kind: IntegrationKind::External,
                cost_note: "Free (community plan). CrowdSec agent is lightweight (~20MB RAM). \
                            Shares threat intelligence across the community — if an IP attacks \
                            another CrowdSec user, it's pre-blocked for you. \
                            Overlaps with AbuseIPDB enrichment on IP reputation — pick one or use both \
                            with different thresholds.",
            }
        },
        // slack-notify
        ModuleRec {
            id: "slack-notify",
            name: "Slack Notifications",
            description: "Sends High/Critical incident alerts to a Slack channel.",
            why: "Optional: push notifications to Slack for any High/Critical incident."
                .to_string(),
            enable_hint: "innerwarden notify slack",
            stars: 2,
            tier: Tier::Optional,
            needs_tool: None,
            docs_path: "slack-notify/docs/README.md",
            findings: vec![],
            kind: IntegrationKind::External,
            cost_note: "Free (requires a Slack workspace). Adds another notification channel. \
                        Caution: if you already have Telegram enabled, activating Slack doubles \
                        your alert volume — you'll get the same incident on both channels. \
                        Use Slack for team channels, Telegram for personal real-time response.",
        },
        // threat-capture
        ModuleRec {
            id: "threat-capture",
            name: "Threat Capture (Premium)",
            description: "Full-packet capture + attacker honeypot. Premium tier.",
            why: "Premium: captures attacker traffic (tcpdump) and deploys interactive honeypots."
                .to_string(),
            enable_hint: "innerwarden module install threat-capture",
            stars: 2,
            tier: Tier::Optional,
            needs_tool: None,
            docs_path: "threat-capture/docs/README.md",
            findings: vec![],
            kind: IntegrationKind::Native,
            cost_note: "Premium tier. tcpdump capture requires root or CAP_NET_RAW. \
                        Honeypot listener adds ~10MB RAM. Produces forensic .pcap files — \
                        configure forensics_max_total_mb to prevent disk exhaustion.",
        },
    ];

    // Sort: Essential → Recommended → Optional → NotAvailable; within tier by stars desc.
    recs.sort_by(|a, b| {
        a.tier
            .order()
            .cmp(&b.tier.order())
            .then(b.stars.cmp(&a.stars))
    });

    recs
}

// ---------------------------------------------------------------------------
// Output rendering
// ---------------------------------------------------------------------------

fn print_recommendations(recs: &[ModuleRec], system_findings: &[ScanFinding]) {
    println!("Recommended modules for this machine:");
    println!("{}", "\u{2501}".repeat(64));

    let mut current_tier: Option<&Tier> = None;
    let mut idx = 1usize;

    let available: Vec<_> = recs
        .iter()
        .filter(|r| r.tier != Tier::NotAvailable)
        .collect();
    let not_available: Vec<_> = recs
        .iter()
        .filter(|r| r.tier == Tier::NotAvailable)
        .collect();

    for rec in &available {
        if current_tier.as_ref().map(|t| t.order()) != Some(rec.tier.order()) {
            println!("\n  {}", rec.tier.label());
            println!();
            current_tier = Some(&rec.tier);
        }
        println!(
            "  [{idx}] {:<28} {}  {}  [{}]",
            rec.id,
            stars(rec.stars),
            rec.name,
            rec.kind.badge()
        );
        println!("      {}", rec.why);
        println!("      \u{2192} {}", rec.enable_hint);

        // Inline findings
        if !rec.findings.is_empty() {
            println!();
            let mut sorted = rec.findings.clone();
            sorted.sort_by_key(|f| f.severity.order());
            for f in &sorted {
                let icon = match f.severity {
                    FindingSeverity::High => "  \u{26a0}  HIGH  ",
                    FindingSeverity::Medium => "  \u{25b8}  MED   ",
                    FindingSeverity::Low => "  \u{25b8}  LOW   ",
                };
                println!("      {}{} \u{2014} {}", icon, f.resource, f.title);
                if f.iw_handles {
                    println!("             InnerWarden will alert automatically once enabled.");
                }
                if f.admin_action.is_some() {
                    println!("             Admin action required \u{2193}  (see summary below)");
                }
            }
            println!();
        }

        println!();
        idx += 1;
    }

    if !not_available.is_empty() {
        println!("\n  NOT AVAILABLE (install the tool first)\n");
        for rec in &not_available {
            let tool = rec.needs_tool.unwrap_or(rec.id);
            println!("  \u{2500} {:<28}  Requires: {tool}", rec.id);
        }
    }

    // ── System-level findings section ─────────────────────────────────────
    if !system_findings.is_empty() {
        println!();
        println!("{}", "\u{2501}".repeat(64));
        println!("System-level security findings");
        println!("{}", "\u{2501}".repeat(64));
        println!();
        let mut sorted_sys = system_findings.to_vec();
        sorted_sys.sort_by_key(|f| f.severity.order());
        for f in &sorted_sys {
            let icon = match f.severity {
                FindingSeverity::High => "\u{26a0}  HIGH",
                FindingSeverity::Medium => "\u{25b8}  MED ",
                FindingSeverity::Low => "\u{25b8}  LOW ",
            };
            println!("  \u{25b8} {}   {} \u{2014} {}", icon, f.resource, f.title);
            if f.admin_action.is_some() {
                println!("          Admin action required \u{2193} (see summary below)");
            }
        }
        println!();
    }

    // ── Admin actions section ──────────────────────────────────────────────
    let module_admin_findings: Vec<&ScanFinding> = recs
        .iter()
        .flat_map(|r| r.findings.iter())
        .filter(|f| f.admin_action.is_some())
        .collect();
    let system_admin_findings: Vec<&ScanFinding> = system_findings
        .iter()
        .filter(|f| f.admin_action.is_some())
        .collect();

    let mut all_admin: Vec<&ScanFinding> = module_admin_findings;
    all_admin.extend(system_admin_findings);

    if !all_admin.is_empty() {
        println!();
        println!("{}", "\u{2501}".repeat(64));
        println!("Admin actions required");
        println!("These issues need manual intervention \u{2014} InnerWarden cannot fix them.");
        println!("{}", "\u{2501}".repeat(64));
        println!();

        all_admin.sort_by_key(|f| f.severity.order());

        for f in all_admin {
            let badge = match f.severity {
                FindingSeverity::High => "[\u{001b}[31mHIGH\u{001b}[0m]  ",
                FindingSeverity::Medium => "[\u{001b}[33mMED\u{001b}[0m]   ",
                FindingSeverity::Low => "[\u{001b}[36mLOW\u{001b}[0m]   ",
            };
            println!("  {}{} \u{2014} {}", badge, f.resource, f.title);
            println!();
            // Word-wrap detail at 68 chars
            for line in wrap_text(&f.detail, 68) {
                println!("  {}", line);
            }
            println!();
            if let Some(action) = &f.admin_action {
                println!("  How to fix:");
                for line in action.lines() {
                    println!("    {}", line);
                }
            }
            println!();
        }
    }

    println!("{}", "\u{2500}".repeat(72));
    println!("Type a module name or number to learn more, or press Enter / 'q' to exit:");
}

/// Simple word-wrapper: split text into lines of at most `width` chars.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = vec![];
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current.clone());
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

// ---------------------------------------------------------------------------
// Module docs lookup
// ---------------------------------------------------------------------------

fn find_module_readme(module_id: &str, modules_dir: &Path) -> Option<PathBuf> {
    // Try caller-supplied dir first, then dev ./modules/, then installed paths.
    let candidates = [
        modules_dir.join(module_id).join("docs").join("README.md"),
        PathBuf::from("modules")
            .join(module_id)
            .join("docs")
            .join("README.md"),
        PathBuf::from("/usr/local/share/innerwarden/modules")
            .join(module_id)
            .join("docs")
            .join("README.md"),
        PathBuf::from("/etc/innerwarden/modules")
            .join(module_id)
            .join("docs")
            .join("README.md"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

fn show_module_info(rec: &ModuleRec, modules_dir: &Path) {
    println!();
    println!("{}", "\u{2501}".repeat(64));
    println!(
        "  {}   [{}]",
        rec.name,
        rec.kind.badge()
    );
    println!("{}", "\u{2501}".repeat(64));
    println!();
    println!("  {}", rec.description);
    println!();
    println!("  Cost / trade-offs:");
    for line in wrap_text(rec.cost_note, 60) {
        println!("    {line}");
    }
    println!();
    println!("  Enable with:");
    println!("    $ {}", rec.enable_hint);
    println!();

    match find_module_readme(rec.id, modules_dir) {
        Some(readme) => match std::fs::read_to_string(&readme) {
            Ok(content) => {
                println!("{}", "\u{2500}".repeat(64));
                println!("{content}");
            }
            Err(e) => {
                println!("Could not read docs for '{}': {e}", rec.id);
            }
        },
        None => {
            println!("(No detailed README found for '{}' on this machine)", rec.id);
        }
    }
}

// ---------------------------------------------------------------------------
// Integration advisor
// ---------------------------------------------------------------------------

struct ConflictPair {
    module_a: &'static str,
    module_b: &'static str,
    overlap: &'static str,
    recommendation: &'static str,
}

fn detect_conflicts(recs: &[ModuleRec]) -> Vec<ConflictPair> {
    let available: std::collections::HashSet<&str> = recs
        .iter()
        .filter(|r| r.tier != Tier::NotAvailable)
        .map(|r| r.id)
        .collect();

    let mut conflicts = vec![];

    // Falco + execution-guard: both detect suspicious exec
    if available.contains("falco-integration") && available.contains("execution-guard") {
        conflicts.push(ConflictPair {
            module_a: "falco-integration",
            module_b: "execution-guard",
            overlap: "Both detect suspicious shell command execution (Falco via eBPF syscalls, \
                      execution-guard via auditd AST analysis)",
            recommendation: "Use Falco and disable execution-guard. Falco is more comprehensive \
                             and has lower privacy impact. Running both will generate duplicate \
                             exec incidents and can flood your notification channel.",
        });
    }

    // Wazuh + ssh-protection: both detect SSH brute-force
    if available.contains("wazuh-integration") && available.contains("ssh-protection") {
        conflicts.push(ConflictPair {
            module_a: "wazuh-integration",
            module_b: "ssh-protection",
            overlap: "Wazuh's sshd detection rules overlap with InnerWarden's auth_log SSH \
                      brute-force detector — both produce SSH incident alerts",
            recommendation: "Both can coexist but you will get duplicate SSH alerts. Consider \
                             disabling InnerWarden's auth_log collector ([collectors.auth_log] \
                             enabled = false) and letting Wazuh own SSH detection, or disable \
                             Wazuh's sshd jail rules.",
        });
    }

    // Suricata + network-defense (syslog_firewall): both detect port scans
    if available.contains("suricata-integration") && available.contains("network-defense") {
        conflicts.push(ConflictPair {
            module_a: "suricata-integration",
            module_b: "network-defense",
            overlap: "Suricata's port-scan detection overlaps with InnerWarden's syslog_firewall \
                      collector that also feeds port-scan detection",
            recommendation: "Once Suricata is active, disable InnerWarden's syslog_firewall \
                             collector ([collectors.syslog_firewall] enabled = false). Suricata \
                             provides deeper network-layer scanning visibility.",
        });
    }

    // AbuseIPDB auto-block + fail2ban: both auto-block IPs
    if available.contains("abuseipdb-enrichment") && available.contains("fail2ban-integration") {
        conflicts.push(ConflictPair {
            module_a: "abuseipdb-enrichment (auto_block_threshold)",
            module_b: "fail2ban-integration",
            overlap: "Both can automatically block IPs without AI involvement — \
                      AbuseIPDB via auto_block_threshold and fail2ban via its ban rules",
            recommendation: "Set abuseipdb.auto_block_threshold = 0 to disable AbuseIPDB \
                             auto-blocking when fail2ban is active. Use AbuseIPDB only for \
                             AI context enrichment. Having both auto-block can trigger \
                             double notifications and competing audit entries.",
        });
    }

    // Telegram + Slack both active: double notification volume
    if available.contains("slack-notify") {
        // Check if Telegram is likely configured (we can't probe from here, so hint always)
        conflicts.push(ConflictPair {
            module_a: "slack-notify",
            module_b: "Telegram (if configured)",
            overlap: "Both channels send the same High/Critical incident alerts in real time",
            recommendation: "Use Telegram for personal real-time response (supports approval \
                             buttons). Use Slack for team visibility channels. If you are the \
                             only operator, activating both doubles your notification volume \
                             with no benefit.",
        });
    }

    conflicts
}

fn activation_sequence(probes: &SystemProbes) -> Vec<(&'static str, &'static str)> {
    let mut seq: Vec<(&str, &str)> = vec![];

    if probes.has_sshd || probes.has_auth_log {
        seq.push((
            "innerwarden enable block-ip",
            "SSH protection + IP blocking (core, activate first)",
        ));
    }

    seq.push((
        "innerwarden integrate geoip",
        "GeoIP enrichment (free, zero noise, adds country/ISP to AI)",
    ));

    seq.push((
        "innerwarden notify telegram",
        "Push alerts (Telegram is recommended: bidirectional approval, no extra cost)",
    ));

    seq.push((
        "innerwarden integrate abuseipdb",
        "IP reputation scoring (free API key, enriches AI context)",
    ));

    if probes.has_fail2ban_client {
        seq.push((
            "innerwarden integrate fail2ban",
            "Unify fail2ban bans into InnerWarden's audit trail",
        ));
    }

    if probes.has_docker {
        seq.push((
            "innerwarden enable container-security",
            "Docker lifecycle + privilege escalation detection",
        ));
    }

    if probes.has_nginx_access_log || probes.has_nginx_error_log {
        seq.push((
            "innerwarden module install nginx-error-monitor",
            "nginx scanner + error spike detection (if you run a web server)",
        ));
    }

    // External tools only after native layer is stable
    if probes.has_falco_log {
        seq.push((
            "innerwarden module install falco-integration",
            "Falco eBPF/syscall alerts (already installed — high value, route into IW)",
        ));
    }

    if probes.has_suricata_eve {
        seq.push((
            "innerwarden module install suricata-integration",
            "Suricata IDS alerts (already installed — high value, route into IW)",
        ));
    }

    seq
}

fn print_advisor(probes: &SystemProbes, recs: &[ModuleRec]) {
    let conflicts = detect_conflicts(recs);

    println!();
    println!("{}", "\u{2501}".repeat(64));
    println!("Integration advisor");
    println!("{}", "\u{2501}".repeat(64));
    println!();
    println!("  \u{25b6} NATIVE   Built into InnerWarden. Zero external dependencies.");
    println!("           Reads logs already present on your server.");
    println!("  \u{25b6} EXTERNAL Connects to a separate tool or cloud service.");
    println!("           More coverage, more complexity, possible ongoing cost.");
    println!();

    if !conflicts.is_empty() {
        println!("  \u{26a0}  Overlaps / conflicts detected:");
        println!();
        for c in &conflicts {
            println!("  \u{25b8} {} \u{2194} {}", c.module_a, c.module_b);
            for line in wrap_text(c.overlap, 60) {
                println!("    {line}");
            }
            println!("    Fix: {}", c.recommendation);
            println!();
        }
    }

    let seq = activation_sequence(probes);
    if !seq.is_empty() {
        println!("  Recommended activation order (one at a time):");
        println!();
        for (i, (cmd, why)) in seq.iter().enumerate() {
            println!("  {}. {}", i + 1, why);
            println!("     $ {cmd}");
            println!();
        }
    }

    println!("  \u{1f4a1} Tip: activate one module at a time. Watch your notification");
    println!("       channel for 24h before enabling the next. This lets you");
    println!("       tune thresholds before the volume increases.");
    println!();
}

// ---------------------------------------------------------------------------
// Interactive Q&A loop
// ---------------------------------------------------------------------------

fn interactive_loop(recs: &[ModuleRec], modules_dir: &Path) {
    let available: Vec<_> = recs
        .iter()
        .filter(|r| r.tier != Tier::NotAvailable)
        .collect();

    loop {
        print!("> ");
        io::stdout().flush().ok();

        let mut input = String::new();
        if io::stdin().lock().read_line(&mut input).is_err() {
            break;
        }
        let trimmed = input.trim().to_lowercase();

        match trimmed.as_str() {
            "" | "q" | "quit" | "exit" => break,
            other => {
                // Try numeric index first.
                if let Ok(n) = other.parse::<usize>() {
                    if n >= 1 && n <= available.len() {
                        let rec = available[n - 1];
                        show_module_info(rec, modules_dir);
                        continue;
                    }
                }

                // Try module ID match (case-insensitive).
                let all: Vec<_> = recs.iter().collect();
                if let Some(rec) = all.iter().find(|r| r.id == other) {
                    show_module_info(rec, modules_dir);
                    continue;
                }

                println!(
                    "Unknown module '{}'. Type a module name from the list above, or 'q' to exit.",
                    trimmed
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Entry point called from `main.rs`.
pub fn cmd_scan(modules_dir_override: &str) -> Result<()> {
    let modules_dir = if modules_dir_override.is_empty() {
        // Fallback: dev ./modules/ first, then installed location.
        if Path::new("modules").is_dir() {
            PathBuf::from("modules")
        } else {
            PathBuf::from("/usr/local/share/innerwarden/modules")
        }
    } else {
        PathBuf::from(modules_dir_override)
    };

    let probes = run_probes();
    print_probes(&probes);

    let recs = score_modules(&probes);
    let system_findings = audit_system();
    print_recommendations(&recs, &system_findings);
    print_advisor(&probes, &recs);

    interactive_loop(&recs, &modules_dir);

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn probes_all_false() -> SystemProbes {
        SystemProbes::default()
    }

    fn probes_with_sshd() -> SystemProbes {
        SystemProbes {
            has_sshd: true,
            has_auth_log: true,
            has_sudo: true,
            ..Default::default()
        }
    }

    fn probes_with_docker() -> SystemProbes {
        SystemProbes {
            has_docker: true,
            ..Default::default()
        }
    }

    fn probes_with_fail2ban() -> SystemProbes {
        SystemProbes {
            has_fail2ban: true,
            has_fail2ban_client: true,
            ..Default::default()
        }
    }

    fn probes_with_crowdsec() -> SystemProbes {
        SystemProbes {
            has_crowdsec: true,
            ..Default::default()
        }
    }

    #[test]
    fn tier_essential_shown_before_recommended() {
        let p = probes_with_sshd();
        let recs = score_modules(&p);
        // Verify Essential modules come before Recommended which come before Optional.
        let mut last_order: u8 = 0;
        for rec in &recs {
            if rec.tier == Tier::NotAvailable {
                continue;
            }
            assert!(
                rec.tier.order() >= last_order,
                "Tier ordering violated: {:?} after higher tier",
                rec.tier
            );
            last_order = rec.tier.order();
        }
    }

    #[test]
    fn module_not_available_when_tool_missing() {
        let p = probes_all_false();
        let recs = score_modules(&p);
        let container = recs.iter().find(|r| r.id == "container-security").unwrap();
        assert_eq!(container.tier, Tier::NotAvailable);
    }

    #[test]
    fn ssh_protection_essential_when_sshd() {
        let p = probes_with_sshd();
        let recs = score_modules(&p);
        let ssh = recs.iter().find(|r| r.id == "ssh-protection").unwrap();
        assert_eq!(ssh.tier, Tier::Essential);
        assert_eq!(ssh.stars, 5);
    }

    #[test]
    fn fail2ban_essential_when_found() {
        let p = probes_with_fail2ban();
        let recs = score_modules(&p);
        let fb = recs
            .iter()
            .find(|r| r.id == "fail2ban-integration")
            .unwrap();
        assert_eq!(fb.tier, Tier::Essential);
    }

    #[test]
    fn geoip_always_optional() {
        for p in [probes_all_false(), probes_with_sshd(), probes_with_docker()] {
            let recs = score_modules(&p);
            let geoip = recs.iter().find(|r| r.id == "geoip-enrichment").unwrap();
            assert_eq!(
                geoip.tier,
                Tier::Optional,
                "geoip-enrichment must always be Optional"
            );
        }
    }

    #[test]
    fn crowdsec_not_available_when_missing() {
        let p = probes_all_false();
        let recs = score_modules(&p);
        let cs = recs
            .iter()
            .find(|r| r.id == "crowdsec-integration")
            .unwrap();
        assert_eq!(cs.tier, Tier::NotAvailable);
    }

    #[test]
    fn crowdsec_essential_when_found() {
        let p = probes_with_crowdsec();
        let recs = score_modules(&p);
        let cs = recs
            .iter()
            .find(|r| r.id == "crowdsec-integration")
            .unwrap();
        assert_eq!(cs.tier, Tier::Essential);
    }

    #[test]
    fn audit_ssh_detects_password_auth() {
        let config = "passwordauthentication yes\nusedns no\n";
        let findings = parse_ssh_config(config);
        assert!(
            findings
                .iter()
                .any(|f| f.title.to_lowercase().contains("password authentication")),
            "Should detect password authentication finding"
        );
    }

    #[test]
    fn audit_ssh_no_high_medium_on_hardened_config() {
        // A hardened config: key-only, no root login, no x11, tcp fwd disabled, low maxtries
        let config = "passwordauthentication no\npermitroot login no\nx11forwarding no\nallowt cpforwarding no\nmaxauthtries 3\n";
        let findings = parse_ssh_config(config);
        let has_high_or_medium = findings
            .iter()
            .any(|f| f.severity == FindingSeverity::High || f.severity == FindingSeverity::Medium);
        assert!(
            !has_high_or_medium,
            "Hardened SSH config should have no High or Medium findings, got: {:?}",
            findings
                .iter()
                .map(|f| format!("{:?}: {}", f.severity, f.title))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn scan_finding_severity_order() {
        assert!(
            FindingSeverity::High.order() < FindingSeverity::Medium.order(),
            "High should sort before Medium"
        );
        assert!(
            FindingSeverity::Medium.order() < FindingSeverity::Low.order(),
            "Medium should sort before Low"
        );
    }

    #[test]
    fn audit_ssh_detects_root_login() {
        let config = "permitrootlogin yes\n";
        let findings = parse_ssh_config(config);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == FindingSeverity::High && f.title.contains("root login")),
            "Should detect root login as High severity"
        );
    }

    #[test]
    fn audit_ssh_detects_x11_forwarding() {
        let config = "x11forwarding yes\npasswordauthentication no\npermitroot login no\nallowt cpforwarding no\nmaxauthtries 3\n";
        let findings = parse_ssh_config(config);
        assert!(
            findings.iter().any(|f| f.title.contains("X11 forwarding")),
            "Should detect X11 forwarding finding"
        );
    }

    #[test]
    fn audit_ssh_emits_tcp_forwarding_when_not_disabled() {
        // Config that doesn't explicitly disable AllowTcpForwarding
        let config = "passwordauthentication no\n";
        let findings = parse_ssh_config(config);
        assert!(
            findings.iter().any(|f| f.title.contains("TCP forwarding")),
            "Should emit TCP forwarding finding when not explicitly disabled"
        );
    }

    #[test]
    fn audit_ssh_no_tcp_forwarding_finding_when_disabled() {
        let config = "allowtcpforwarding no\npasswordauthentication no\npermitroot login no\nmaxauthtries 3\n";
        let findings = parse_ssh_config(config);
        assert!(
            !findings.iter().any(|f| f.title.contains("TCP forwarding")),
            "Should NOT emit TCP forwarding finding when explicitly disabled"
        );
    }

    #[test]
    fn audit_system_returns_vec() {
        // Just verify it doesn't panic and returns a Vec (content depends on host)
        let findings = audit_system();
        // It's a Vec, even if empty on a well-configured system
        let _ = findings.len();
    }
}
