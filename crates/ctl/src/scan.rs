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
}

fn stars(n: u8) -> String {
    let filled = "\u{2605}".repeat(n as usize);
    let empty = "\u{2606}".repeat(5usize.saturating_sub(n as usize));
    format!("{filled}{empty}")
}

/// Score every module against the probes and return sorted recommendations.
pub fn score_modules(p: &SystemProbes) -> Vec<ModuleRec> {
    let mut recs: Vec<ModuleRec> = vec![
        // ssh-protection
        {
            let (tier, why, s) = if p.has_sshd || p.has_auth_log {
                (
                    Tier::Essential,
                    "sshd is running. Automatically detects and blocks brute-force attacks."
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
            }
        },
        // network-defense
        {
            let has_fw = p.has_ufw || p.has_iptables || p.has_nftables;
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
        },
        // container-security
        {
            let (tier, why, s, skip) = if p.has_docker {
                (
                    Tier::Essential,
                    "Docker is installed. Track container events and privileged container alerts."
                        .to_string(),
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
                enable_hint: "innerwarden module install container-security",
                stars: s,
                tier,
                needs_tool: if skip { Some("Docker") } else { None },
                docs_path: "container-security/docs/README.md",
            }
        },
        // search-protection
        {
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
            }
        },
        // nginx-error-monitor
        {
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
            }
        },
        // fail2ban-integration
        {
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
                enable_hint: "innerwarden module install fail2ban-integration",
                stars: s,
                tier,
                needs_tool: if missing { Some("fail2ban") } else { None },
                docs_path: "fail2ban-integration/docs/README.md",
            }
        },
        // geoip-enrichment
        ModuleRec {
            id: "geoip-enrichment",
            name: "IP Geolocation Enrichment",
            description: "Adds country/ISP context to AI decisions — free, no API key needed.",
            why: "Free enrichment layer. Adds country/ISP context to every AI decision."
                .to_string(),
            enable_hint: "innerwarden module install geoip-enrichment",
            stars: 2,
            tier: Tier::Optional,
            needs_tool: None,
            docs_path: "geoip-enrichment/docs/README.md",
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
            enable_hint: "innerwarden module install abuseipdb-enrichment",
            stars: 2,
            tier: Tier::Optional,
            needs_tool: None,
            docs_path: "abuseipdb-enrichment/docs/README.md",
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
            }
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
            }
        },
        // slack-notify
        ModuleRec {
            id: "slack-notify",
            name: "Slack Notifications",
            description: "Sends High/Critical incident alerts to a Slack channel.",
            why: "Optional: push notifications to Slack for any High/Critical incident."
                .to_string(),
            enable_hint: "innerwarden module install slack-notify",
            stars: 2,
            tier: Tier::Optional,
            needs_tool: None,
            docs_path: "slack-notify/docs/README.md",
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

fn print_recommendations(recs: &[ModuleRec]) {
    println!("Recommended modules for this machine:");
    println!("{}", "\u{2501}".repeat(64));

    let mut current_tier: Option<&Tier> = None;
    let mut idx = 1usize;

    // First pass: print available modules grouped by tier.
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
            "  [{idx}] {:<28} {}  {}",
            rec.id,
            stars(rec.stars),
            rec.name
        );
        println!("      {}", rec.why);
        println!("      \u{2192} {}", rec.enable_hint);
        println!();
        idx += 1;
    }

    if !not_available.is_empty() {
        println!("\n  NOT AVAILABLE (install the tool first, then re-run innerwarden scan)\n");
        for rec in &not_available {
            let tool = rec.needs_tool.unwrap_or(rec.id);
            println!("  \u{2500} {:<28}  Requires: {tool}", rec.id);
        }
    }

    println!();
    println!("{}", "\u{2500}".repeat(72));
    println!("Type a module name or number to learn more, or press Enter / 'q' to exit:");
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

fn show_module_info(module_id: &str, modules_dir: &Path) {
    match find_module_readme(module_id, modules_dir) {
        Some(readme) => match std::fs::read_to_string(&readme) {
            Ok(content) => {
                println!();
                println!("{content}");
            }
            Err(e) => {
                println!("Could not read docs for '{module_id}': {e}");
            }
        },
        None => {
            println!();
            println!("No detailed docs found for '{module_id}'.");
            println!("\u{2192} innerwarden module install {module_id}");
        }
    }
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
                        show_module_info(rec.id, modules_dir);
                        continue;
                    }
                }

                // Try module ID match (case-insensitive).
                let all: Vec<_> = recs.iter().collect();
                if let Some(rec) = all.iter().find(|r| r.id == other) {
                    show_module_info(rec.id, modules_dir);
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
    print_recommendations(&recs);

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
}
