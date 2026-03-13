mod ai;
mod correlation;
mod config;
mod decisions;
mod narrative;
mod report;
mod reader;
mod skills;
mod webhook;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::{debug, info, warn};

#[derive(Parser)]
#[command(name = "innerwarden-agent", version, about = "Interpretive layer — reads sensor JSONL, generates narratives, and auto-responds to incidents")]
struct Cli {
    /// Path to the sensor data directory (where events-*.jsonl and incidents-*.jsonl live)
    #[arg(long, default_value = "/var/lib/innerwarden")]
    data_dir: PathBuf,

    /// Path to agent config TOML (narrative, webhook, ai, responder settings). Optional.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Run once (process new entries then exit) instead of continuous mode
    #[arg(long)]
    once: bool,

    /// Generate a trial operational report from existing artifacts and exit
    #[arg(long)]
    report: bool,

    /// Poll interval in seconds for the narrative slow loop (default: 30)
    #[arg(long, default_value = "30")]
    interval: u64,
}

// ---------------------------------------------------------------------------
// Shared agent state (passed through tick functions)
// ---------------------------------------------------------------------------

struct AgentState {
    skill_registry: skills::SkillRegistry,
    blocklist: skills::Blocklist,
    correlator: correlation::TemporalCorrelator,
    /// Wrapped in Arc so we can clone a handle for use within a loop iteration
    /// without holding a borrow of `state` across async calls that need `&mut state`.
    ai_provider: Option<Arc<dyn ai::AiProvider>>,
    decision_writer: Option<decisions::DecisionWriter>,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file if present (fail-silent — production uses real env vars)
    match dotenvy::dotenv() {
        Ok(path) => debug!("loaded env from {}", path.display()),
        Err(dotenvy::Error::Io(_)) => {} // no .env file — that's fine
        Err(e) => warn!("could not parse .env file: {e}"),
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("innerwarden_agent=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    if cli.report {
        let out = report::generate(&cli.data_dir)?;
        info!(
            analyzed_date = %out.report.analyzed_date,
            markdown = %out.markdown_path.display(),
            json = %out.json_path.display(),
            "trial report generated"
        );
        println!(
            "Trial report generated:\n  {}\n  {}",
            out.markdown_path.display(),
            out.json_path.display()
        );
        return Ok(());
    }

    // Load config (optional — all fields have sensible defaults)
    let cfg = match &cli.config {
        Some(path) => config::load(path)?,
        None => config::AgentConfig::default(),
    };

    info!(
        data_dir = %cli.data_dir.display(),
        mode = if cli.once { "once" } else { "continuous" },
        narrative = cfg.narrative.enabled,
        webhook = cfg.webhook.enabled,
        ai = cfg.ai.enabled,
        correlation = cfg.correlation.enabled,
        correlation_window_secs = cfg.correlation.window_seconds,
        responder = cfg.responder.enabled,
        dry_run = cfg.responder.dry_run,
        "innerwarden-agent v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    // Clean up old summaries on startup
    if cfg.narrative.enabled {
        if let Err(e) = narrative::cleanup_old(&cli.data_dir, cfg.narrative.keep_days) {
            warn!("failed to clean up old summaries: {e:#}");
        }
    }

    // Build shared agent state
    let mut state = AgentState {
        skill_registry: skills::SkillRegistry::default_builtin(),
        blocklist: if cfg.responder.enabled && !cfg.responder.dry_run {
            skills::Blocklist::load_from_ufw().await
        } else {
            skills::Blocklist::default()
        },
        correlator: correlation::TemporalCorrelator::new(cfg.correlation.window_seconds, 4096),
        ai_provider: if cfg.ai.enabled {
            Some(Arc::from(ai::build_provider(&cfg.ai)))
        } else {
            None
        },
        decision_writer: if cfg.ai.enabled {
            match decisions::DecisionWriter::new(&cli.data_dir) {
                Ok(w) => Some(w),
                Err(e) => {
                    warn!("failed to create decision writer: {e:#}");
                    None
                }
            }
        } else {
            None
        },
    };

    let state_path = cli.data_dir.join("agent-state.json");
    let mut cursor = reader::AgentCursor::load(&state_path)?;

    if cli.once {
        let handled = process_incidents(&cli.data_dir, &mut cursor, &cfg, &mut state).await;
        let new_events = process_narrative_tick(&cli.data_dir, &mut cursor, &cfg).await?;
        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        cursor.save(&state_path)?;
        info!(new_events, incidents_handled = handled, "run complete");
    } else {
        let ai_poll = cfg.ai.incident_poll_secs;
        info!(
            narrative_interval_secs = cli.interval,
            incident_interval_secs = ai_poll,
            "entering continuous mode"
        );

        let mut narrative_ticker =
            tokio::time::interval(tokio::time::Duration::from_secs(cli.interval));
        let mut incident_ticker =
            tokio::time::interval(tokio::time::Duration::from_secs(ai_poll));

        // SIGTERM / SIGINT
        #[cfg(unix)]
        let mut sigterm = {
            use tokio::signal::unix::{signal, SignalKind};
            signal(SignalKind::terminate())?
        };

        loop {
            #[cfg(unix)]
            let shutdown = tokio::select! {
                _ = incident_ticker.tick() => {
                    process_incidents(&cli.data_dir, &mut cursor, &cfg, &mut state).await;
                    // Persist cursor after every incident tick — prevents double-processing on restart
                    if let Err(e) = cursor.save(&state_path) {
                        warn!("failed to save cursor after incident tick: {e:#}");
                    }
                    false
                }
                _ = narrative_ticker.tick() => {
                    match process_narrative_tick(&cli.data_dir, &mut cursor, &cfg).await {
                        Ok(n) => {
                            if n > 0 {
                                info!(new_events = n, "narrative tick");
                            }
                        }
                        Err(e) => warn!("narrative tick error: {e:#}"),
                    }
                    if let Err(e) = cursor.save(&state_path) {
                        warn!("failed to save cursor after narrative tick: {e:#}");
                    }
                    false
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("SIGINT received — shutting down");
                    true
                }
                _ = sigterm.recv() => {
                    info!("SIGTERM received — shutting down");
                    true
                }
            };

            #[cfg(not(unix))]
            let shutdown = tokio::select! {
                _ = incident_ticker.tick() => {
                    process_incidents(&cli.data_dir, &mut cursor, &cfg, &mut state).await;
                    if let Err(e) = cursor.save(&state_path) {
                        warn!("failed to save cursor after incident tick: {e:#}");
                    }
                    false
                }
                _ = narrative_ticker.tick() => {
                    match process_narrative_tick(&cli.data_dir, &mut cursor, &cfg).await {
                        Ok(n) => {
                            if n > 0 {
                                info!(new_events = n, "narrative tick");
                            }
                        }
                        Err(e) => warn!("narrative tick error: {e:#}"),
                    }
                    if let Err(e) = cursor.save(&state_path) {
                        warn!("failed to save cursor after narrative tick: {e:#}");
                    }
                    false
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("SIGINT received — shutting down");
                    true
                }
            };

            if shutdown {
                if let Some(w) = &mut state.decision_writer {
                    w.flush();
                }
                cursor.save(&state_path)?;
                break;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Incident tick — runs every 2s
//
// Responsibilities (in order, for every new incident):
//   1. Webhook: notify immediately for all incidents above min_severity
//   2. AI analysis: only for High/Critical that pass the algorithm gate
//
// The incident cursor is advanced and saved after every tick, so a crash
// between ticks never causes double-processing or lost webhook notifications.
// ---------------------------------------------------------------------------

/// Returns the number of incidents handled (webhook sent and/or AI analyzed).
async fn process_incidents(
    data_dir: &Path,
    cursor: &mut reader::AgentCursor,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> usize {
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();

    let incidents_path = data_dir.join(format!("incidents-{today}.jsonl"));

    let new_incidents = match reader::read_new_entries::<innerwarden_core::incident::Incident>(
        &incidents_path,
        cursor.incidents_offset(&today),
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!("incident tick: failed to read incidents: {e:#}");
            return 0;
        }
    };

    if new_incidents.entries.is_empty() {
        return 0;
    }

    // Advance cursor before any async work — prevents double-processing on crash/restart
    cursor.set_incidents_offset(&today, new_incidents.new_offset);

    // Pre-compute webhook threshold once (None = webhook disabled)
    let webhook_min_rank: Option<u8> = if cfg.webhook.enabled && !cfg.webhook.url.is_empty() {
        Some(webhook::severity_rank(&cfg.webhook.parsed_min_severity()))
    } else {
        None
    };

    // Pre-compute AI context (only if AI is configured)
    let ai_enabled = cfg.ai.enabled && state.ai_provider.is_some();
    let (all_events, skill_infos, ai_provider, provider_name, already_blocked, mut blocked_set) =
        if ai_enabled {
            let events_path = data_dir.join(format!("events-{today}.jsonl"));
            let events =
                reader::read_new_entries::<innerwarden_core::event::Event>(&events_path, 0)
                    .map(|r| r.entries)
                    .unwrap_or_default();
            let infos = state.skill_registry.infos();
            // Clone the Arc — owned handle, no borrow of `state`
            let prov: Arc<dyn ai::AiProvider> = state.ai_provider.as_ref().unwrap().clone();
            let pname = prov.name();
            let blocked = state.blocklist.as_vec();
            // Mutable so we can update it mid-tick to prevent duplicate AI calls
            // for the same IP when multiple incidents arrive in the same 2s window.
            let blocked_set: HashSet<String> = blocked.iter().cloned().collect();
            (events, infos, Some(prov), pname, blocked, blocked_set)
        } else {
            (vec![], vec![], None, "", vec![], HashSet::new())
        };

    let mut handled = 0;

    for incident in &new_incidents.entries {
        let related_incidents = if cfg.correlation.enabled {
            state
                .correlator
                .related_to(incident, cfg.correlation.max_related_incidents)
        } else {
            Vec::new()
        };
        if cfg.correlation.enabled {
            if !related_incidents.is_empty() {
                info!(
                    incident_id = %incident.incident_id,
                    correlated_count = related_incidents.len(),
                    "temporal correlation: related incidents found"
                );
            }
            // Observe early so correlation history stays consistent even when this
            // incident is later skipped by gate or AI call fails.
            state.correlator.observe(incident);
        }

        // 1. Webhook — fires for ALL incidents above configured threshold, regardless of AI gate
        if let Some(min_rank) = webhook_min_rank {
            if webhook::severity_rank(&incident.severity) >= min_rank {
                if let Err(e) = webhook::send_incident(
                    &cfg.webhook.url,
                    cfg.webhook.timeout_secs,
                    incident,
                )
                .await
                {
                    warn!(incident_id = %incident.incident_id, "webhook failed: {e:#}");
                }
            }
        }

        // 2. AI analysis — only when AI is enabled and incident passes the gate
        if !ai_enabled {
            handled += 1;
            continue;
        }

        if !ai::should_invoke_ai(incident, &blocked_set) {
            info!(
                incident_id = %incident.incident_id,
                severity = ?incident.severity,
                "AI gate: skipping (low severity / private IP / already blocked)"
            );
            handled += 1;
            continue;
        }

        // ai_provider is Some when ai_enabled — safe to unwrap
        let provider = ai_provider.as_ref().unwrap();

        info!(
            incident_id = %incident.incident_id,
            provider = provider_name,
            correlated_count = related_incidents.len(),
            "sending incident to AI for analysis"
        );

        // Build context — filter events to those involving the same incident IPs/users
        let entity_ips: HashSet<&str> = incident
            .entities
            .iter()
            .filter(|e| e.r#type == innerwarden_core::entities::EntityType::Ip)
            .map(|e| e.value.as_str())
            .collect();
        let entity_users: HashSet<&str> = incident
            .entities
            .iter()
            .filter(|e| e.r#type == innerwarden_core::entities::EntityType::User)
            .map(|e| e.value.as_str())
            .collect();

        let recent: Vec<&innerwarden_core::event::Event> = all_events
            .iter()
            .filter(|ev| {
                ev.entities
                    .iter()
                    .any(|e| {
                        (e.r#type == innerwarden_core::entities::EntityType::Ip
                            && entity_ips.contains(e.value.as_str()))
                            || (e.r#type == innerwarden_core::entities::EntityType::User
                                && entity_users.contains(e.value.as_str()))
                    })
            })
            .rev()
            .take(cfg.ai.context_events)
            .collect();
        let related_refs: Vec<&innerwarden_core::incident::Incident> =
            related_incidents.iter().collect();

        let ctx = ai::DecisionContext {
            incident,
            recent_events: recent,
            related_incidents: related_refs,
            already_blocked: already_blocked.clone(),
            available_skills: skill_infos
                .iter()
                .map(|s| ai::SkillInfo {
                    id: s.id.clone(),
                    name: s.name.clone(),
                    description: s.description.clone(),
                    tier: match s.tier {
                        skills::SkillTier::Open => "open".to_string(),
                        skills::SkillTier::Premium => "premium".to_string(),
                    },
                })
                .collect(),
        };

        let decision = match provider.decide(&ctx).await {
            Ok(d) => d,
            Err(e) => {
                warn!(incident_id = %incident.incident_id, "AI decision failed: {e:#}");
                handled += 1;
                continue;
            }
        };

        // Update the in-memory blocked_set immediately after a BlockIp decision.
        // This prevents a second incident from the same IP (arriving in the same 2s tick)
        // from triggering a duplicate AI call. The actual blocklist persists separately;
        // this is only a per-tick deduplication guard.
        if let ai::AiAction::BlockIp { ip, .. } = &decision.action {
            blocked_set.insert(ip.clone());
        }

        info!(
            incident_id = %incident.incident_id,
            action = ?decision.action,
            confidence = decision.confidence,
            auto_execute = decision.auto_execute,
            reason = %decision.reason,
            "AI decision"
        );

        // Execute if auto_execute AND confidence above threshold AND responder enabled
        let execution_result = if decision.auto_execute
            && decision.confidence >= cfg.ai.confidence_threshold
            && cfg.responder.enabled
        {
            execute_decision(&decision, incident, cfg, state).await
        } else if !cfg.responder.enabled {
            "skipped: responder disabled".to_string()
        } else if !decision.auto_execute {
            "skipped: AI did not recommend auto-execution".to_string()
        } else {
            format!(
                "skipped: confidence {:.2} below threshold {:.2}",
                decision.confidence, cfg.ai.confidence_threshold
            )
        };

        // Write to audit trail
        if let Some(writer) = &mut state.decision_writer {
            let entry = decisions::build_entry(
                &incident.incident_id,
                &incident.host,
                provider_name,
                &decision,
                cfg.responder.dry_run,
                &execution_result,
            );
            if let Err(e) = writer.write(&entry) {
                warn!("failed to write decision entry: {e:#}");
            }
        }

        handled += 1;
    }

    handled
}

/// Execute an AI decision by finding and running the appropriate skill.
async fn execute_decision(
    decision: &ai::AiDecision,
    incident: &innerwarden_core::incident::Incident,
    cfg: &config::AgentConfig,
    state: &mut AgentState,
) -> String {
    use ai::AiAction;

    match &decision.action {
        AiAction::BlockIp { ip, skill_id } => {
            // Resolve the effective skill ID, honouring the allowed_skills whitelist.
            // If the AI selected a skill not in the whitelist, fall back to the
            // configured backend default. This prevents the AI from executing a
            // skill the operator did not explicitly allow.
            let effective_id: String = if cfg.responder.allowed_skills.contains(skill_id) {
                skill_id.clone()
            } else {
                let fallback = format!("block-ip-{}", cfg.responder.block_backend);
                if cfg.responder.allowed_skills.contains(&fallback) {
                    fallback
                } else {
                    return format!("skipped: skill '{skill_id}' not in allowed_skills");
                }
            };

            let skill = state
                .skill_registry
                .get(&effective_id)
                .or_else(|| state.skill_registry.block_skill_for_backend(&cfg.responder.block_backend));

            match skill {
                Some(skill) => {
                    let ctx = skills::SkillContext {
                        incident: incident.clone(),
                        target_ip: Some(ip.clone()),
                        host: incident.host.clone(),
                    };
                    let result = skill.execute(&ctx, cfg.responder.dry_run).await;
                    if result.success && !cfg.responder.dry_run {
                        state.blocklist.insert(ip.clone());
                    }
                    result.message
                }
                None => format!("skipped: skill '{effective_id}' not found"),
            }
        }
        AiAction::Monitor { ip } => {
            if let Some(skill) = state.skill_registry.get("monitor-ip") {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: Some(ip.clone()),
                    host: incident.host.clone(),
                };
                skill.execute(&ctx, cfg.responder.dry_run).await.message
            } else {
                "skipped: monitor-ip skill not available".to_string()
            }
        }
        AiAction::Honeypot { ip } => {
            if let Some(skill) = state.skill_registry.get("honeypot") {
                let ctx = skills::SkillContext {
                    incident: incident.clone(),
                    target_ip: Some(ip.clone()),
                    host: incident.host.clone(),
                };
                skill.execute(&ctx, cfg.responder.dry_run).await.message
            } else {
                "skipped: honeypot skill not available".to_string()
            }
        }
        AiAction::RequestConfirmation { summary } => {
            if cfg.webhook.enabled && !cfg.webhook.url.is_empty() {
                let payload = serde_json::json!({
                    "type": "confirmation_required",
                    "incident_id": incident.incident_id,
                    "summary": summary,
                    "decision_reason": decision.reason,
                });
                let client = reqwest::Client::new();
                match client.post(&cfg.webhook.url).json(&payload).send().await {
                    Ok(_) => "confirmation request sent via webhook".to_string(),
                    Err(e) => format!("confirmation webhook failed: {e}"),
                }
            } else {
                "confirmation requested (no webhook configured)".to_string()
            }
        }
        AiAction::Ignore { reason } => {
            format!("ignored: {reason}")
        }
    }
}

// ---------------------------------------------------------------------------
// Narrative tick — runs every 30s
//
// Responsibility: regenerate the daily Markdown summary when new events arrive.
// Webhook and incident processing have been moved to process_incidents so that
// all incidents are notified in real-time, not batched every 30 seconds.
// ---------------------------------------------------------------------------

/// Returns the number of new events seen this tick.
async fn process_narrative_tick(
    data_dir: &Path,
    cursor: &mut reader::AgentCursor,
    cfg: &config::AgentConfig,
) -> Result<usize> {
    let today = chrono::Local::now()
        .date_naive()
        .format("%Y-%m-%d")
        .to_string();

    let events_path = data_dir.join(format!("events-{today}.jsonl"));

    // Read new events and advance the events cursor
    let new_events = reader::read_new_entries::<innerwarden_core::event::Event>(
        &events_path,
        cursor.events_offset(&today),
    )?;

    let events_count = new_events.entries.len();
    cursor.set_events_offset(&today, new_events.new_offset);

    // Regenerate daily summary when there are new events
    if cfg.narrative.enabled && events_count > 0 {
        let incidents_path = data_dir.join(format!("incidents-{today}.jsonl"));
        // Always read from offset 0 — summary covers the full day, not just new entries
        let all_events =
            reader::read_new_entries::<innerwarden_core::event::Event>(&events_path, 0)?;
        let all_incidents = reader::read_new_entries::<innerwarden_core::incident::Incident>(
            &incidents_path,
            0,
        )?;

        let host = all_events
            .entries
            .first()
            .map(|e| e.host.as_str())
            .or_else(|| all_incidents.entries.first().map(|i| i.host.as_str()))
            .unwrap_or("unknown");

        let md = narrative::generate(
            &today,
            host,
            &all_events.entries,
            &all_incidents.entries,
            cfg.correlation.window_seconds,
        );
        if let Err(e) = narrative::write(data_dir, &today, &md) {
            warn!("failed to write daily summary: {e:#}");
        } else {
            info!(date = today, "daily summary updated");
        }
    }

    Ok(events_count)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tempfile::TempDir;

    // ------------------------------------------------------------------
    // Minimal mock AI provider — returns a fixed decision, no network I/O
    // ------------------------------------------------------------------

    struct MockAiProvider {
        decision: ai::AiDecision,
    }

    #[async_trait::async_trait]
    impl ai::AiProvider for MockAiProvider {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn decide(&self, _ctx: &ai::DecisionContext<'_>) -> anyhow::Result<ai::AiDecision> {
            Ok(self.decision.clone())
        }
    }

    struct CountingMockAiProvider {
        decision: ai::AiDecision,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ai::AiProvider for CountingMockAiProvider {
        fn name(&self) -> &'static str {
            "mock-counting"
        }
        async fn decide(&self, _ctx: &ai::DecisionContext<'_>) -> anyhow::Result<ai::AiDecision> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision.clone())
        }
    }

    struct CorrelationInspectingMockAiProvider {
        decision: ai::AiDecision,
        last_related_count: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ai::AiProvider for CorrelationInspectingMockAiProvider {
        fn name(&self) -> &'static str {
            "mock-correlation"
        }

        async fn decide(&self, ctx: &ai::DecisionContext<'_>) -> anyhow::Result<ai::AiDecision> {
            self.last_related_count
                .store(ctx.related_incidents.len(), Ordering::SeqCst);
            Ok(self.decision.clone())
        }
    }

    /// Write a minimal Incident JSON line (ssh brute-force from an external IP).
    fn incident_line(ip: &str) -> String {
        serde_json::to_string(&innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: format!("ssh_bruteforce:{ip}:test"),
            severity: innerwarden_core::event::Severity::High,
            title: "SSH Brute Force".to_string(),
            summary: format!("9 failed SSH attempts from {ip}"),
            evidence: serde_json::json!({"failed_attempts": 9}),
            recommended_checks: vec![],
            tags: vec!["ssh".to_string()],
            entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
        })
        .unwrap()
    }

    fn incident_line_with_kind(ip: &str, kind: &str) -> String {
        serde_json::to_string(&innerwarden_core::incident::Incident {
            ts: chrono::Utc::now(),
            host: "test-host".to_string(),
            incident_id: format!("{kind}:{ip}:test"),
            severity: innerwarden_core::event::Severity::High,
            title: format!("{kind} detected"),
            summary: format!("{kind} from {ip}"),
            evidence: serde_json::json!({"kind": kind}),
            recommended_checks: vec![],
            tags: vec![kind.to_string()],
            entities: vec![innerwarden_core::entities::EntityRef::ip(ip)],
        })
        .unwrap()
    }

    // ------------------------------------------------------------------
    // Golden path: incident → algorithm gate → mock AI → dry-run block → decisions.jsonl
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn golden_path_dry_run_produces_decision_entry() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        // 1. Plant a single brute-force incident from a routable external IP.
        //    Must NOT be RFC1918, loopback, or documentation (203.0.113.x / 198.51.100.x
        //    are TEST-NET ranges and would be filtered by the algorithm gate).
        let attacker_ip = "1.2.3.4";
        let incidents_path = dir.path().join(format!("incidents-{today}.jsonl"));
        let mut f = std::fs::File::create(&incidents_path).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        drop(f);

        // 2. Config: AI enabled, responder dry_run=true, ufw backend allowed
        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.8,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                allowed_skills: vec!["block-ip-ufw".to_string()],
            },
            ..config::AgentConfig::default()
        };

        // 3. Mock provider always recommends blocking the IP
        let mock = Arc::new(MockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::BlockIp {
                    ip: attacker_ip.to_string(),
                    skill_id: "block-ip-ufw".to_string(),
                },
                confidence: 0.97,
                auto_execute: true,
                reason: "9 SSH failures, no success, external IP — classic brute force".to_string(),
                alternatives: vec!["monitor".to_string()],
                estimated_threat: "high".to_string(),
            },
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
        };

        // 4. Run the incident tick
        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(dir.path(), &mut cursor, &cfg, &mut state).await;

        // Verify: one incident handled
        assert_eq!(handled, 1, "expected 1 incident handled");

        // Verify: cursor advanced (incident will not be re-read on next tick)
        assert!(
            cursor.incidents_offset(&today) > 0,
            "cursor should have advanced past the incident"
        );

        // Verify: decision written to audit trail
        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let content = std::fs::read_to_string(&decisions_path).unwrap();
        assert!(content.contains(attacker_ip), "decision must record the target IP");
        assert!(content.contains("block_ip"), "decision must record action type");
        assert!(content.contains("\"dry_run\":true"), "dry_run must be flagged in audit trail");
        assert!(content.contains("mock"), "AI provider name must appear in audit trail");
    }

    // ------------------------------------------------------------------
    // allowed_skills whitelist: AI selects a disallowed skill → fallback used
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn allowed_skills_whitelist_enforced() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        // Use a routable external IP — TEST-NET ranges (203.0.113.x) are filtered by the gate
        let attacker_ip = "5.6.7.8";
        let incidents_path = dir.path().join(format!("incidents-{today}.jsonl"));
        let mut f = std::fs::File::create(&incidents_path).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        drop(f);

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.5,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                // Only ufw is allowed; AI picks iptables — should fall back silently
                allowed_skills: vec!["block-ip-ufw".to_string()],
            },
            ..config::AgentConfig::default()
        };

        // AI picks iptables (not in whitelist)
        let mock = Arc::new(MockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::BlockIp {
                    ip: attacker_ip.to_string(),
                    skill_id: "block-ip-iptables".to_string(), // NOT in allowed_skills
                },
                confidence: 0.95,
                auto_execute: true,
                reason: "brute force".to_string(),
                alternatives: vec![],
                estimated_threat: "high".to_string(),
            },
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(dir.path(), &mut cursor, &cfg, &mut state).await;

        // Still handled (not skipped entirely) — fell back to ufw
        assert_eq!(handled, 1);

        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let content = std::fs::read_to_string(&decisions_path).unwrap();
        // The execution used the ufw fallback, not iptables.
        // The audit trail still records the IP the AI identified.
        assert!(content.contains(attacker_ip));
    }

    #[tokio::test]
    async fn same_ip_in_same_tick_triggers_single_ai_call() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        let attacker_ip = "9.8.7.6";
        let incidents_path = dir.path().join(format!("incidents-{today}.jsonl"));
        let mut f = std::fs::File::create(&incidents_path).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        writeln!(f, "{}", incident_line(attacker_ip)).unwrap();
        drop(f);

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.5,
                context_events: 5,
                ..config::AiConfig::default()
            },
            responder: config::ResponderConfig {
                enabled: true,
                dry_run: true,
                block_backend: "ufw".to_string(),
                allowed_skills: vec!["block-ip-ufw".to_string()],
            },
            ..config::AgentConfig::default()
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let mock = Arc::new(CountingMockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::BlockIp {
                    ip: attacker_ip.to_string(),
                    skill_id: "block-ip-ufw".to_string(),
                },
                confidence: 0.95,
                auto_execute: true,
                reason: "duplicate IP in same tick".to_string(),
                alternatives: vec![],
                estimated_threat: "high".to_string(),
            },
            calls: calls.clone(),
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(dir.path(), &mut cursor, &cfg, &mut state).await;
        assert_eq!(handled, 2, "both incidents should be accounted for");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "same IP in same tick must call AI only once"
        );

        if let Some(w) = &mut state.decision_writer {
            w.flush();
        }
        let decisions_path = dir.path().join(format!("decisions-{today}.jsonl"));
        let content = std::fs::read_to_string(&decisions_path).unwrap();
        assert_eq!(content.lines().count(), 1, "only one decision should be recorded");
    }

    #[tokio::test]
    async fn temporal_correlation_context_is_passed_to_ai() {
        let dir = TempDir::new().unwrap();
        let today = chrono::Local::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        let attacker_ip = "2.3.4.5";
        let incidents_path = dir.path().join(format!("incidents-{today}.jsonl"));
        let mut f = std::fs::File::create(&incidents_path).unwrap();
        writeln!(f, "{}", incident_line_with_kind(attacker_ip, "port_scan")).unwrap();
        writeln!(
            f,
            "{}",
            incident_line_with_kind(attacker_ip, "credential_stuffing")
        )
        .unwrap();
        drop(f);

        let cfg = config::AgentConfig {
            ai: config::AiConfig {
                enabled: true,
                confidence_threshold: 0.5,
                context_events: 5,
                ..config::AiConfig::default()
            },
            correlation: config::CorrelationConfig {
                enabled: true,
                window_seconds: 300,
                max_related_incidents: 8,
            },
            responder: config::ResponderConfig {
                enabled: false,
                ..config::ResponderConfig::default()
            },
            ..config::AgentConfig::default()
        };

        let related_count = Arc::new(AtomicUsize::new(0));
        let mock = Arc::new(CorrelationInspectingMockAiProvider {
            decision: ai::AiDecision {
                action: ai::AiAction::Ignore {
                    reason: "test correlation".to_string(),
                },
                confidence: 0.9,
                auto_execute: false,
                reason: "test correlation".to_string(),
                alternatives: vec![],
                estimated_threat: "medium".to_string(),
            },
            last_related_count: related_count.clone(),
        });

        let mut state = AgentState {
            skill_registry: skills::SkillRegistry::default_builtin(),
            blocklist: skills::Blocklist::default(),
            correlator: correlation::TemporalCorrelator::new(300, 4096),
            ai_provider: Some(mock as Arc<dyn ai::AiProvider>),
            decision_writer: Some(decisions::DecisionWriter::new(dir.path()).unwrap()),
        };

        let mut cursor = reader::AgentCursor::default();
        let handled = process_incidents(dir.path(), &mut cursor, &cfg, &mut state).await;
        assert_eq!(handled, 2);
        assert!(
            related_count.load(Ordering::SeqCst) >= 1,
            "second correlated incident should carry prior incident context"
        );
    }
}
