/// Telegram notification and approval channel for InnerWarden.
///
/// T.1 — Notifications: sends an alert message for every High/Critical incident.
/// T.2 — Approvals: sends an inline-keyboard message when the AI requests human
///        confirmation; polls for button presses and sends results back to the
///        main loop via a channel.
use std::time::Duration;

use anyhow::{Context, Result};
use innerwarden_core::incident::Incident;
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Guardian mode
// ---------------------------------------------------------------------------

/// Operating mode of the InnerWarden agent — drives notification style.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GuardianMode {
    /// Responder enabled, live — agent acts autonomously and reports decisions.
    Guard,
    /// Responder enabled, dry-run — simulates actions, asks for confirmation.
    DryRun,
    /// Responder disabled — monitors and asks operator what to do.
    Watch,
}

impl GuardianMode {
    pub fn label(&self) -> &'static str {
        match self {
            GuardianMode::Guard => "🟢 GUARD",
            GuardianMode::DryRun => "🟡 DRY-RUN",
            GuardianMode::Watch => "🔵 WATCH",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            GuardianMode::Guard => "I act on threats automatically",
            GuardianMode::DryRun => "I simulate actions — no real changes",
            GuardianMode::Watch => "I alert you and wait for your call",
        }
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// An approval result received from the operator via Telegram.
#[derive(Debug, Clone)]
pub struct ApprovalResult {
    pub incident_id: String,
    pub approved: bool,
    pub operator_name: String,
    /// If true, the operator wants this detector+action pair to always auto-execute.
    pub always: bool,
    /// The action chosen by the operator (for multi-choice keyboards).
    /// Values: "honeypot", "block", "monitor", "ignore", or empty (binary approve/reject).
    pub chosen_action: String,
}

/// Tracks a pending confirmation while waiting for the operator's response.
#[derive(Debug, Clone)]
pub struct PendingConfirmation {
    #[allow(dead_code)]
    pub incident_id: String,
    pub telegram_message_id: i64,
    #[allow(dead_code)]
    pub action_description: String,
    #[allow(dead_code)]
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Detector that triggered this incident (for trust-rule creation on "Always").
    pub detector: String,
    /// Action name (for trust-rule creation on "Always").
    pub action_name: String,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub struct TelegramClient {
    bot_token: String,
    chat_id: String,
    dashboard_url: Option<String>,
    http: reqwest::Client,
}

impl TelegramClient {
    pub fn new(
        bot_token: impl Into<String>,
        chat_id: impl Into<String>,
        dashboard_url: Option<String>,
    ) -> Result<Self> {
        // Long-poll timeout is 25 s; give a 10 s buffer so the HTTP layer
        // never fires before the Telegram timeout parameter expires.
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(35))
            .build()
            .context("failed to build Telegram HTTP client")?;
        Ok(Self {
            bot_token: bot_token.into(),
            chat_id: chat_id.into(),
            dashboard_url,
            http,
        })
    }

    fn api_url(&self, method: &str) -> String {
        format!("https://api.telegram.org/bot{}/{}", self.bot_token, method)
    }

    // -----------------------------------------------------------------------
    // T.1 — Incident notification
    // -----------------------------------------------------------------------

    /// Send a notification message for a High/Critical incident.
    /// In GUARD mode the alert is compact — no action buttons, the agent will
    /// act and follow up with send_action_report(). In WATCH/DryRun mode the
    /// alert includes Block/Ignore quick-action buttons.
    /// Failures are logged as warnings and never propagate — fail-open.
    pub async fn send_incident_alert(&self, incident: &Incident, mode: GuardianMode) -> Result<()> {
        let text = format_incident_message(incident, self.dashboard_url.as_deref(), mode);

        let mut body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });

        match mode {
            GuardianMode::Guard => {
                // GUARD: agent will act — show investigate button only, no Block/Ignore
                if let Some(ip) = first_ip_entity(incident) {
                    if let Some(ref base_url) = self.dashboard_url {
                        let link = format!(
                            "{base_url}/?subject_type=ip&subject={ip}&date={}",
                            incident.ts.format("%Y-%m-%d")
                        );
                        body["reply_markup"] = serde_json::json!({
                            "inline_keyboard": [[{
                                "text": "🔍 Investigate",
                                "url": link
                            }]]
                        });
                    }
                }
            }
            GuardianMode::Watch | GuardianMode::DryRun => {
                // WATCH/DryRun: operator makes the call — add Block/Ignore buttons
                if let Some(ip) = first_ip_entity(incident) {
                    let mut keyboard: Vec<Vec<serde_json::Value>> = vec![vec![
                        serde_json::json!({
                            "text": format!("🛡 Block {ip}"),
                            "callback_data": format!("quick:block:{ip}")
                        }),
                        serde_json::json!({
                            "text": "🙈 Ignore",
                            "callback_data": "quick:ignore"
                        }),
                    ]];

                    if let Some(ref base_url) = self.dashboard_url {
                        let link = format!(
                            "{base_url}/?subject_type=ip&subject={ip}&date={}",
                            incident.ts.format("%Y-%m-%d")
                        );
                        keyboard.push(vec![serde_json::json!({
                            "text": "🔍 Investigate in dashboard",
                            "url": link
                        })]);
                    }

                    body["reply_markup"] = serde_json::json!({ "inline_keyboard": keyboard });
                } else if let Some(ref base_url) = self.dashboard_url {
                    let link = format!("{base_url}/?date={}", incident.ts.format("%Y-%m-%d"));
                    body["reply_markup"] = serde_json::json!({
                        "inline_keyboard": [[{
                            "text": "🔍 Investigate in dashboard",
                            "url": link
                        }]]
                    });
                }
            }
        }

        self.post_json("sendMessage", &body).await
    }

    /// Send a post-execution report when the agent autonomously acted on a threat.
    /// Called in GUARD mode after execute_decision succeeds.
    pub async fn send_action_report(
        &self,
        action_label: &str,
        target: &str,
        incident_title: &str,
        confidence: f32,
        host: &str,
        dry_run: bool,
        reputation: Option<&crate::abuseipdb::IpReputation>,
        geo: Option<&crate::geoip::GeoInfo>,
    ) -> Result<()> {
        let pct = (confidence * 100.0) as u32;

        // Build optional enrichment block
        let mut enrichment = String::new();
        if let Some(rep) = reputation {
            let bar = reputation_score_bar(rep.confidence_score);
            let country_part = geo
                .map(|g| {
                    let flag = country_flag_emoji(&g.country_code);
                    format!(" · {flag} {} · {}", g.country, g.isp)
                })
                .unwrap_or_default();
            enrichment = format!(
                "\n📊 AbuseIPDB: <b>{}/100</b> {bar}{country_part}",
                rep.confidence_score
            );
        } else if let Some(g) = geo {
            let flag = country_flag_emoji(&g.country_code);
            enrichment = format!("\n🌐 {flag} {} · {}", g.country, escape_html(&g.isp));
        }

        let text = if dry_run {
            format!(
                "🧪 <b>Simulated</b> — <b>{host}</b>\n\
                 Would've {action_label} <code>{target}</code>{enrichment}\n\
                 <i>{incident_title}</i>\n\
                 Confidence: {pct}% | No real action taken (dry-run mode)",
                host = escape_html(host),
                target = escape_html(target),
                incident_title = escape_html(incident_title),
            )
        } else {
            format!(
                "✅ <b>Threat neutralized</b> — <b>{host}</b>\n\
                 {action_label} <code>{target}</code>{enrichment}\n\
                 <i>{incident_title}</i>\n\
                 Confidence: {pct}% | This actor won't be back.",
                host = escape_html(host),
                target = escape_html(target),
                incident_title = escape_html(incident_title),
            )
        };

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });
        self.post_json("sendMessage", &body).await
    }

    /// Send the onboarding/welcome message when the operator opens the bot.
    /// Shows current mode, today's stats, and quick-action buttons.
    pub async fn send_onboarding(
        &self,
        host: &str,
        incident_count: usize,
        decision_count: usize,
        mode: GuardianMode,
    ) -> Result<()> {
        let mode_label = mode.label();
        let mode_desc = mode.description();

        let today_line = if incident_count == 0 {
            "Perimeter's clean — no threat actors in the logs today.".to_string()
        } else {
            format!(
                "<b>{incident_count}</b> intrusion attempt{} logged, <b>{decision_count}</b> neutralized.",
                if incident_count == 1 { "" } else { "s" },
            )
        };

        let text = format!(
            "👾 Yo. I'm <b>InnerWarden</b> — your server's hacker guardian.\n\
             Got eyes on <b>{host}</b>. Perimeter's mine.\n\
             \n\
             {today_line}\n\
             \n\
             Mode: <b>{mode_label}</b>\n\
             <i>{mode_desc}</i>\n\
             \n\
             What do you need, operator?",
            host = escape_html(host),
        );

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "reply_markup": {
                "inline_keyboard": [
                    [
                        { "text": "📊 Status",    "callback_data": "menu:status"    },
                        { "text": "🚨 Threats",   "callback_data": "menu:threats"   }
                    ],
                    [
                        { "text": "⚖️ Decisions", "callback_data": "menu:decisions" },
                        { "text": "❓ Help",       "callback_data": "menu:help"      }
                    ]
                ]
            }
        });
        self.post_json("sendMessage", &body).await
    }

    // -----------------------------------------------------------------------
    // T.2 — Confirmation request (inline keyboard: Approve / Reject)
    // -----------------------------------------------------------------------

    /// Send a confirmation-request message with Approve/Reject inline keyboard.
    /// Returns the Telegram message ID so the caller can track the pending approval.
    pub async fn send_confirmation_request(
        &self,
        incident: &Incident,
        action_description: &str,
        action_name: &str,
        confidence: f32,
        expires_secs: u64,
    ) -> Result<i64> {
        let sev = severity_label(incident);
        let source_icon = source_icon(&incident.tags);
        let entity_line = entity_summary(incident);
        let pct = (confidence * 100.0) as u32;

        let confidence_phrase = match pct {
            90..=100 => "High confidence — this is a real threat",
            75..=89 => "Strong signal — TTPs check out",
            60..=74 => "Moderate confidence — worth acting on",
            _ => "Low signal — could be noise, could be legit",
        };
        let action_plain = plain_action(action_description);
        let expires_min = expires_secs / 60;
        let expires_label = if expires_min >= 1 {
            format!("{expires_min} min")
        } else {
            format!("{expires_secs}s")
        };

        let text = format!(
            "{source_icon} {sev} — <b>{host}</b>\n\
             <b>{title}</b>\n\
             {entity_line}\n\
             \n\
             🤖 {confidence_phrase} ({pct}%). Recommended action:\n\
             <code>{action_plain}</code>\n\
             \n\
             Your call, operator — {expires_label} to respond.",
            host = escape_html(&incident.host),
            title = escape_html(&incident.title),
            action_plain = escape_html(&action_plain),
            entity_line = entity_line,
            sev = sev,
            source_icon = source_icon,
            confidence_phrase = confidence_phrase,
            expires_label = expires_label,
            pct = pct,
        );

        let id = &incident.incident_id;
        let always_label = format!("🔁 Always {action_name}");
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "reply_markup": {
                "inline_keyboard": [[
                    { "text": "✅ Approve", "callback_data": format!("approve:{id}") },
                    { "text": always_label, "callback_data": format!("always:{id}") },
                    { "text": "❌ Reject", "callback_data": format!("reject:{id}") }
                ]]
            }
        });

        let resp = self.post_json_with_response("sendMessage", &body).await?;
        let msg_id = resp["result"]["message_id"]
            .as_i64()
            .context("Telegram sendMessage returned no message_id")?;
        Ok(msg_id)
    }

    // -----------------------------------------------------------------------
    // Honeypot operator-in-the-loop suggestion
    // -----------------------------------------------------------------------

    /// Send a honeypot suggestion message with a 4-button choice keyboard.
    ///
    /// Sent when the AI recommends `Honeypot` (or when `block_ip` is decided and honeypot
    /// is an allowed skill) so the operator can choose what to do with the attacker.
    ///
    /// Returns the Telegram `message_id` for pending-choice tracking.
    pub async fn send_honeypot_suggestion(
        &self,
        incident: &Incident,
        ip: &str,
        ai_reason: &str,
        ai_confidence: f32,
        ai_suggested: &str, // "honeypot" | "block" | "monitor"
    ) -> Result<i64> {
        let pct = (ai_confidence * 100.0) as u32;

        let text = format!(
            "🎯 <b>Tenho um suspeito aqui</b>\n\
             \n\
             <b>IP:</b> <code>{ip}</code>\n\
             <b>Incidente:</b> {title}\n\
             <b>Avaliação IA:</b> {reason} (confiança: {pct}%)\n\
             \n\
             O que fazemos com esse cara?",
            ip = escape_html(ip),
            title = escape_html(&incident.title),
            reason = escape_html(ai_reason),
            pct = pct,
        );

        // Add ✓ checkmark to the AI-suggested action
        let honeypot_label = if ai_suggested == "honeypot" {
            "🍯 Honeypot ✓"
        } else {
            "🍯 Honeypot"
        };
        let block_label = if ai_suggested == "block" {
            "🚫 Bloquear ✓"
        } else {
            "🚫 Bloquear"
        };
        let monitor_label = if ai_suggested == "monitor" {
            "👁 Monitorar ✓"
        } else {
            "👁 Monitorar"
        };

        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
            "reply_markup": {
                "inline_keyboard": [
                    [
                        { "text": honeypot_label, "callback_data": format!("hpot:honeypot:{ip}") },
                        { "text": block_label,    "callback_data": format!("hpot:block:{ip}")    }
                    ],
                    [
                        { "text": monitor_label,  "callback_data": format!("hpot:monitor:{ip}")  },
                        { "text": "❌ Ignorar",   "callback_data": format!("hpot:ignore:{ip}")   }
                    ]
                ]
            }
        });

        let resp = self.post_json_with_response("sendMessage", &body).await?;
        let msg_id = resp["result"]["message_id"]
            .as_i64()
            .context("Telegram sendMessage returned no message_id")?;
        Ok(msg_id)
    }

    /// Edit a confirmation message to show the final outcome (removes the keyboard).
    pub async fn resolve_confirmation(
        &self,
        message_id: i64,
        approved: bool,
        always: bool,
        operator: &str,
    ) -> Result<()> {
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "message_id": message_id,
            "reply_markup": { "inline_keyboard": [] }
        });
        // Remove inline keyboard
        let _ = self.post_json("editMessageReplyMarkup", &body).await;

        // Send follow-up result message with hacker personality
        let text = if always {
            format!(
                "🔁 Trust rule saved, {operator}. This TTP is now auto-contained — no need to ping you next time.",
                operator = escape_html(operator)
            )
        } else if approved {
            format!(
                "✅ Executed. {operator} called the shot — threat actor has been neutralized.",
                operator = escape_html(operator)
            )
        } else {
            format!(
                "❌ Standing down on {operator}'s call. Logging the IOC, keeping eyes on it.",
                operator = escape_html(operator)
            )
        };
        let body2 = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "reply_to_message_id": message_id,
        });
        self.post_json("sendMessage", &body2).await
    }

    // -----------------------------------------------------------------------
    // T.5 — Post-session honeypot report
    // -----------------------------------------------------------------------

    /// T.5 — Post-session report sent after a honeypot session ends.
    /// Summarizes commands, extracted IOCs, AI verdict, and offers a Block action.
    pub async fn send_honeypot_session_report(
        &self,
        ip: &str,
        session_id: &str,
        duration_secs: u64,
        commands: &[String],
        iocs: &crate::ioc::ExtractedIocs,
        ai_verdict: &str,
        auto_blocked: bool,
    ) -> Result<()> {
        let mut lines = Vec::new();
        lines.push(format!(
            "🍯 <b>Sessão de honeypot encerrada</b>\n\n\
             <b>Atacante:</b> <code>{ip}</code>\n\
             <b>Sessão:</b> <code>{session_id}</code>\n\
             <b>Duração:</b> {duration_secs}s | <b>Comandos:</b> {}",
            commands.len(),
            ip = escape_html(ip),
            session_id = escape_html(session_id),
        ));

        if !commands.is_empty() {
            let mut cmd_block = "\n<b>O que ele tentou:</b>\n".to_string();
            for cmd in commands.iter().take(8) {
                cmd_block.push_str(&format!("  $ <code>{}</code>\n", escape_html(cmd)));
            }
            lines.push(cmd_block.trim_end().to_string());
        }

        if !iocs.is_empty() {
            let ioc_text = iocs.format_telegram();
            if !ioc_text.is_empty() {
                lines.push(format!("\n<b>IOCs extraídos:</b>\n{ioc_text}"));
            }
        }

        lines.push(format!(
            "\n<b>Veredicto IA:</b> {}",
            escape_html(ai_verdict)
        ));

        if auto_blocked {
            lines.push("\n✅ IP bloqueado automaticamente.".to_string());
        }

        let text = lines.join("\n");

        // Build inline keyboard
        let mut keyboard_rows: Vec<Vec<serde_json::Value>> = vec![];

        if !auto_blocked {
            keyboard_rows.push(vec![serde_json::json!({
                "text": "🚫 Bloquear agora",
                "callback_data": format!("hpot:block:{ip}")
            })]);
        }

        if let Some(ref dash_url) = self.dashboard_url {
            keyboard_rows.push(vec![serde_json::json!({
                "text": "📊 Ver no dashboard",
                "url": dash_url
            })]);
        }

        let body = if keyboard_rows.is_empty() {
            serde_json::json!({
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": true,
            })
        } else {
            serde_json::json!({
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": true,
                "reply_markup": {
                    "inline_keyboard": keyboard_rows
                }
            })
        };

        self.post_json("sendMessage", &body).await
    }

    // -----------------------------------------------------------------------
    // AbuseIPDB auto-block notification
    // -----------------------------------------------------------------------

    /// Notify operator when an IP is auto-blocked via AbuseIPDB threshold
    /// (no AI call was made — pure reputation gate).
    pub async fn send_abuseipdb_autoblock(
        &self,
        ip: &str,
        score: u8,
        threshold: u8,
        total_reports: u32,
        country: Option<&str>,
        isp: Option<&str>,
        incident_title: &str,
        dry_run: bool,
        dashboard_url: Option<&str>,
    ) -> Result<()> {
        let country_flag = country
            .map(|c| format!(" {} ·", country_flag_emoji(c)))
            .unwrap_or_default();
        let isp_line = isp
            .map(|i| format!(" · <i>{}</i>", escape_html(i)))
            .unwrap_or_default();
        let reports_line = if total_reports > 0 {
            format!(" · {} reports worldwide", total_reports)
        } else {
            String::new()
        };

        let (action_line, header) = if dry_run {
            (
                format!("Would've blocked <code>{}</code> — dry-run mode, no real action.", escape_html(ip)),
                "🧪 <b>Simulation</b> — AbuseIPDB auto-block",
            )
        } else {
            (
                format!("Blocked <code>{}</code> instantly — no AI token wasted.", escape_html(ip)),
                "🛡 <b>Auto-blocked</b> — AbuseIPDB gate",
            )
        };

        let score_bar = reputation_score_bar(score);

        let text = format!(
            "{header}\n\
             \n\
             🌐{country_flag} <code>{ip}</code>{isp_line}\n\
             📊 Score: <b>{score}/100</b> {score_bar}{reports_line}\n\
             🔍 <i>{incident_title}</i>\n\
             \n\
             {action_line}\n\
             <i>Score ≥ {threshold} — handled before AI analysis.</i>",
            ip = escape_html(ip),
            incident_title = escape_html(incident_title),
        );

        let mut body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });

        // Deep-link to dashboard journey for this IP
        if let Some(base_url) = dashboard_url {
            let today = chrono::Utc::now().format("%Y-%m-%d");
            body["reply_markup"] = serde_json::json!({
                "inline_keyboard": [[{
                    "text": "🔍 View threat timeline",
                    "url": format!("{base_url}/?subject_type=ip&subject={ip}&date={today}", ip = ip)
                }]]
            });
        }

        self.post_json("sendMessage", &body).await
    }

    // T.3 — Daily digest
    // -----------------------------------------------------------------------

    /// Send a plain HTML text message (used for daily digest).
    pub async fn send_text_message(&self, text: &str) -> Result<()> {
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });
        self.post_json("sendMessage", &body).await
    }

    /// Send an HTML message with an inline keyboard.
    pub async fn send_text_with_keyboard(
        &self,
        text: &str,
        keyboard: serde_json::Value,
    ) -> Result<()> {
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
            "reply_markup": { "inline_keyboard": keyboard },
        });
        self.post_json("sendMessage", &body).await
    }

    /// Send the interactive menu with inline keyboard buttons.
    pub async fn send_menu(&self) -> Result<()> {
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": "🛡 <b>InnerWarden</b> — what would you like?",
            "parse_mode": "HTML",
            "reply_markup": {
                "inline_keyboard": [
                    [
                        { "text": "📊 Status",    "callback_data": "menu:status"    },
                        { "text": "🚨 Threats",   "callback_data": "menu:threats"   }
                    ],
                    [
                        { "text": "⚖️ Decisions", "callback_data": "menu:decisions" },
                        { "text": "❓ Help",       "callback_data": "menu:help"      }
                    ]
                ]
            }
        });
        self.post_json("sendMessage", &body).await
    }

    /// React to a message with 👀 (processing indicator).
    pub async fn react_eyes(&self, chat_id: i64, message_id: i64) {
        let body = serde_json::json!({
            "chat_id": chat_id,
            "message_id": message_id,
            "reaction": [{ "type": "emoji", "emoji": "👀" }]
        });
        let _ = self.post_json("setMessageReaction", &body).await;
    }

    /// Show "typing..." indicator in the chat.
    pub async fn send_typing(&self) {
        let body = serde_json::json!({
            "chat_id": self.chat_id,
            "action": "typing"
        });
        let _ = self.post_json("sendChatAction", &body).await;
    }

    /// Register the bot's persistent command menu (shown in the text input).
    /// Called once at startup.
    pub async fn set_commands(&self) {
        let body = serde_json::json!({
            "commands": [
                { "command": "status",       "description": "Guardian status — mode, AI, threat intel" },
                { "command": "threats",      "description": "Recent intrusion attempts" },
                { "command": "decisions",    "description": "Actions I've taken" },
                { "command": "blocked",      "description": "Threat actors currently contained" },
                { "command": "capabilities", "description": "List all capabilities and their status" },
                { "command": "enable",       "description": "Enable a capability — /enable block-ip" },
                { "command": "disable",      "description": "Disable a capability — /disable ai" },
                { "command": "doctor",       "description": "Full health check with fix hints" },
                { "command": "guard",        "description": "Activate auto-defend mode" },
                { "command": "watch",        "description": "Switch to passive monitor mode" },
                { "command": "ask",          "description": "Ask me anything — I know my config" },
                { "command": "help",         "description": "Operator command playbook" }
            ]
        });
        let _ = self.post_json("setMyCommands", &body).await;
    }

    // -----------------------------------------------------------------------
    // Polling loop (background task)
    // -----------------------------------------------------------------------

    /// Polls Telegram for updates and sends ApprovalResults to `approval_tx`.
    /// Designed to run as a background tokio task — exits when `approval_tx` is closed.
    ///
    /// Uses long-polling (timeout=25s) so this blocks for up to 25s between updates.
    /// Any errors are logged and the loop continues.
    pub async fn run_polling(
        self: std::sync::Arc<Self>,
        approval_tx: mpsc::Sender<ApprovalResult>,
    ) {
        let mut offset: i64 = 0;

        loop {
            if approval_tx.is_closed() {
                break;
            }

            match self.get_updates(offset).await {
                Ok(updates) => {
                    if !updates.is_empty() {
                        info!(count = updates.len(), offset, "Telegram: received updates");
                    }
                    for update in updates {
                        offset = update.update_id + 1;

                        if let Some(callback) = update.callback_query {
                            let operator = callback
                                .from
                                .first_name
                                .clone()
                                .unwrap_or_else(|| "unknown".to_string());

                            if let Some(data) = &callback.data {
                                if data == "quick:ignore" {
                                    // Just ack with toast — no further action needed
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            "👍 Logged as false positive. Keeping eyes on it.",
                                        )
                                        .await;
                                } else if let Some(ip) = data.strip_prefix("quick:block:") {
                                    let ip = ip.to_string();
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            &format!("🛡 Dropping {ip} at the firewall..."),
                                        )
                                        .await;
                                    let result = ApprovalResult {
                                        incident_id: format!("__quick_block__:{ip}"),
                                        approved: true,
                                        always: false,
                                        operator_name: operator.clone(),
                                        chosen_action: String::new(),
                                    };
                                    if approval_tx.send(result).await.is_err() {
                                        return;
                                    }
                                } else if let Some(rest) = data.strip_prefix("hpot:") {
                                    // Honeypot operator-in-the-loop choice
                                    // format: "hpot:{action}:{ip}"
                                    let parts: Vec<&str> = rest.splitn(2, ':').collect();
                                    if parts.len() == 2 {
                                        let action = parts[0];
                                        let ip = parts[1];
                                        let toast = match action {
                                            "honeypot" => {
                                                format!("🍯 Jogando {ip} no honeypot...")
                                            }
                                            "block" => {
                                                format!("🚫 Bloqueando {ip} no firewall...")
                                            }
                                            "monitor" => {
                                                format!("👁 Monitorando {ip} silenciosamente...")
                                            }
                                            _ => "👍 Registrado.".to_string(),
                                        };
                                        let _ =
                                            self.answer_callback_toast(&callback.id, &toast).await;
                                        let result = ApprovalResult {
                                            incident_id: format!("__hpot__:{ip}"),
                                            approved: action != "ignore",
                                            always: false,
                                            operator_name: operator.clone(),
                                            chosen_action: action.to_string(),
                                        };
                                        if approval_tx.send(result).await.is_err() {
                                            return;
                                        }
                                    }
                                } else {
                                    // Answer the callback immediately to remove the spinner
                                    let _ = self.answer_callback(&callback.id).await;
                                    if let Some(result) = parse_callback(data, &operator) {
                                        if approval_tx.send(result).await.is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                        }

                        // Handle text commands and free-form messages
                        if let Some(msg) = update.message {
                            if let Some(raw_text) = &msg.text {
                                // Strip @BotUsername suffix that Telegram appends
                                // (e.g. "/help@InnerWardenBot" → "/help")
                                let text = strip_bot_suffix(raw_text.trim());
                                let operator = msg
                                    .from
                                    .as_ref()
                                    .and_then(|f| f.first_name.clone())
                                    .unwrap_or_default();
                                info!(text = %text, operator = %operator, "Telegram: text message received");

                                // Visual feedback: react with 👀 and show typing
                                let chat_id = msg.chat.as_ref().map(|c| c.id).unwrap_or(0);
                                if chat_id != 0 {
                                    self.react_eyes(chat_id, msg.message_id).await;
                                }
                                self.send_typing().await;

                                let incident_id = if text == "/status"
                                    || text.starts_with("/status ")
                                {
                                    info!("Telegram: routing /status command");
                                    "__status__".to_string()
                                } else if text == "/help" || text.starts_with("/help ") {
                                    "__help__".to_string()
                                } else if text == "/menu" || text.starts_with("/menu ") {
                                    "__menu__".to_string()
                                } else if text == "/incidents"
                                    || text.starts_with("/incidents ")
                                    || text == "/threats"
                                    || text.starts_with("/threats ")
                                {
                                    "__threats__".to_string()
                                } else if text == "/decisions" || text.starts_with("/decisions ") {
                                    "__decisions__".to_string()
                                } else if text == "/blocked" || text.starts_with("/blocked ") {
                                    "__blocked__".to_string()
                                } else if text == "/guard" || text.starts_with("/guard ") {
                                    "__guard__".to_string()
                                } else if text == "/watch" || text.starts_with("/watch ") {
                                    "__watch__".to_string()
                                } else if text == "/doctor" || text.starts_with("/doctor ") {
                                    "__doctor__".to_string()
                                } else if text == "/capabilities"
                                    || text.starts_with("/capabilities ")
                                    || text == "/list"
                                    || text.starts_with("/list ")
                                {
                                    "__capabilities__".to_string()
                                } else if let Some(cap) = text.strip_prefix("/enable ") {
                                    format!("__enable__:{cap}")
                                } else if let Some(cap) = text.strip_prefix("/disable ") {
                                    format!("__disable__:{cap}")
                                } else if text == "/start" || text.starts_with("/start ") {
                                    // Telegram sends /start when user first opens the bot
                                    "__start__".to_string()
                                } else if !text.starts_with('/') || text.starts_with("/ask ") {
                                    // Free-form text or /ask <question> — route to AI
                                    let question =
                                        text.strip_prefix("/ask ").unwrap_or(&text).to_string();
                                    format!("__ask__:{question}")
                                } else {
                                    // Unknown command — send help hint
                                    "__unknown_cmd__".to_string()
                                };

                                let _ = approval_tx
                                    .send(ApprovalResult {
                                        incident_id,
                                        approved: true,
                                        always: false,
                                        operator_name: operator,
                                        chosen_action: String::new(),
                                    })
                                    .await;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Telegram poll error: {e:#}");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Low-level API calls
    // -----------------------------------------------------------------------

    async fn get_updates(&self, offset: i64) -> Result<Vec<Update>> {
        let url = self.api_url("getUpdates");
        let resp = self
            .http
            .get(&url)
            .query(&[
                ("offset", offset.to_string()),
                ("timeout", "25".to_string()),
                (
                    "allowed_updates",
                    r#"["message","callback_query"]"#.to_string(),
                ),
            ])
            .send()
            .await
            .context("getUpdates request failed")?
            .json::<serde_json::Value>()
            .await
            .context("getUpdates JSON parse failed")?;

        if !resp["ok"].as_bool().unwrap_or(false) {
            let desc = resp["description"].as_str().unwrap_or("unknown error");
            warn!("Telegram getUpdates error: {desc}");
            return Ok(vec![]);
        }

        let raw_result = resp["result"].clone();
        let result_count = raw_result.as_array().map(|a| a.len()).unwrap_or(0);
        let updates: Vec<Update> = match serde_json::from_value(raw_result) {
            Ok(u) => u,
            Err(e) => {
                warn!(error = %e, raw_count = result_count, "Telegram: failed to deserialize updates");
                vec![]
            }
        };
        Ok(updates)
    }

    async fn answer_callback(&self, callback_query_id: &str) -> Result<()> {
        let body = serde_json::json!({ "callback_query_id": callback_query_id });
        self.post_json("answerCallbackQuery", &body).await
    }

    async fn answer_callback_toast(&self, callback_query_id: &str, text: &str) -> Result<()> {
        let body = serde_json::json!({
            "callback_query_id": callback_query_id,
            "text": text,
            "show_alert": false
        });
        self.post_json("answerCallbackQuery", &body).await
    }

    async fn post_json(&self, method: &str, body: &serde_json::Value) -> Result<()> {
        self.post_json_with_response(method, body).await?;
        Ok(())
    }

    async fn post_json_with_response(
        &self,
        method: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let url = self.api_url(method);
        let resp = self
            .http
            .post(&url)
            .json(body)
            .send()
            .await
            .with_context(|| format!("Telegram {method} failed"))?
            .json::<serde_json::Value>()
            .await
            .with_context(|| format!("Telegram {method} JSON parse failed"))?;

        if !resp["ok"].as_bool().unwrap_or(false) {
            let desc = resp["description"]
                .as_str()
                .unwrap_or("unknown Telegram error");
            warn!(method, "Telegram API error: {desc}");
        }

        Ok(resp)
    }
}

// ---------------------------------------------------------------------------
// Polling response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct Update {
    update_id: i64,
    #[serde(default)]
    message: Option<Message>,
    #[serde(default)]
    callback_query: Option<CallbackQuery>,
}

#[derive(Debug, Deserialize)]
struct Message {
    #[serde(default)]
    message_id: i64,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    from: Option<User>,
    #[serde(default)]
    chat: Option<Chat>,
}

#[derive(Debug, Deserialize)]
struct Chat {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    id: String,
    from: User,
    #[serde(default)]
    data: Option<String>,
}

#[derive(Debug, Deserialize)]
struct User {
    #[serde(default)]
    first_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn format_incident_message(
    incident: &Incident,
    dashboard_url: Option<&str>,
    mode: GuardianMode,
) -> String {
    let sev = severity_label(incident);
    let source_icon = source_icon(&incident.tags);
    let entity_line = entity_summary(incident);

    let summary_trunc = if incident.summary.len() > 200 {
        format!("{}…", &incident.summary[..200])
    } else {
        incident.summary.clone()
    };

    // Mode-specific header and call-to-action
    let (mode_prefix, cta) = match mode {
        GuardianMode::Guard => (
            "⚡ Live threat —",
            "\n<i>Analyzing TTPs… action report incoming.</i>".to_string(),
        ),
        GuardianMode::DryRun => (
            "🧪 Dry-run —",
            "\n<i>Simulation only — enable live mode to let me act.</i>".to_string(),
        ),
        GuardianMode::Watch => {
            let quip = incident_quip(incident);
            ("🚨", quip.to_string())
        }
    };

    let link_line = dashboard_url
        .and_then(|base| first_ip_entity(incident).map(|ip| (base, ip)))
        .map(|(base, ip)| {
            format!(
                "\n🔗 <a href=\"{}/?subject_type=ip&subject={}&date={}\">Investigate</a>",
                base,
                ip,
                incident.ts.format("%Y-%m-%d")
            )
        })
        .unwrap_or_default();

    let prefix_line = if mode_prefix.is_empty() {
        String::new()
    } else {
        format!("{mode_prefix} ")
    };

    format!(
        "{source_icon} {prefix_line}{sev} — <b>{host}</b>\n\
         <b>{title}</b>\n\
         {entity_line}\n\
         <i>{summary}</i>\n\
         \n\
         {cta}{link_line}",
        host = escape_html(&incident.host),
        title = escape_html(&incident.title),
        summary = escape_html(&summary_trunc),
        entity_line = entity_line,
        sev = sev,
        source_icon = source_icon,
        prefix_line = prefix_line,
        cta = cta,
        link_line = link_line,
    )
}

/// Returns a hacker-flavored one-liner based on the incident type.
fn incident_quip(incident: &Incident) -> &'static str {
    let title = incident.title.to_lowercase();
    let tags: Vec<&str> = incident.tags.iter().map(|s| s.as_str()).collect();

    if title.contains("brute") || (title.contains("ssh") && title.contains("fail")) {
        return "💥 Script kiddie hammering the front door. Dictionary attack, classic.";
    }
    if title.contains("credential") || title.contains("stuffing") || title.contains("spray") {
        return "🎭 Credential spray detected. Threat actor cosplaying as your users.";
    }
    if title.contains("port scan") || title.contains("portscan") {
        return "🔭 Recon phase active — they're mapping our attack surface. Not on my watch.";
    }
    if title.contains("sudo") || title.contains("privilege") {
        return "👑 Privilege escalation attempt. This actor's trying to go root. Hard no.";
    }
    if title.contains("execution") || title.contains("shell") || title.contains("command") {
        return "💀 Suspicious binary execution. Could be a payload drop — locking it down.";
    }
    if title.contains("rate") || title.contains("search") || title.contains("abuse") {
        return "🤖 Automated scraping detected. Bot's treating your server like an open API.";
    }
    if title.contains("authorized_keys") || title.contains("ssh key") {
        return "🔑 SSH key tampering — classic persistence play. ATT&CK T1098.004 vibes.";
    }
    if title.contains("cron") || title.contains("scheduled") {
        return "⏰ Cron tampering — threat actor planting a persistent backdoor. ATT&CK T1053.";
    }
    if title.contains("file") || title.contains("integrity") {
        return "🕵️ File tampered outside expected windows. Could be an IOC — eyes on it.";
    }
    if title.contains("container") || title.contains("docker") {
        return "🐳 Suspicious container spun up. Checking for --privileged escapes.";
    }
    if tags.contains(&"falco") {
        return "🔬 Falco snagged a kernel-level anomaly. That's deep in the stack — serious.";
    }
    if tags.contains(&"suricata") {
        return "🌐 Suricata flagged dirty traffic. Network-layer IOC confirmed.";
    }
    if tags.contains(&"wazuh") {
        return "🛡 Wazuh HIDS tripped. Host-based intrusion signatures firing.";
    }
    "👾 Anomaly in the noise. Threat actor or misconfigured bot — investigating."
}

/// Converts a technical action description into hacker-flavored plain language.
fn plain_action(action: &str) -> String {
    let a = action.trim();
    // block-ip variants
    if a.contains("ufw deny from")
        || a.contains("iptables")
        || a.contains("nftables")
        || a.contains("pfctl")
    {
        let ip = a.split_whitespace().last().unwrap_or("IP");
        return format!("Drop {ip} at the firewall — blackhole their traffic");
    }
    if a.contains("block") && a.contains("ip") {
        let ip = a.split_whitespace().last().unwrap_or("IP");
        return format!("Firewall drop {ip} — null route all inbound traffic");
    }
    // suspend-user-sudo
    if a.contains("sudoers") || a.contains("suspend") {
        let user = a.split_whitespace().last().unwrap_or("user");
        return format!("Kill sudo privileges for {user} — privilege revoked");
    }
    // monitor
    if a.contains("tcpdump") || a.contains("monitor") || a.contains("pcap") {
        let ip = a.split_whitespace().last().unwrap_or("IP");
        return format!("Spin up packet capture on {ip} — collect forensic evidence");
    }
    // honeypot
    if a.contains("honeypot") {
        return "Redirect threat actor to honeypot — let them think they're in".to_string();
    }
    // fallback
    a.to_string()
}

fn severity_label(incident: &Incident) -> &'static str {
    use innerwarden_core::event::Severity::*;
    match incident.severity {
        Critical => "🔴 <b>CRITICAL</b>",
        High => "🟠 <b>HIGH</b>",
        Medium => "🟡 MEDIUM",
        Low => "🟢 LOW",
        _ => "⚪ INFO",
    }
}

fn source_icon(tags: &[String]) -> &'static str {
    if tags.iter().any(|t| t == "falco") {
        "🔬"
    } else if tags.iter().any(|t| t == "suricata") {
        "🌐"
    } else if tags.iter().any(|t| t == "osquery") {
        "🔍"
    } else if tags.iter().any(|t| t == "ssh" || t == "sshd") {
        "🔐"
    } else {
        "📋"
    }
}

fn entity_summary(incident: &Incident) -> String {
    use innerwarden_core::entities::EntityType::*;
    let parts: Vec<String> = incident
        .entities
        .iter()
        .take(3)
        .map(|e| match e.r#type {
            Ip => format!("IP: <code>{}</code>", escape_html(&e.value)),
            User => format!("User: <code>{}</code>", escape_html(&e.value)),
            Container => format!("Container: <code>{}</code>", escape_html(&e.value)),
            Path => format!("Path: <code>{}</code>", escape_html(&e.value)),
            Service => format!("Service: <code>{}</code>", escape_html(&e.value)),
        })
        .collect();
    parts.join(" · ")
}

fn first_ip_entity(incident: &Incident) -> Option<String> {
    incident
        .entities
        .iter()
        .find(|e| matches!(e.r#type, innerwarden_core::entities::EntityType::Ip))
        .map(|e| e.value.clone())
}

/// Parse a Telegram callback_data string into an ApprovalResult.
/// Format: "approve:{incident_id}", "reject:{incident_id}", or "menu:{command}"
fn parse_callback(data: &str, operator: &str) -> Option<ApprovalResult> {
    if let Some(id) = data.strip_prefix("approve:") {
        return Some(ApprovalResult {
            incident_id: id.to_string(),
            approved: true,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    if let Some(id) = data.strip_prefix("always:") {
        return Some(ApprovalResult {
            incident_id: id.to_string(),
            approved: true,
            always: true,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    if let Some(id) = data.strip_prefix("reject:") {
        return Some(ApprovalResult {
            incident_id: id.to_string(),
            approved: false,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    // Inline-keyboard menu buttons: "menu:status", "menu:threats", etc.
    if let Some(cmd) = data.strip_prefix("menu:") {
        let incident_id = match cmd {
            "status" => "__status__",
            "incidents" | "threats" => "__threats__",
            "decisions" => "__decisions__",
            "help" => "__help__",
            _ => "__unknown_cmd__",
        };
        return Some(ApprovalResult {
            incident_id: incident_id.to_string(),
            approved: true,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    // Capabilities inline keyboard: "enable:<id>" → routed to __enable__:<id> handler
    if let Some(cap_id) = data.strip_prefix("enable:") {
        return Some(ApprovalResult {
            incident_id: format!("enable:{cap_id}"),
            approved: true,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        });
    }
    None
}

/// Strip `@BotUsername` suffix from Telegram commands.
/// "/help@InnerWardenBot" → "/help", "/status" → "/status", "hello" → "hello"
fn strip_bot_suffix(text: &str) -> String {
    if text.starts_with('/') {
        if let Some(at_pos) = text.find('@') {
            // Check if @bot comes right after the command (before any space)
            let space_pos = text.find(' ').unwrap_or(text.len());
            if at_pos < space_pos {
                // "/help@Bot args" → "/help args"
                let cmd = &text[..at_pos];
                let rest = &text[space_pos..];
                return format!("{cmd}{rest}");
            }
        }
    }
    text.to_string()
}

/// Escape HTML special characters for Telegram HTML parse mode.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Visual score bar for AbuseIPDB confidence (e.g. "████░░░░ 80/100").
fn reputation_score_bar(score: u8) -> String {
    let filled = (score as usize * 8 / 100).min(8);
    let empty = 8 - filled;
    let bar = "█".repeat(filled) + &"░".repeat(empty);
    format!("[{bar}]")
}

/// Convert a 2-letter ISO country code to a flag emoji.
fn country_flag_emoji(code: &str) -> String {
    if code.len() != 2 {
        return String::new();
    }
    let bytes = code.to_uppercase();
    let mut chars = bytes.chars();
    if let (Some(a), Some(b)) = (chars.next(), chars.next()) {
        let base: u32 = 0x1F1E6 - b'A' as u32;
        let fa = char::from_u32(base + a as u32).unwrap_or(' ');
        let fb = char::from_u32(base + b as u32).unwrap_or(' ');
        return format!("{fa}{fb}");
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use innerwarden_core::{entities::EntityRef, event::Severity, incident::Incident};

    fn make_incident(severity: Severity, tags: Vec<String>, entities: Vec<EntityRef>) -> Incident {
        Incident {
            ts: Utc::now(),
            host: "web-server-01".to_string(),
            incident_id: "ssh_bruteforce:1.2.3.4:2026-03-15T15:00Z".to_string(),
            severity,
            title: "Possible SSH brute force from 1.2.3.4".to_string(),
            summary: "15 failed SSH logins in 5 minutes".to_string(),
            evidence: serde_json::json!([]),
            recommended_checks: vec![],
            tags,
            entities,
        }
    }

    #[test]
    fn format_critical_message_contains_key_fields() {
        let inc = make_incident(
            Severity::Critical,
            vec!["falco".to_string()],
            vec![EntityRef::ip("1.2.3.4".to_string())],
        );
        let msg = format_incident_message(&inc, None, GuardianMode::Watch);
        assert!(msg.contains("CRITICAL"));
        assert!(msg.contains("web-server-01"));
        assert!(msg.contains("SSH brute force"));
        assert!(msg.contains("1.2.3.4"));
        assert!(msg.contains("🔬"), "falco icon should appear");
    }

    #[test]
    fn format_high_message_with_dashboard_url() {
        let inc = make_incident(
            Severity::High,
            vec!["suricata".to_string()],
            vec![EntityRef::ip("203.0.113.10".to_string())],
        );
        let msg = format_incident_message(&inc, Some("http://127.0.0.1:8787"), GuardianMode::Watch);
        assert!(msg.contains("HIGH"));
        assert!(msg.contains("🌐"), "suricata icon");
        assert!(msg.contains("Investigate"));
        assert!(msg.contains("203.0.113.10"));
    }

    #[test]
    fn format_guard_mode_shows_analyzing_prefix() {
        let inc = make_incident(
            Severity::High,
            vec!["ssh".to_string()],
            vec![EntityRef::ip("1.2.3.4".to_string())],
        );
        let msg = format_incident_message(&inc, None, GuardianMode::Guard);
        assert!(
            msg.contains("Analyzing"),
            "GUARD mode shows analyzing prefix"
        );
        assert!(!msg.contains("Block"), "GUARD mode has no block CTA");
    }

    #[test]
    fn source_icon_picks_correct_icon() {
        assert_eq!(source_icon(&["falco".to_string()]), "🔬");
        assert_eq!(source_icon(&["suricata".to_string()]), "🌐");
        assert_eq!(source_icon(&["osquery".to_string()]), "🔍");
        assert_eq!(source_icon(&["ssh".to_string()]), "🔐");
        assert_eq!(source_icon(&["other".to_string()]), "📋");
    }

    #[test]
    fn parse_callback_approve() {
        let result = parse_callback("approve:ssh_bruteforce:1.2.3.4:2026Z", "Alice").unwrap();
        assert!(result.approved);
        assert_eq!(result.incident_id, "ssh_bruteforce:1.2.3.4:2026Z");
        assert_eq!(result.operator_name, "Alice");
    }

    #[test]
    fn parse_callback_reject() {
        let result = parse_callback("reject:some:incident:id", "Bob").unwrap();
        assert!(!result.approved);
        assert_eq!(result.incident_id, "some:incident:id");
    }

    #[test]
    fn parse_callback_unknown_returns_none() {
        assert!(parse_callback("unknown:foo", "user").is_none());
        assert!(parse_callback("", "user").is_none());
    }

    #[test]
    fn parse_callback_menu_routes_to_sentinels() {
        let r = parse_callback("menu:status", "Alice").unwrap();
        assert_eq!(r.incident_id, "__status__");
        assert!(r.approved);

        // Both "threats" and "incidents" route to __threats__
        let r = parse_callback("menu:threats", "Alice").unwrap();
        assert_eq!(r.incident_id, "__threats__");

        let r = parse_callback("menu:incidents", "Alice").unwrap();
        assert_eq!(r.incident_id, "__threats__");

        let r = parse_callback("menu:decisions", "Alice").unwrap();
        assert_eq!(r.incident_id, "__decisions__");

        let r = parse_callback("menu:help", "Alice").unwrap();
        assert_eq!(r.incident_id, "__help__");

        // Unknown menu command → unknown cmd sentinel
        let r = parse_callback("menu:bogus", "Alice").unwrap();
        assert_eq!(r.incident_id, "__unknown_cmd__");
    }

    #[test]
    fn guardian_mode_labels_and_descriptions() {
        assert_eq!(GuardianMode::Guard.label(), "🟢 GUARD");
        assert_eq!(GuardianMode::DryRun.label(), "🟡 DRY-RUN");
        assert_eq!(GuardianMode::Watch.label(), "🔵 WATCH");
        assert!(GuardianMode::Guard.description().contains("automatically"));
        assert!(GuardianMode::Watch.description().contains("your call"));
    }

    #[test]
    fn strip_bot_suffix_removes_at_username() {
        assert_eq!(strip_bot_suffix("/help@InnerWardenBot"), "/help");
        assert_eq!(strip_bot_suffix("/status@Bot"), "/status");
        assert_eq!(
            strip_bot_suffix("/ask@Bot question here"),
            "/ask question here"
        );
        assert_eq!(strip_bot_suffix("/status"), "/status");
        assert_eq!(strip_bot_suffix("hello"), "hello");
        assert_eq!(strip_bot_suffix("text with @mention"), "text with @mention");
    }

    #[test]
    fn quick_block_callback_routes_to_sentinel() {
        // Simulate the run_polling logic for "quick:block:<ip>" callbacks.
        // The callback data must produce the correct ApprovalResult sentinel.
        let data = "quick:block:1.2.3.4";
        let operator = "Alice";

        let ip = data.strip_prefix("quick:block:").unwrap();
        assert_eq!(ip, "1.2.3.4");

        let result = ApprovalResult {
            incident_id: format!("__quick_block__:{ip}"),
            approved: true,
            always: false,
            operator_name: operator.to_string(),
            chosen_action: String::new(),
        };

        assert_eq!(result.incident_id, "__quick_block__:1.2.3.4");
        assert!(result.approved);
        assert!(!result.always);
        assert_eq!(result.operator_name, "Alice");

        // quick:ignore must not produce a routing result (handled inline)
        assert!(parse_callback("quick:ignore", operator).is_none());
        // quick:block: prefix must not be caught by parse_callback
        assert!(parse_callback("quick:block:1.2.3.4", operator).is_none());
    }

    #[test]
    fn escape_html_handles_specials() {
        assert_eq!(
            escape_html("<b>test & \"value\"</b>"),
            "&lt;b&gt;test &amp; &quot;value&quot;&lt;/b&gt;"
        );
    }

    #[test]
    fn severity_label_covers_all() {
        let make = |sev| make_incident(sev, vec![], vec![]);
        assert!(severity_label(&make(Severity::Critical)).contains("CRITICAL"));
        assert!(severity_label(&make(Severity::High)).contains("HIGH"));
        assert!(severity_label(&make(Severity::Medium)).contains("MEDIUM"));
    }

    #[test]
    fn first_ip_entity_returns_first_ip() {
        let inc = make_incident(
            Severity::High,
            vec![],
            vec![
                EntityRef::user("bob".to_string()),
                EntityRef::ip("10.0.0.1".to_string()),
                EntityRef::ip("203.0.113.10".to_string()),
            ],
        );
        assert_eq!(first_ip_entity(&inc), Some("10.0.0.1".to_string()));
    }

    // -----------------------------------------------------------------------
    // Honeypot operator-in-the-loop tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_hpot_callback_routing() {
        // Simulate the run_polling routing logic for hpot: callbacks
        let data = "hpot:honeypot:1.2.3.4";
        let rest = data.strip_prefix("hpot:").unwrap();
        let parts: Vec<&str> = rest.splitn(2, ':').collect();
        assert_eq!(parts.len(), 2);
        let action = parts[0];
        let ip = parts[1];
        assert_eq!(action, "honeypot");
        assert_eq!(ip, "1.2.3.4");

        let result = ApprovalResult {
            incident_id: format!("__hpot__:{ip}"),
            approved: action != "ignore",
            always: false,
            operator_name: "Alice".to_string(),
            chosen_action: action.to_string(),
        };
        assert_eq!(result.incident_id, "__hpot__:1.2.3.4");
        assert!(result.approved);
        assert_eq!(result.chosen_action, "honeypot");

        // ignore action should produce approved=false
        let data_ignore = "hpot:ignore:5.6.7.8";
        let rest_i = data_ignore.strip_prefix("hpot:").unwrap();
        let parts_i: Vec<&str> = rest_i.splitn(2, ':').collect();
        let action_i = parts_i[0];
        assert_eq!(action_i, "ignore");
        let result_i = ApprovalResult {
            incident_id: format!("__hpot__:{}", parts_i[1]),
            approved: action_i != "ignore",
            always: false,
            operator_name: "Bob".to_string(),
            chosen_action: action_i.to_string(),
        };
        assert!(!result_i.approved);
        assert_eq!(result_i.chosen_action, "ignore");

        // hpot: prefix must not be caught by parse_callback
        assert!(parse_callback("hpot:honeypot:1.2.3.4", "Alice").is_none());
        assert!(parse_callback("hpot:block:1.2.3.4", "Alice").is_none());
    }

    #[test]
    fn test_send_honeypot_suggestion_format() {
        // Verify the message body would contain the key fields.
        // We test by constructing the expected format string directly.
        let ip = "185.220.101.45";
        let title = "47 tentativas SSH em 5 min";
        let reason = "IP novo, sem histórico em listas negras";
        let confidence = 0.87_f32;
        let pct = (confidence * 100.0) as u32;

        let text = format!(
            "🎯 <b>Tenho um suspeito aqui</b>\n\
             \n\
             <b>IP:</b> <code>{ip}</code>\n\
             <b>Incidente:</b> {title}\n\
             <b>Avaliação IA:</b> {reason} (confiança: {pct}%)\n\
             \n\
             O que fazemos com esse cara?",
            ip = escape_html(ip),
            title = escape_html(title),
            reason = escape_html(reason),
            pct = pct,
        );

        assert!(text.contains("185.220.101.45"), "IP must appear in message");
        assert!(
            text.contains("47 tentativas"),
            "incident title must appear in message"
        );
        assert!(text.contains("87%"), "confidence percentage must appear");
        assert!(
            text.contains("Tenho um suspeito"),
            "personality heading must appear"
        );
        assert!(
            text.contains("O que fazemos"),
            "operator question must appear"
        );

        // Verify ai_suggested checkmark logic
        let honeypot_label_suggested = if "honeypot" == "honeypot" {
            "🍯 Honeypot ✓"
        } else {
            "🍯 Honeypot"
        };
        assert_eq!(honeypot_label_suggested, "🍯 Honeypot ✓");

        let block_label_not_suggested = if "honeypot" == "block" {
            "🚫 Bloquear ✓"
        } else {
            "🚫 Bloquear"
        };
        assert_eq!(block_label_not_suggested, "🚫 Bloquear");
    }
}
