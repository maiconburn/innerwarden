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
use tracing::{debug, warn};

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
    /// Failures are logged as warnings and never propagate — fail-open.
    pub async fn send_incident_alert(&self, incident: &Incident) -> Result<()> {
        let text = format_incident_message(incident, self.dashboard_url.as_deref());

        let mut body = serde_json::json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
        });

        // Add a deep-link button if dashboard URL is configured
        if let Some(ref base_url) = self.dashboard_url {
            if let Some(ip) = first_ip_entity(incident) {
                let link = format!(
                    "{base_url}/?subject_type=ip&subject={ip}&date={}",
                    incident.ts.format("%Y-%m-%d")
                );
                body["reply_markup"] = serde_json::json!({
                    "inline_keyboard": [[{
                        "text": "🔍 Investigate in dashboard",
                        "url": link
                    }]]
                });
            }
        }

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
            90..=100 => "I'm very confident about this",
            75..=89 => "I'm fairly confident about this",
            60..=74 => "I think this is the right call",
            _ => "not 100% sure, but leaning toward this",
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
             🤖 {confidence_phrase}. Suggested action:\n\
             <b>{action_plain}</b>\n\
             \n\
             Your call — {expires_label} to decide.",
            host = escape_html(&incident.host),
            title = escape_html(&incident.title),
            action_plain = escape_html(&action_plain),
            entity_line = entity_line,
            sev = sev,
            source_icon = source_icon,
            confidence_phrase = confidence_phrase,
            expires_label = expires_label,
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

        // Send follow-up result message with personality
        let text = if always {
            format!("🔁 Got it, {operator}. I'll handle this automatically from now on. No need to ask.", operator = escape_html(operator))
        } else if approved {
            format!(
                "✅ Done. Executed on {operator}'s orders. They won't bother us again.",
                operator = escape_html(operator)
            )
        } else {
            format!(
                "❌ Standing down. {operator} said let it slide. I'll keep watching.",
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
                        { "text": "🚨 Incidents", "callback_data": "menu:incidents" }
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
                    for update in updates {
                        offset = update.update_id + 1;

                        if let Some(callback) = update.callback_query {
                            let operator = callback
                                .from
                                .first_name
                                .clone()
                                .unwrap_or_else(|| "unknown".to_string());

                            if let Some(data) = &callback.data {
                                // Answer the callback immediately to remove the spinner
                                let _ = self.answer_callback(&callback.id).await;
                                if let Some(result) = parse_callback(data, &operator) {
                                    if approval_tx.send(result).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }

                        // Handle text commands and free-form messages
                        if let Some(msg) = update.message {
                            if let Some(text) = &msg.text {
                                let text = text.trim().to_string();
                                let operator = msg
                                    .from
                                    .as_ref()
                                    .and_then(|f| f.first_name.clone())
                                    .unwrap_or_default();

                                let incident_id = if text == "/status"
                                    || text.starts_with("/status ")
                                {
                                    debug!("Telegram /status command received");
                                    "__status__".to_string()
                                } else if text == "/help" || text.starts_with("/help ") {
                                    "__help__".to_string()
                                } else if text == "/menu" || text.starts_with("/menu ") {
                                    "__menu__".to_string()
                                } else if text == "/incidents" || text.starts_with("/incidents ") {
                                    "__incidents__".to_string()
                                } else if text == "/decisions" || text.starts_with("/decisions ") {
                                    "__decisions__".to_string()
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

        let updates: Vec<Update> =
            serde_json::from_value(resp["result"].clone()).unwrap_or_default();
        Ok(updates)
    }

    async fn answer_callback(&self, callback_query_id: &str) -> Result<()> {
        let body = serde_json::json!({ "callback_query_id": callback_query_id });
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
    text: Option<String>,
    #[serde(default)]
    from: Option<User>,
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

fn format_incident_message(incident: &Incident, dashboard_url: Option<&str>) -> String {
    let sev = severity_label(incident);
    let source_icon = source_icon(&incident.tags);
    let entity_line = entity_summary(incident);
    let quip = incident_quip(incident);

    let summary_trunc = if incident.summary.len() > 200 {
        format!("{}…", &incident.summary[..200])
    } else {
        incident.summary.clone()
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

    format!(
        "{source_icon} {sev} — <b>{host}</b>\n\
         <b>{title}</b>\n\
         {entity_line}\n\
         <i>{summary}</i>\n\
         \n\
         {quip}{link_line}",
        host = escape_html(&incident.host),
        title = escape_html(&incident.title),
        summary = escape_html(&summary_trunc),
        entity_line = entity_line,
        sev = sev,
        source_icon = source_icon,
        quip = quip,
        link_line = link_line,
    )
}

/// Returns a snarky one-liner based on the incident type.
fn incident_quip(incident: &Incident) -> &'static str {
    let title = incident.title.to_lowercase();
    let tags: Vec<&str> = incident.tags.iter().map(|s| s.as_str()).collect();

    if title.contains("brute") || title.contains("ssh") {
        return "🧱 Script kiddie found the door. On it.";
    }
    if title.contains("credential") || title.contains("stuffing") || title.contains("spray") {
        return "🎭 Someone's cosplaying as your users. Not for long.";
    }
    if title.contains("port scan") || title.contains("portscan") {
        return "🔭 They're window shopping. Let's close the blinds.";
    }
    if title.contains("sudo") || title.contains("privilege") {
        return "👑 Someone's reaching for the crown. Hard no.";
    }
    if title.contains("execution") || title.contains("shell") || title.contains("command") {
        return "💀 That command had bad news written all over it.";
    }
    if title.contains("rate") || title.contains("search") || title.contains("abuse") {
        return "🤖 Bot party detected. Bouncer mode: engaged.";
    }
    if title.contains("file") || title.contains("integrity") {
        return "🕵️ Someone touched what they shouldn't have.";
    }
    if tags.contains(&"falco") {
        return "🔬 Falco caught something spicy in the kernel.";
    }
    if tags.contains(&"suricata") {
        return "🌐 Network IDS flagged it. Dirty traffic incoming.";
    }
    "👀 Something's off. Eyes on this one."
}

/// Converts a technical action description into plain language.
fn plain_action(action: &str) -> String {
    let a = action.trim();
    // block-ip variants
    if a.contains("ufw deny from")
        || a.contains("iptables")
        || a.contains("nftables")
        || a.contains("pfctl")
    {
        let ip = a.split_whitespace().last().unwrap_or("IP");
        return format!("Block {ip} at the firewall");
    }
    if a.contains("block") && a.contains("ip") {
        let ip = a.split_whitespace().last().unwrap_or("IP");
        return format!("Block {ip} at the firewall");
    }
    // suspend-user-sudo
    if a.contains("sudoers") || a.contains("suspend") {
        let user = a.split_whitespace().last().unwrap_or("user");
        return format!("Suspend sudo access for {user}");
    }
    // monitor
    if a.contains("tcpdump") || a.contains("monitor") || a.contains("pcap") {
        let ip = a.split_whitespace().last().unwrap_or("IP");
        return format!("Capture traffic from {ip} for analysis");
    }
    // honeypot
    if a.contains("honeypot") {
        return "Redirect attacker to honeypot".to_string();
    }
    // fallback: show as-is but clean up
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
        });
    }
    if let Some(id) = data.strip_prefix("always:") {
        return Some(ApprovalResult {
            incident_id: id.to_string(),
            approved: true,
            always: true,
            operator_name: operator.to_string(),
        });
    }
    if let Some(id) = data.strip_prefix("reject:") {
        return Some(ApprovalResult {
            incident_id: id.to_string(),
            approved: false,
            always: false,
            operator_name: operator.to_string(),
        });
    }
    // Inline-keyboard menu buttons: "menu:status", "menu:incidents", etc.
    if let Some(cmd) = data.strip_prefix("menu:") {
        let incident_id = match cmd {
            "status" => "__status__",
            "incidents" => "__incidents__",
            "decisions" => "__decisions__",
            "help" => "__help__",
            _ => "__unknown_cmd__",
        };
        return Some(ApprovalResult {
            incident_id: incident_id.to_string(),
            approved: true,
            always: false,
            operator_name: operator.to_string(),
        });
    }
    None
}

/// Escape HTML special characters for Telegram HTML parse mode.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
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
        let msg = format_incident_message(&inc, None);
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
        let msg = format_incident_message(&inc, Some("http://127.0.0.1:8787"));
        assert!(msg.contains("HIGH"));
        assert!(msg.contains("🌐"), "suricata icon");
        assert!(msg.contains("Investigate"));
        assert!(msg.contains("203.0.113.10"));
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

        let r = parse_callback("menu:incidents", "Alice").unwrap();
        assert_eq!(r.incident_id, "__incidents__");

        let r = parse_callback("menu:decisions", "Alice").unwrap();
        assert_eq!(r.incident_id, "__decisions__");

        let r = parse_callback("menu:help", "Alice").unwrap();
        assert_eq!(r.incident_id, "__help__");

        // Unknown menu command → unknown cmd sentinel
        let r = parse_callback("menu:bogus", "Alice").unwrap();
        assert_eq!(r.incident_id, "__unknown_cmd__");
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
}
