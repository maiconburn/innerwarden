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
    ) -> Result<()> {
        let pct = (confidence * 100.0) as u32;
        let text = if dry_run {
            format!(
                "🧪 <b>DRY RUN</b> — <b>{host}</b>\n\
                 Would have {action_label} <code>{target}</code>\n\
                 <i>{incident_title}</i>\n\
                 Confidence: {pct}%",
                host = escape_html(host),
                action_label = action_label,
                target = escape_html(target),
                incident_title = escape_html(incident_title),
            )
        } else {
            format!(
                "✅ <b>Done</b> — <b>{host}</b>\n\
                 {action_label} <code>{target}</code>\n\
                 <i>{incident_title}</i>\n\
                 Confidence: {pct}%",
                host = escape_html(host),
                action_label = action_label,
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
            "All quiet today — no threats detected.".to_string()
        } else {
            format!(
                "Today: <b>{incident_count}</b> threat{} detected, <b>{decision_count}</b> action{}.",
                if incident_count == 1 { "" } else { "s" },
                if decision_count == 1 { "" } else { "s" },
            )
        };

        let text = format!(
            "🛡 Hey! I'm <b>InnerWarden</b>, your server's security guardian.\n\
             Watching <b>{host}</b> right now.\n\
             \n\
             {today_line}\n\
             \n\
             Mode: {mode_label}\n\
             <i>{mode_desc}</i>\n\
             \n\
             Ask me anything or use the buttons below.",
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
                { "command": "status",    "description": "How am I doing? Mode, AI, today's summary" },
                { "command": "threats",   "description": "Recent threats detected" },
                { "command": "decisions", "description": "Recent actions taken" },
                { "command": "blocked",   "description": "Currently blocked IPs" },
                { "command": "guard",     "description": "Activate auto-defend mode" },
                { "command": "watch",     "description": "Switch to monitor-only mode" },
                { "command": "ask",       "description": "Ask me anything about your server" },
                { "command": "help",      "description": "What can I do?" }
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
                                            "👍 Noted — monitoring continues",
                                        )
                                        .await;
                                } else if let Some(ip) = data.strip_prefix("quick:block:") {
                                    let ip = ip.to_string();
                                    let _ = self
                                        .answer_callback_toast(
                                            &callback.id,
                                            &format!("🛡 Queuing block for {ip}..."),
                                        )
                                        .await;
                                    let result = ApprovalResult {
                                        incident_id: format!("__quick_block__:{ip}"),
                                        approved: true,
                                        always: false,
                                        operator_name: operator.clone(),
                                    };
                                    if approval_tx.send(result).await.is_err() {
                                        return;
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
            "⚡ Analyzing…",
            String::new(), // No CTA — action report will follow
        ),
        GuardianMode::DryRun => (
            "🧪 Dry-run mode —",
            "\n<i>No real action taken — configure responder to go live</i>".to_string(),
        ),
        GuardianMode::Watch => {
            let quip = incident_quip(incident);
            ("", quip.to_string())
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
}
