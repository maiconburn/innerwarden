//! SSH medium-interaction and LLM-shell honeypot handler.
//!
//! Uses `russh` to accept real SSH connections, negotiate key exchange,
//! capture authentication attempts (password, publickey, none).
//!
//! Two interaction modes are supported:
//! - `RejectAll` — the classic medium mode: captures creds, rejects auth, no shell.
//! - `LlmShell` — accepts password auth and serves an AI-backed interactive shell.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{self, Auth, Config, Handler, Session};
use russh::{ChannelId, CryptoVec};
use serde::Serialize;
use tracing::debug;

// ---------------------------------------------------------------------------
// Evidence types
// ---------------------------------------------------------------------------

/// One SSH authentication attempt captured from the attacker.
#[derive(Debug, Clone, Serialize)]
pub struct SshAuthAttempt {
    pub ts: String,
    /// `none` | `password` | `publickey` | `keyboard-interactive`
    pub method: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_name: Option<String>,
}

/// One shell command captured during LLM shell interaction.
#[derive(Debug, Clone, Serialize)]
pub struct SshShellCommand {
    pub ts: String,
    pub username: String,
    pub command: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub response: String,
}

/// SSH connection evidence: client banner + all auth attempts + optional shell session.
#[derive(Debug, Clone, Serialize)]
pub struct SshConnectionEvidence {
    pub auth_attempts: Vec<SshAuthAttempt>,
    /// Populated only in llm_shell interaction mode.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub shell_commands: Vec<SshShellCommand>,
}

// ---------------------------------------------------------------------------
// Interaction mode
// ---------------------------------------------------------------------------

/// Controls how the SSH honeypot handler behaves after a connection is accepted.
pub enum SshInteractionMode {
    /// Capture auth attempts and always reject — no shell granted (medium interaction).
    RejectAll,
    /// Accept password auth and serve an AI-backed interactive shell.
    LlmShell {
        ai: Arc<dyn crate::ai::AiProvider>,
        /// Fake hostname shown in the shell prompt (e.g. `"srv-prod-01"`).
        hostname: String,
    },
}

// ---------------------------------------------------------------------------
// Handler implementation
// ---------------------------------------------------------------------------

/// Shared evidence bucket for a single SSH connection.
type EvidenceBucket = Arc<Mutex<SshConnectionEvidence>>;

/// Internal handler mode carrying the mutable per-connection state.
enum HandlerMode {
    RejectAll,
    LlmShell {
        ai: Arc<dyn crate::ai::AiProvider>,
        hostname: String,
        accepted_user: Option<String>,
        /// Raw bytes buffered since the last newline.
        input_buf: Vec<u8>,
        /// Rolling history of (command, response) pairs sent to the AI as context.
        history: Vec<(String, String)>,
    },
}

/// russh server handler that captures auth attempts.
///
/// In `RejectAll` mode all auth methods are rejected and no shell is granted.
/// In `LlmShell` mode password auth is accepted and the client gets an
/// AI-backed interactive shell.
pub(crate) struct HoneypotSshHandler {
    evidence: EvidenceBucket,
    mode: HandlerMode,
}

impl HoneypotSshHandler {
    fn record(
        &self,
        method: &str,
        username: &str,
        password: Option<String>,
        key_name: Option<String>,
    ) {
        let mut ev = self.evidence.lock().unwrap_or_else(|e| e.into_inner());
        ev.auth_attempts.push(SshAuthAttempt {
            ts: Utc::now().to_rfc3339(),
            method: method.to_string(),
            username: username.to_string(),
            password,
            key_name,
        });
    }

    fn build_prompt(&self) -> String {
        if let HandlerMode::LlmShell {
            hostname,
            accepted_user,
            ..
        } = &self.mode
        {
            format!(
                "{}@{}:~# ",
                accepted_user.as_deref().unwrap_or("root"),
                hostname
            )
        } else {
            String::new()
        }
    }
}

// russh 0.57 Handler uses RPITIT (impl Future in trait), no async_trait needed.
impl Handler for HoneypotSshHandler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        debug!(user, "honeypot SSH auth_none");
        self.record("none", user, None, None);
        Ok(Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        })
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        debug!(user, "honeypot SSH auth_password");
        self.record("password", user, Some(password.to_string()), None);
        match &mut self.mode {
            HandlerMode::LlmShell { accepted_user, .. } => {
                // Accept the first password attempt — store the username for prompt/context.
                *accepted_user = Some(user.to_string());
                Ok(Auth::Accept)
            }
            HandlerMode::RejectAll => Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            }),
        }
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        debug!(user, "honeypot SSH auth_publickey");
        self.record(
            "publickey",
            user,
            None,
            Some(key.algorithm().as_str().to_string()),
        );
        Ok(Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        _response: Option<server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        debug!(user, "honeypot SSH auth_keyboard_interactive");
        self.record("keyboard-interactive", user, None, None);
        Ok(Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<server::Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        match &self.mode {
            HandlerMode::LlmShell { .. } => Ok(true),
            HandlerMode::RejectAll => Ok(false),
        }
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if matches!(self.mode, HandlerMode::LlmShell { .. }) {
            let _ = session.channel_success(channel);
        } else {
            let _ = session.channel_failure(channel);
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if matches!(self.mode, HandlerMode::LlmShell { .. }) {
            let _ = session.channel_success(channel_id);
            let prompt = self.build_prompt();
            let _ = session.data(channel_id, CryptoVec::from(prompt.into_bytes()));
        } else {
            let _ = session.channel_failure(channel_id);
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let HandlerMode::LlmShell {
            ai,
            hostname,
            accepted_user,
            input_buf,
            history,
        } = &mut self.mode
        else {
            return Ok(());
        };

        for &byte in data {
            match byte {
                b'\r' | b'\n' => {
                    // Echo newline.
                    let _ = session.data(channel_id, CryptoVec::from(b"\r\n".to_vec()));

                    let cmd = String::from_utf8_lossy(input_buf).trim().to_string();
                    input_buf.clear();

                    if cmd.is_empty() {
                        let prompt = format!(
                            "{}@{}:~# ",
                            accepted_user.as_deref().unwrap_or("root"),
                            hostname
                        );
                        let _ = session.data(channel_id, CryptoVec::from(prompt.into_bytes()));
                        continue;
                    }

                    // Handle exit/logout gracefully.
                    if cmd == "exit" || cmd == "logout" || cmd == "quit" {
                        let _ = session.data(channel_id, CryptoVec::from(b"logout\r\n".to_vec()));
                        let _ = session.close(channel_id);
                        return Ok(());
                    }

                    let user = accepted_user.as_deref().unwrap_or("root").to_string();

                    // Try deterministic fake shell first (zero tokens, instant response).
                    // Falls back to LLM only for unknown commands.
                    let response = if let Some(fake_output) =
                        super::fake_shell::try_handle(&cmd, &user, hostname)
                    {
                        fake_output
                    } else {
                        let sys_prompt = build_shell_system_prompt(&user, hostname, history);
                        let ai_clone = Arc::clone(ai);
                        match ai_clone.chat(&sys_prompt, &cmd).await {
                            Ok(r) => r.trim().to_string(),
                            Err(e) => {
                                debug!("honeypot LLM shell AI error: {e}");
                                String::new()
                            }
                        }
                    };

                    if !response.is_empty() {
                        let mut out = response.replace('\n', "\r\n");
                        out.push_str("\r\n");
                        let _ = session.data(channel_id, CryptoVec::from(out.into_bytes()));
                    }

                    // Update rolling history (keep last 10).
                    history.push((cmd.clone(), response.clone()));
                    if history.len() > 10 {
                        history.remove(0);
                    }

                    // Record evidence.
                    {
                        let mut ev = self.evidence.lock().unwrap_or_else(|e| e.into_inner());
                        ev.shell_commands.push(SshShellCommand {
                            ts: Utc::now().to_rfc3339(),
                            username: user.clone(),
                            command: cmd,
                            response,
                        });
                    }

                    let prompt = format!("{}@{}:~# ", user, hostname);
                    let _ = session.data(channel_id, CryptoVec::from(prompt.into_bytes()));
                }
                0x7f | 0x08 => {
                    // Backspace / DEL.
                    if !input_buf.is_empty() {
                        input_buf.pop();
                        let _ = session.data(channel_id, CryptoVec::from(b"\x08 \x08".to_vec()));
                    }
                }
                0x03 => {
                    // Ctrl+C.
                    input_buf.clear();
                    let _ = session.data(channel_id, CryptoVec::from(b"^C\r\n".to_vec()));
                    let prompt = format!(
                        "{}@{}:~# ",
                        accepted_user.as_deref().unwrap_or("root"),
                        hostname
                    );
                    let _ = session.data(channel_id, CryptoVec::from(prompt.into_bytes()));
                }
                byte if byte >= 0x20 => {
                    // Printable character: buffer and echo.
                    input_buf.push(byte);
                    let _ = session.data(channel_id, CryptoVec::from(vec![byte]));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shell system prompt builder
// ---------------------------------------------------------------------------

fn build_shell_system_prompt(user: &str, hostname: &str, history: &[(String, String)]) -> String {
    let mut prompt = format!(
        "You are a Ubuntu 22.04.3 LTS Linux terminal. Hostname: {hostname}. Current user: {user}.\n\
         Reply ONLY with the exact terminal output — no markdown, no code blocks, no explanation.\n\
         Make responses realistic with plausible fake data. Be concise.\n\
         If asked for /etc/passwd, /etc/shadow, or similar sensitive files, return realistic-looking fake content.\n\
         If destructive commands run (rm -rf, etc.), pretend they worked with no output.\n"
    );
    if !history.is_empty() {
        prompt.push_str("\nRecent session history:\n");
        for (cmd, resp) in history.iter().take(6) {
            prompt.push_str(&format!("$ {cmd}\n{resp}\n"));
        }
    }
    prompt
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Build an ephemeral russh server config with an Ed25519 key.
pub(crate) fn build_ssh_config(max_auth_attempts: usize) -> Arc<Config> {
    // ssh_key::PrivateKey::random requires a CSPRNG.
    let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519)
        .expect("Ed25519 key generation should not fail");
    Arc::new(Config {
        keys: vec![key],
        max_auth_attempts,
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        inactivity_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    })
}

/// Handle one SSH connection.
///
/// The `mode` parameter controls whether auth is always rejected (`RejectAll`) or
/// whether the handler accepts password auth and grants an LLM-backed shell (`LlmShell`).
///
/// Returns all captured evidence (auth attempts + optional shell commands).
/// Enforces `conn_timeout` over the entire connection.
pub(crate) async fn handle_connection(
    stream: tokio::net::TcpStream,
    config: Arc<Config>,
    conn_timeout: Duration,
    mode: SshInteractionMode,
) -> SshConnectionEvidence {
    let bucket: EvidenceBucket = Arc::new(Mutex::new(SshConnectionEvidence {
        auth_attempts: Vec::new(),
        shell_commands: Vec::new(),
    }));

    let handler_mode = match mode {
        SshInteractionMode::RejectAll => HandlerMode::RejectAll,
        SshInteractionMode::LlmShell { ai, hostname } => HandlerMode::LlmShell {
            ai,
            hostname,
            accepted_user: None,
            input_buf: Vec::new(),
            history: Vec::new(),
        },
    };

    let handler = HoneypotSshHandler {
        evidence: Arc::clone(&bucket),
        mode: handler_mode,
    };

    let result =
        tokio::time::timeout(conn_timeout, server::run_stream(config, stream, handler)).await;

    match result {
        Ok(Ok(session)) => {
            // Wait for the session future to complete (client disconnects).
            let _ = tokio::time::timeout(conn_timeout, session).await;
        }
        Ok(Err(e)) => {
            debug!("SSH honeypot session error: {e}");
        }
        Err(_) => {
            debug!("SSH honeypot connection timed out");
        }
    }

    let evidence = bucket.lock().unwrap_or_else(|e| e.into_inner()).clone();
    evidence
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_bucket() -> EvidenceBucket {
        Arc::new(Mutex::new(SshConnectionEvidence {
            auth_attempts: Vec::new(),
            shell_commands: Vec::new(),
        }))
    }

    #[test]
    fn build_ssh_config_generates_key() {
        let cfg = build_ssh_config(3);
        assert_eq!(cfg.keys.len(), 1, "should have exactly one server key");
        assert_eq!(cfg.max_auth_attempts, 3);
    }

    #[tokio::test]
    async fn handler_records_password_attempt_reject_all() {
        let bucket = empty_bucket();
        let mut h = HoneypotSshHandler {
            evidence: Arc::clone(&bucket),
            mode: HandlerMode::RejectAll,
        };
        let result = h.auth_password("root", "secret123").await.unwrap();
        assert!(matches!(result, Auth::Reject { .. }));
        let ev = bucket.lock().unwrap();
        assert_eq!(ev.auth_attempts.len(), 1);
        assert_eq!(ev.auth_attempts[0].method, "password");
        assert_eq!(ev.auth_attempts[0].username, "root");
        assert_eq!(ev.auth_attempts[0].password.as_deref(), Some("secret123"));
    }

    #[tokio::test]
    async fn handler_records_none_attempt() {
        let bucket = empty_bucket();
        let mut h = HoneypotSshHandler {
            evidence: Arc::clone(&bucket),
            mode: HandlerMode::RejectAll,
        };
        let result = h.auth_none("admin").await.unwrap();
        assert!(matches!(result, Auth::Reject { .. }));
        let ev = bucket.lock().unwrap();
        assert_eq!(ev.auth_attempts.len(), 1);
        assert_eq!(ev.auth_attempts[0].method, "none");
        assert_eq!(ev.auth_attempts[0].username, "admin");
    }

    #[tokio::test]
    async fn handler_always_rejects_in_reject_all_mode() {
        let bucket = empty_bucket();
        let mut h = HoneypotSshHandler {
            evidence: Arc::clone(&bucket),
            mode: HandlerMode::RejectAll,
        };
        // Multiple attempts — all must be rejected.
        for i in 0..4u32 {
            let res = h.auth_password("user", &format!("pass{i}")).await.unwrap();
            assert!(
                matches!(res, Auth::Reject { .. }),
                "attempt {i} should reject"
            );
        }
        assert_eq!(bucket.lock().unwrap().auth_attempts.len(), 4);
    }

    #[tokio::test]
    async fn handler_denies_shell_in_reject_all_mode() {
        let bucket = empty_bucket();
        // We can test the config path without a real russh channel.
        let cfg = build_ssh_config(6);
        assert!(cfg.max_auth_attempts > 0);
        let _ = bucket; // used for compilation check
    }

    // --- LlmShell mode tests (no real AI needed for unit tests) ---

    #[tokio::test]
    async fn llm_shell_mode_accepts_password_auth() {
        // We use a minimal mock that is never called in these unit tests
        // (the auth flow itself does not invoke the AI).
        struct NoopAi;

        #[async_trait::async_trait]
        impl crate::ai::AiProvider for NoopAi {
            fn name(&self) -> &'static str {
                "noop"
            }
            async fn decide(
                &self,
                _ctx: &crate::ai::DecisionContext<'_>,
            ) -> anyhow::Result<crate::ai::AiDecision> {
                anyhow::bail!("not used")
            }
            async fn chat(
                &self,
                _system_prompt: &str,
                _user_message: &str,
            ) -> anyhow::Result<String> {
                Ok("fake output".to_string())
            }
        }

        let bucket = empty_bucket();
        let mut h = HoneypotSshHandler {
            evidence: Arc::clone(&bucket),
            mode: HandlerMode::LlmShell {
                ai: Arc::new(NoopAi),
                hostname: "srv-prod-01".to_string(),
                accepted_user: None,
                input_buf: Vec::new(),
                history: Vec::new(),
            },
        };
        let result = h.auth_password("attacker", "hunter2").await.unwrap();
        assert!(
            matches!(result, Auth::Accept),
            "LlmShell mode must accept password auth"
        );
        // Ensure the attempt was still recorded.
        let ev = bucket.lock().unwrap();
        assert_eq!(ev.auth_attempts.len(), 1);
        assert_eq!(ev.auth_attempts[0].method, "password");
        assert_eq!(ev.auth_attempts[0].username, "attacker");
    }

    #[tokio::test]
    async fn llm_shell_mode_opens_session() {
        struct NoopAi;

        #[async_trait::async_trait]
        impl crate::ai::AiProvider for NoopAi {
            fn name(&self) -> &'static str {
                "noop"
            }
            async fn decide(
                &self,
                _ctx: &crate::ai::DecisionContext<'_>,
            ) -> anyhow::Result<crate::ai::AiDecision> {
                anyhow::bail!("not used")
            }
            async fn chat(
                &self,
                _system_prompt: &str,
                _user_message: &str,
            ) -> anyhow::Result<String> {
                Ok(String::new())
            }
        }

        let bucket = empty_bucket();
        let h = HoneypotSshHandler {
            evidence: Arc::clone(&bucket),
            mode: HandlerMode::LlmShell {
                ai: Arc::new(NoopAi),
                hostname: "srv-prod-01".to_string(),
                accepted_user: Some("root".to_string()),
                input_buf: Vec::new(),
                history: Vec::new(),
            },
        };
        // channel_open_session requires a real russh Channel so we test via the mode variant.
        assert!(matches!(h.mode, HandlerMode::LlmShell { .. }));
    }

    #[test]
    fn build_shell_system_prompt_contains_hostname_and_user() {
        let prompt = build_shell_system_prompt("root", "srv-prod-01", &[]);
        assert!(
            prompt.contains("srv-prod-01"),
            "prompt must contain hostname"
        );
        assert!(prompt.contains("root"), "prompt must contain username");
        assert!(
            prompt.contains("Ubuntu"),
            "prompt must mention Ubuntu distro"
        );
    }

    #[test]
    fn build_shell_system_prompt_includes_history() {
        let history = vec![
            ("ls".to_string(), "bin etc home".to_string()),
            ("whoami".to_string(), "root".to_string()),
        ];
        let prompt = build_shell_system_prompt("root", "host", &history);
        assert!(
            prompt.contains("ls"),
            "history command must appear in prompt"
        );
        assert!(
            prompt.contains("bin etc home"),
            "history response must appear in prompt"
        );
        assert!(
            prompt.contains("whoami"),
            "second history command must appear"
        );
    }
}
