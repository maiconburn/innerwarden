/// Web Push notifications — RFC 8291 content encryption + RFC 8292 VAPID.
///
/// This module implements the server-side of the Web Push Protocol:
///   1. VAPID key generation and JWT signing (EC P-256, ES256)
///   2. Content encryption (aes128gcm, RFC 8291)
///   3. Push subscription storage and delivery
///
/// Generate VAPID keys with:  `innerwarden notify web-push setup`
/// The public key is served at: GET /api/push/vapid-key
/// Subscriptions are registered at: POST /api/push/subscribe
use std::path::Path;
use std::sync::OnceLock;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Key, Nonce,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hkdf::Hkdf;
use p256::{
    ecdh::EphemeralSecret,
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::DecodePrivateKey,
    EncodedPoint, PublicKey,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::warn;

use crate::config::WebPushConfig;

fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("failed to build web push HTTP client")
    })
}

// ---------------------------------------------------------------------------
// Subscription types (match the browser PushSubscription JSON shape)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebPushSubscription {
    pub endpoint: String,
    pub keys: WebPushKeys,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebPushKeys {
    /// Base64url-encoded uncompressed P-256 public key (65 bytes, no padding)
    pub p256dh: String,
    /// Base64url-encoded 16-byte authentication secret (no padding)
    pub auth: String,
}

// ---------------------------------------------------------------------------
// VAPID key management
// ---------------------------------------------------------------------------

/// Generate a fresh VAPID EC P-256 key pair.
/// Returns `(private_key_pem, public_key_base64url)`.
/// The PEM should be stored in `agent.env` as INNERWARDEN_VAPID_PRIVATE_KEY.
/// The base64url public key is what browsers use when subscribing.
#[cfg(test)]
pub fn generate_vapid_keys() -> Result<(String, String)> {
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // PKCS#8 PEM for private key storage
    let pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to serialize VAPID private key to PEM")?;
    let pem_str = pem.to_string();

    // Uncompressed P-256 point (65 bytes: 0x04 + X + Y) as base64url
    let public_bytes = EncodedPoint::from(verifying_key).to_bytes().to_vec();
    let public_b64 = URL_SAFE_NO_PAD.encode(&public_bytes);

    Ok((pem_str, public_b64))
}

// ---------------------------------------------------------------------------
// VAPID JWT (RFC 8292)
// ---------------------------------------------------------------------------

fn build_vapid_auth(endpoint: &str, config: &WebPushConfig) -> Result<String> {
    // Parse the push service origin from the endpoint URL
    // e.g. "https://fcm.googleapis.com/fcm/send/..." → "https://fcm.googleapis.com"
    let audience = {
        let scheme_end = endpoint.find("://").map(|i| i + 3).unwrap_or(0);
        let path_start = endpoint[scheme_end..]
            .find('/')
            .map(|i| scheme_end + i)
            .unwrap_or(endpoint.len());
        &endpoint[..path_start]
    };

    // Build unsigned token: base64url(header).base64url(payload)
    let header = URL_SAFE_NO_PAD.encode(r#"{"typ":"JWT","alg":"ES256"}"#);
    let exp = chrono::Utc::now().timestamp() + 43_200; // 12 h
    let payload_json = format!(
        r#"{{"aud":"{}","exp":{},"sub":"{}"}}"#,
        audience, exp, config.vapid_subject
    );
    let payload = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let signing_input = format!("{}.{}", header, payload);

    // Sign with ES256 (ECDSA P-256, SHA-256)
    let signing_key = SigningKey::from_pkcs8_pem(&config.vapid_private_key)
        .context("failed to parse VAPID private key — run `innerwarden notify web-push setup`")?;
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    // P1363 format (r || s, 64 bytes) — required by JWT ES256
    let sig_bytes = signature.to_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes.as_slice());

    let jwt = format!("{}.{}", signing_input, sig_b64);
    Ok(format!("vapid t={},k={}", jwt, config.vapid_public_key))
}

// ---------------------------------------------------------------------------
// Content encryption — RFC 8291 (aes128gcm)
// ---------------------------------------------------------------------------

fn encrypt_payload(plaintext: &[u8], subscription: &WebPushSubscription) -> Result<Vec<u8>> {
    // --- Parse subscriber keys ---
    let receiver_key_bytes = URL_SAFE_NO_PAD
        .decode(&subscription.keys.p256dh)
        .context("failed to base64-decode subscriber p256dh")?;
    let receiver_public = PublicKey::from_sec1_bytes(&receiver_key_bytes)
        .context("failed to parse subscriber public key (p256dh)")?;

    let auth_secret = URL_SAFE_NO_PAD
        .decode(&subscription.keys.auth)
        .context("failed to base64-decode subscriber auth secret")?;

    // --- Ephemeral sender key pair ---
    let sender_secret = EphemeralSecret::random(&mut OsRng);
    let sender_public = sender_secret.public_key();
    // Uncompressed point (65 bytes) for the ECE header key_id field
    let sender_public_bytes = EncodedPoint::from(sender_public).to_bytes().to_vec();

    // --- ECDH shared secret (x-coordinate only) ---
    let shared = sender_secret.diffie_hellman(&receiver_public);
    let shared_bytes = shared.raw_secret_bytes();

    // --- Receiver public key uncompressed bytes (for HKDF info) ---
    let receiver_public_bytes = EncodedPoint::from(receiver_public).to_bytes().to_vec();

    // --- PRK = HKDF-Extract(salt=auth_secret, ikm=shared_secret) ---
    let prk = Hkdf::<Sha256>::new(Some(&auth_secret), shared_bytes.as_slice());

    // --- IKM = HKDF-Expand(PRK, "WebPush: info\0" || receiver_pub || sender_pub, 32) ---
    let mut info = b"WebPush: info\x00".to_vec();
    info.extend_from_slice(&receiver_public_bytes);
    info.extend_from_slice(&sender_public_bytes);
    let mut ikm = [0u8; 32];
    prk.expand(&info, &mut ikm)
        .map_err(|_| anyhow::anyhow!("HKDF expand for IKM failed"))?;

    // --- Random salt (16 bytes) ---
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    // --- Key material from salt + IKM ---
    let key_hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);

    // CEK = HKDF-Expand(key_hkdf, "Content-Encoding: aes128gcm\0\x01", 16)
    let mut cek = [0u8; 16];
    key_hkdf
        .expand(b"Content-Encoding: aes128gcm\x00\x01", &mut cek)
        .map_err(|_| anyhow::anyhow!("HKDF expand for CEK failed"))?;

    // Nonce = HKDF-Expand(key_hkdf, "Content-Encoding: nonce\0\x01", 12)
    let mut nonce_bytes = [0u8; 12];
    key_hkdf
        .expand(b"Content-Encoding: nonce\x00\x01", &mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("HKDF expand for nonce failed"))?;

    // --- AES-128-GCM encryption ---
    // Append record delimiter: 0x02 = last (and only) record
    let mut padded = plaintext.to_vec();
    padded.push(0x02);

    let key = Key::<Aes128Gcm>::from_slice(&cek);
    let cipher = Aes128Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, padded.as_slice())
        .map_err(|_| anyhow::anyhow!("AES-128-GCM encryption failed"))?;

    // --- ECE header: salt(16) || rs(4 BE) || idlen(1) || key_id(sender_pub) || ciphertext ---
    let rs: u32 = 4096;
    let idlen = sender_public_bytes.len() as u8; // 65

    let mut result = Vec::with_capacity(16 + 4 + 1 + sender_public_bytes.len() + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&rs.to_be_bytes());
    result.push(idlen);
    result.extend_from_slice(&sender_public_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

// ---------------------------------------------------------------------------
// Send + subscription management
// ---------------------------------------------------------------------------

/// Send a Web Push notification to a single subscription.
/// Returns `Err("subscription_expired")` if the push service returns 410/404.
pub async fn send_push(
    subscription: &WebPushSubscription,
    title: &str,
    body: &str,
    config: &WebPushConfig,
) -> Result<()> {
    let payload = serde_json::json!({ "title": title, "body": body }).to_string();
    let encrypted = encrypt_payload(payload.as_bytes(), subscription)
        .context("failed to encrypt web push payload")?;

    let auth_header = build_vapid_auth(&subscription.endpoint, config)
        .context("failed to build VAPID authorization header")?;

    let resp = http_client()
        .post(&subscription.endpoint)
        .header("Authorization", auth_header)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Encoding", "aes128gcm")
        .header("TTL", "86400")
        .body(encrypted)
        .send()
        .await
        .context("web push HTTP request failed")?;

    let status = resp.status();
    // 410 Gone / 404 Not Found → subscription is no longer valid
    if status == reqwest::StatusCode::GONE || status == reqwest::StatusCode::NOT_FOUND {
        bail!("subscription_expired");
    }
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        bail!(
            "push service returned {status}: {}",
            text.chars().take(200).collect::<String>()
        );
    }
    Ok(())
}

const SUBSCRIPTIONS_FILE: &str = "web-push-subscriptions.json";

pub fn load_subscriptions(data_dir: &Path) -> Vec<WebPushSubscription> {
    let path = data_dir.join(SUBSCRIPTIONS_FILE);
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    serde_json::from_str(&content).unwrap_or_default()
}

pub fn save_subscriptions(data_dir: &Path, subs: &[WebPushSubscription]) -> Result<()> {
    let path = data_dir.join(SUBSCRIPTIONS_FILE);
    let content = serde_json::to_string_pretty(subs)?;
    std::fs::write(&path, content)
        .with_context(|| format!("failed to write subscriptions to {}", path.display()))
}

/// Remove a subscription by endpoint URL. Returns true if it was present.
pub fn remove_subscription(data_dir: &Path, endpoint: &str) -> Result<bool> {
    let mut subs = load_subscriptions(data_dir);
    let before = subs.len();
    subs.retain(|s| s.endpoint != endpoint);
    if subs.len() < before {
        save_subscriptions(data_dir, &subs)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Send a push notification for a new incident to all registered subscriptions.
/// Expired subscriptions are pruned automatically.
pub async fn notify_incident(
    incident: &innerwarden_core::incident::Incident,
    data_dir: &Path,
    config: &WebPushConfig,
) {
    if !config.enabled || config.vapid_private_key.is_empty() || config.vapid_public_key.is_empty()
    {
        return;
    }

    // Filter by configured minimum severity
    let min_high = config.min_severity.to_lowercase() != "critical";
    let passes = match incident.severity {
        innerwarden_core::event::Severity::Critical => true,
        innerwarden_core::event::Severity::High => min_high,
        _ => false,
    };
    if !passes {
        return;
    }

    let subscriptions = load_subscriptions(data_dir);
    if subscriptions.is_empty() {
        return;
    }

    let severity_str = format!("{:?}", incident.severity);
    let title = format!("InnerWarden — {} Incident", severity_str);
    let body = incident.summary.clone();

    let mut expired_indices: Vec<usize> = Vec::new();
    for (idx, sub) in subscriptions.iter().enumerate() {
        match send_push(sub, &title, &body, config).await {
            Ok(()) => {}
            Err(e) if e.to_string() == "subscription_expired" => {
                expired_indices.push(idx);
            }
            Err(e) => {
                warn!(endpoint = %sub.endpoint, "web push failed: {e:#}");
            }
        }
    }

    // Prune expired subscriptions (iterate in reverse to preserve indices)
    if !expired_indices.is_empty() {
        let mut subs = subscriptions;
        for idx in expired_indices.into_iter().rev() {
            subs.remove(idx);
        }
        if let Err(e) = save_subscriptions(data_dir, &subs) {
            warn!("failed to save pruned subscriptions: {e:#}");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_vapid_keys_produces_valid_pair() {
        let (pem, public_b64) = generate_vapid_keys().expect("key generation failed");
        assert!(
            pem.contains("PRIVATE KEY"),
            "PEM should contain PRIVATE KEY header"
        );
        // Public key: 65 bytes uncompressed → 87 base64url chars (no padding)
        let bytes = URL_SAFE_NO_PAD
            .decode(&public_b64)
            .expect("should be valid base64url");
        assert_eq!(bytes.len(), 65, "uncompressed P-256 point is 65 bytes");
        assert_eq!(bytes[0], 0x04, "uncompressed point starts with 0x04");
    }

    #[test]
    fn load_subscriptions_returns_empty_for_missing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let subs = load_subscriptions(dir.path());
        assert!(subs.is_empty());
    }

    #[test]
    fn save_and_load_subscriptions() {
        let dir = tempfile::TempDir::new().unwrap();
        let sub = WebPushSubscription {
            endpoint: "https://example.com/push/test".to_string(),
            keys: WebPushKeys {
                p256dh: "test_key".to_string(),
                auth: "test_auth".to_string(),
            },
        };
        save_subscriptions(dir.path(), &[sub.clone()]).unwrap();
        let loaded = load_subscriptions(dir.path());
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].endpoint, sub.endpoint);
    }

    #[test]
    fn remove_subscription_removes_by_endpoint() {
        let dir = tempfile::TempDir::new().unwrap();
        let sub1 = WebPushSubscription {
            endpoint: "https://example.com/push/1".to_string(),
            keys: WebPushKeys {
                p256dh: "k1".to_string(),
                auth: "a1".to_string(),
            },
        };
        let sub2 = WebPushSubscription {
            endpoint: "https://example.com/push/2".to_string(),
            keys: WebPushKeys {
                p256dh: "k2".to_string(),
                auth: "a2".to_string(),
            },
        };
        save_subscriptions(dir.path(), &[sub1.clone(), sub2.clone()]).unwrap();
        let removed = remove_subscription(dir.path(), &sub1.endpoint).unwrap();
        assert!(removed);
        let remaining = load_subscriptions(dir.path());
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].endpoint, sub2.endpoint);
    }

    #[test]
    fn remove_subscription_nonexistent_returns_false() {
        let dir = tempfile::TempDir::new().unwrap();
        let removed = remove_subscription(dir.path(), "https://example.com/nonexistent").unwrap();
        assert!(!removed);
    }
}
