// ---------------------------------------------------------------------------
// AbuseIPDB IP reputation enrichment
// ---------------------------------------------------------------------------
//
// Before sending an incident to the AI provider, InnerWarden can optionally
// query the AbuseIPDB API to enrich the decision context with crowd-sourced
// reputation data. This gives the AI provider more signal to raise or lower
// its confidence without adding latency to the critical path for IPs that
// are already well-known.
//
// API: GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=30
// Docs: https://docs.abuseipdb.com/#check-endpoint
//
// Configuration in agent.toml:
//   [abuseipdb]
//   enabled   = true
//   api_key   = ""   # or ABUSEIPDB_API_KEY env var
//   max_age_days = 30

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// API response types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct AbuseIpDbResponse {
    pub data: AbuseIpDbData,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AbuseIpDbData {
    #[allow(dead_code)]
    pub ip_address: String,
    pub abuse_confidence_score: u8, // 0–100
    pub total_reports: u32,
    pub num_distinct_users: u32,
    pub country_code: Option<String>,
    pub isp: Option<String>,
    #[allow(dead_code)]
    pub domain: Option<String>,
    pub is_tor: Option<bool>,
    #[allow(dead_code)]
    pub is_public: bool,
}

/// Lightweight reputation summary attached to `DecisionContext`.
#[derive(Debug, Clone)]
pub struct IpReputation {
    pub confidence_score: u8,
    pub total_reports: u32,
    pub distinct_users: u32,
    pub country_code: Option<String>,
    pub isp: Option<String>,
    pub is_tor: bool,
}

impl IpReputation {
    /// Human-readable summary for inclusion in the AI prompt.
    pub fn as_context_line(&self) -> String {
        let tor_flag = if self.is_tor { ", Tor exit node" } else { "" };
        let country = self.country_code.as_deref().unwrap_or("??");
        let isp = self.isp.as_deref().unwrap_or("unknown ISP");
        format!(
            "AbuseIPDB: score={}/100, reports={}, distinct_reporters={}, country={}, isp={}{tor_flag}",
            self.confidence_score,
            self.total_reports,
            self.distinct_users,
            country,
            isp,
        )
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub struct AbuseIpDbClient {
    api_key: String,
    max_age_days: u32,
    http: reqwest::Client,
}

impl AbuseIpDbClient {
    pub fn new(api_key: String, max_age_days: u32) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("failed to build AbuseIPDB HTTP client");
        Self {
            api_key,
            max_age_days,
            http,
        }
    }

    pub fn is_configured(&self) -> bool {
        !self.api_key.is_empty()
    }

    /// Report an abusive IP to the AbuseIPDB database.
    ///
    /// Called after a successful block so that our defense contributes to the
    /// global threat intelligence network.  Returns `true` on success.
    ///
    /// API: POST https://api.abuseipdb.com/api/v2/report
    /// Docs: https://docs.abuseipdb.com/#report-endpoint
    pub async fn report(&self, ip: &str, categories: &str, comment: &str) -> bool {
        if !self.is_configured() {
            return false;
        }

        debug!(ip, categories, "reporting IP to AbuseIPDB");

        let body = ReportRequest {
            ip: ip.to_string(),
            categories: categories.to_string(),
            comment: comment.to_string(),
        };

        let resp = self
            .http
            .post("https://api.abuseipdb.com/api/v2/report")
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await;

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                warn!(ip, error = %e, "AbuseIPDB report request failed");
                return false;
            }
        };

        if resp.status().as_u16() == 429 {
            warn!("AbuseIPDB rate limit hit — skipping report");
            return false;
        }

        if resp.status().as_u16() == 422 {
            // Duplicate report or validation error — not a failure worth retrying
            debug!(
                ip,
                "AbuseIPDB report rejected (422) — likely duplicate or invalid"
            );
            return false;
        }

        if resp.status().is_success() {
            info!(ip, categories, "reported IP to AbuseIPDB");
            true
        } else {
            warn!(ip, status = %resp.status(), "AbuseIPDB report returned non-200");
            false
        }
    }

    /// Look up the reputation of a single IP address.
    /// Returns `None` on any non-fatal error (API down, rate limit, parse failure)
    /// so callers can proceed without enrichment.
    pub async fn check(&self, ip: &str) -> Option<IpReputation> {
        if !self.is_configured() {
            return None;
        }

        debug!(ip, "querying AbuseIPDB");

        let resp = self
            .http
            .get("https://api.abuseipdb.com/api/v2/check")
            .query(&[
                ("ipAddress", ip),
                ("maxAgeInDays", &self.max_age_days.to_string()),
            ])
            .header("Key", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await;

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                warn!(ip, error = %e, "AbuseIPDB request failed");
                return None;
            }
        };

        if resp.status().as_u16() == 429 {
            warn!("AbuseIPDB rate limit hit — skipping enrichment");
            return None;
        }

        if !resp.status().is_success() {
            warn!(ip, status = %resp.status(), "AbuseIPDB returned non-200");
            return None;
        }

        let data: AbuseIpDbResponse = match resp.json().await {
            Ok(d) => d,
            Err(e) => {
                warn!(ip, error = %e, "failed to parse AbuseIPDB response");
                return None;
            }
        };

        Some(IpReputation {
            confidence_score: data.data.abuse_confidence_score,
            total_reports: data.data.total_reports,
            distinct_users: data.data.num_distinct_users,
            country_code: data.data.country_code,
            isp: data.data.isp,
            is_tor: data.data.is_tor.unwrap_or(false),
        })
    }
}

// ---------------------------------------------------------------------------
// Report request
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ReportRequest {
    ip: String,
    categories: String,
    comment: String,
}

/// Map an InnerWarden detector name to AbuseIPDB category IDs.
///
/// Categories: https://www.abuseipdb.com/categories
///   14 = Port Scan, 15 = Hacking, 18 = Brute-Force, 21 = Web App Attack, 22 = SSH
pub fn detector_to_categories(detector: &str) -> &'static str {
    match detector {
        d if d.contains("ssh_bruteforce") => "18,22",
        d if d.contains("credential_stuffing") => "18,22",
        d if d.contains("port_scan") => "14",
        d if d.contains("web_scan") || d.contains("scanner_ua") => "21",
        d if d.contains("search_abuse") => "21",
        d if d.contains("execution_guard") => "15",
        d if d.contains("sudo_abuse") => "15",
        _ => "15", // generic "Hacking"
    }
}

/// Resolve AbuseIPDB API key from config value or environment variable.
pub fn resolve_api_key(config_key: &str) -> String {
    if !config_key.is_empty() {
        return config_key.to_string();
    }
    std::env::var("ABUSEIPDB_API_KEY").unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_check_response() {
        let json = r#"{
            "data": {
                "ipAddress": "1.2.3.4",
                "isPublic": true,
                "ipVersion": 4,
                "isWhitelisted": false,
                "abuseConfidenceScore": 87,
                "countryCode": "CN",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "SomeHosting Inc.",
                "domain": "somehosting.cn",
                "isTor": false,
                "totalReports": 342,
                "numDistinctUsers": 89,
                "lastReportedAt": "2024-01-15T12:00:00+00:00"
            }
        }"#;
        let resp: AbuseIpDbResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.data.abuse_confidence_score, 87);
        assert_eq!(resp.data.total_reports, 342);
        assert_eq!(resp.data.num_distinct_users, 89);
        assert_eq!(resp.data.country_code.as_deref(), Some("CN"));
        assert_eq!(resp.data.isp.as_deref(), Some("SomeHosting Inc."));
        assert_eq!(resp.data.is_tor, Some(false));
    }

    #[test]
    fn deserializes_tor_node() {
        let json = r#"{
            "data": {
                "ipAddress": "10.0.0.1",
                "isPublic": false,
                "abuseConfidenceScore": 100,
                "countryCode": "US",
                "isp": "Tor Project",
                "isTor": true,
                "totalReports": 1000,
                "numDistinctUsers": 500
            }
        }"#;
        let resp: AbuseIpDbResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.data.is_tor, Some(true));
        assert_eq!(resp.data.abuse_confidence_score, 100);
    }

    #[test]
    fn context_line_format() {
        let rep = IpReputation {
            confidence_score: 75,
            total_reports: 100,
            distinct_users: 30,
            country_code: Some("RU".to_string()),
            isp: Some("Evil ISP".to_string()),
            is_tor: false,
        };
        let line = rep.as_context_line();
        assert!(line.contains("score=75/100"));
        assert!(line.contains("reports=100"));
        assert!(line.contains("country=RU"));
        assert!(!line.contains("Tor"));
    }

    #[test]
    fn context_line_tor_flag() {
        let rep = IpReputation {
            confidence_score: 100,
            total_reports: 999,
            distinct_users: 200,
            country_code: None,
            isp: None,
            is_tor: true,
        };
        let line = rep.as_context_line();
        assert!(line.contains("Tor exit node"));
    }

    #[test]
    fn not_configured_when_empty_key() {
        let client = AbuseIpDbClient::new(String::new(), 30);
        assert!(!client.is_configured());
    }

    #[test]
    fn resolve_api_key_prefers_config() {
        // When config key is non-empty, use it
        let key = resolve_api_key("mykey123");
        assert_eq!(key, "mykey123");
    }

    #[test]
    fn detector_categories_ssh() {
        assert_eq!(detector_to_categories("ssh_bruteforce"), "18,22");
        assert_eq!(detector_to_categories("credential_stuffing"), "18,22");
    }

    #[test]
    fn detector_categories_scan() {
        assert_eq!(detector_to_categories("port_scan"), "14");
        assert_eq!(detector_to_categories("web_scan"), "21");
        assert_eq!(detector_to_categories("scanner_ua"), "21");
    }

    #[test]
    fn detector_categories_fallback() {
        assert_eq!(detector_to_categories("unknown_detector"), "15");
    }

    #[test]
    fn report_request_serializes() {
        let req = ReportRequest {
            ip: "1.2.3.4".to_string(),
            categories: "18,22".to_string(),
            comment: "test".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"ip\":\"1.2.3.4\""));
        assert!(json.contains("\"categories\":\"18,22\""));
    }
}
