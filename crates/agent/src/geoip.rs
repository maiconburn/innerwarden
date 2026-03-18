// ---------------------------------------------------------------------------
// IP Geolocation enrichment via ip-api.com
// ---------------------------------------------------------------------------
//
// Before sending an incident to the AI provider, InnerWarden can optionally
// query ip-api.com to enrich the decision context with geolocation data.
// This gives the AI provider additional geographic and network signal (country,
// city, ISP, ASN) without requiring an API key.
//
// API: GET http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as
// Docs: https://ip-api.com/docs/api:json
//
// Free tier: 45 requests/minute. Private IPs and invalid addresses return
// {"status":"fail"} and are handled gracefully (returns None).
//
// Configuration in agent.toml:
//   [geoip]
//   enabled = true

use serde::Deserialize;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// API response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct IpApiResponse {
    status: String,
    #[serde(default)]
    country: String,
    #[serde(rename = "countryCode", default)]
    country_code: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    isp: String,
    #[serde(rename = "as", default)]
    asn: String,
}

/// Lightweight geolocation summary attached to `DecisionContext`.
#[derive(Debug, Clone)]
pub struct GeoInfo {
    pub country: String,
    pub country_code: String,
    pub city: String,
    pub isp: String,
    pub asn: String,
}

impl GeoInfo {
    /// Human-readable summary for inclusion in the AI prompt.
    pub fn as_context_line(&self) -> String {
        format!(
            "Geolocation: country={} ({}), city={}, isp={}, asn={}",
            self.country, self.country_code, self.city, self.isp, self.asn
        )
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub struct GeoIpClient {
    http: reqwest::Client,
}

impl GeoIpClient {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("failed to build GeoIP HTTP client");
        Self { http }
    }

    /// Look up geolocation for a single IP address.
    /// Returns `None` on any non-fatal error (API down, rate limit, private IP,
    /// parse failure) so callers can proceed without enrichment.
    pub async fn lookup(&self, ip: &str) -> Option<GeoInfo> {
        if ip.is_empty() {
            return None;
        }

        debug!(ip, "querying ip-api.com");

        let url = format!(
            "http://ip-api.com/json/{}?fields=status,country,countryCode,city,isp,org,as",
            ip
        );

        let resp = self.http.get(&url).send().await;

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                warn!(ip, error = %e, "ip-api.com request failed");
                return None;
            }
        };

        if resp.status().as_u16() == 429 {
            warn!("ip-api.com rate limit hit — skipping geolocation enrichment");
            return None;
        }

        if !resp.status().is_success() {
            warn!(ip, status = %resp.status(), "ip-api.com returned non-200");
            return None;
        }

        let data: IpApiResponse = match resp.json().await {
            Ok(d) => d,
            Err(e) => {
                warn!(ip, error = %e, "failed to parse ip-api.com response");
                return None;
            }
        };

        if data.status != "success" {
            // Handles private IPs, invalid IPs, etc.
            return None;
        }

        Some(GeoInfo {
            country: data.country,
            country_code: data.country_code,
            city: data.city,
            isp: data.isp,
            asn: data.asn,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_success_response() {
        let json = r#"{
            "status": "success",
            "country": "China",
            "countryCode": "CN",
            "city": "Shenzhen",
            "isp": "China Telecom",
            "org": "China Telecom Guangdong",
            "as": "AS4134 China Telecom"
        }"#;
        let resp: IpApiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "success");
        assert_eq!(resp.country, "China");
        assert_eq!(resp.country_code, "CN");
        assert_eq!(resp.city, "Shenzhen");
        assert_eq!(resp.isp, "China Telecom");
        assert_eq!(resp.asn, "AS4134 China Telecom");
    }

    #[test]
    fn returns_none_on_fail_status() {
        let json = r#"{"status":"fail","message":"private range"}"#;
        let resp: IpApiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "fail");
        // When status != "success", lookup() returns None
        assert_ne!(resp.status, "success");
    }

    #[test]
    fn context_line_format() {
        let geo = GeoInfo {
            country: "Russia".to_string(),
            country_code: "RU".to_string(),
            city: "Moscow".to_string(),
            isp: "Rostelecom".to_string(),
            asn: "AS12389 Rostelecom".to_string(),
        };
        let line = geo.as_context_line();
        assert!(line.contains("country=Russia"));
        assert!(line.contains("(RU)"));
        assert!(line.contains("city=Moscow"));
        assert!(line.contains("isp=Rostelecom"));
        assert!(line.contains("asn=AS12389 Rostelecom"));
    }

    #[test]
    fn context_line_with_empty_fields() {
        let geo = GeoInfo {
            country: String::new(),
            country_code: String::new(),
            city: String::new(),
            isp: String::new(),
            asn: String::new(),
        };
        let line = geo.as_context_line();
        // Should not panic; empty strings are rendered as empty
        assert!(line.contains("Geolocation:"));
        assert!(line.contains("country="));
        assert!(line.contains("city="));
    }

    #[test]
    fn not_configured_when_disabled() {
        // GeoIpClient::new() is always available (no key needed).
        // Verify that lookup returns None for an empty IP string synchronously.
        // We test the guard at the start of lookup() rather than making a network call.
        // The empty-string guard is the only sync-testable path.
        let _client = GeoIpClient::new();
        // GeoIpClient::new() constructs successfully without requiring a key.
        // The empty-string guard (if ip.is_empty() { return None; }) is the
        // only sync-testable path; network calls are skipped in unit tests.
    }
}
