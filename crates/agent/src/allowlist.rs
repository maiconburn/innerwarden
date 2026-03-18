/// Allowlist — trusted IPs, CIDRs, and users that skip automated AI response.
///
/// Incidents involving allowlisted entities are still logged, still sent to
/// webhook/Telegram/Slack, but are not forwarded to the AI gate and will
/// never trigger an automatic skill execution.
use std::net::IpAddr;

/// Returns true if `ip` matches any entry in `trusted_ips`.
/// Entries may be exact IPs ("1.2.3.4") or CIDR notation ("192.168.0.0/24").
pub fn is_ip_allowlisted(ip: &str, trusted_ips: &[String]) -> bool {
    trusted_ips.iter().any(|entry| ip_matches(ip, entry))
}

/// Returns true if `user` matches any entry in `trusted_users`.
pub fn is_user_allowlisted(user: &str, trusted_users: &[String]) -> bool {
    trusted_users.iter().any(|u| u == user)
}

fn ip_matches(ip_str: &str, entry: &str) -> bool {
    // Exact match
    if ip_str == entry {
        return true;
    }

    // CIDR match
    let Some((base_str, prefix_str)) = entry.split_once('/') else {
        return false;
    };
    let Ok(prefix_len) = prefix_str.parse::<u32>() else {
        return false;
    };
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };
    let Ok(base) = base_str.parse::<IpAddr>() else {
        return false;
    };

    match (ip, base) {
        (IpAddr::V4(ip4), IpAddr::V4(base4)) if prefix_len <= 32 => {
            let shift = 32u32.saturating_sub(prefix_len);
            // When prefix_len == 0, mask is 0 → matches all
            let mask = if shift >= 32 { 0u32 } else { !0u32 << shift };
            (u32::from(ip4) & mask) == (u32::from(base4) & mask)
        }
        (IpAddr::V6(ip6), IpAddr::V6(base6)) if prefix_len <= 128 => {
            let shift = 128u32.saturating_sub(prefix_len);
            let mask = if shift >= 128 { 0u128 } else { !0u128 << shift };
            (u128::from(ip6) & mask) == (u128::from(base6) & mask)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_ipv4_match() {
        assert!(ip_matches("1.2.3.4", "1.2.3.4"));
        assert!(!ip_matches("1.2.3.5", "1.2.3.4"));
    }

    #[test]
    fn cidr_v4_slash24() {
        assert!(ip_matches("192.168.1.1", "192.168.1.0/24"));
        assert!(ip_matches("192.168.1.254", "192.168.1.0/24"));
        assert!(!ip_matches("192.168.2.1", "192.168.1.0/24"));
    }

    #[test]
    fn cidr_v4_slash16() {
        assert!(ip_matches("10.0.255.1", "10.0.0.0/16"));
        assert!(!ip_matches("10.1.0.1", "10.0.0.0/16"));
    }

    #[test]
    fn cidr_v4_slash32() {
        assert!(ip_matches("1.2.3.4", "1.2.3.4/32"));
        assert!(!ip_matches("1.2.3.5", "1.2.3.4/32"));
    }

    #[test]
    fn cidr_v4_slash0_matches_all() {
        assert!(ip_matches("1.2.3.4", "0.0.0.0/0"));
        assert!(ip_matches("255.255.255.255", "0.0.0.0/0"));
    }

    #[test]
    fn ipv6_exact() {
        assert!(ip_matches("::1", "::1"));
        assert!(!ip_matches("::2", "::1"));
    }

    #[test]
    fn ipv6_cidr() {
        assert!(ip_matches("2001:db8::1", "2001:db8::/32"));
        assert!(!ip_matches("2001:db9::1", "2001:db8::/32"));
    }

    #[test]
    fn invalid_cidr_does_not_panic() {
        assert!(!ip_matches("1.2.3.4", "not-a-cidr"));
        assert!(!ip_matches("1.2.3.4", "1.2.3.0/abc"));
    }

    #[test]
    fn is_ip_allowlisted_returns_true_when_matched() {
        let list = vec!["192.168.1.0/24".to_string(), "10.0.0.1".to_string()];
        assert!(is_ip_allowlisted("192.168.1.50", &list));
        assert!(is_ip_allowlisted("10.0.0.1", &list));
        assert!(!is_ip_allowlisted("1.2.3.4", &list));
    }

    #[test]
    fn is_ip_allowlisted_empty_list() {
        assert!(!is_ip_allowlisted("1.2.3.4", &[]));
    }

    #[test]
    fn is_user_allowlisted_matches() {
        let list = vec!["deploy".to_string(), "backup".to_string()];
        assert!(is_user_allowlisted("deploy", &list));
        assert!(!is_user_allowlisted("root", &list));
    }

    #[test]
    fn is_user_allowlisted_empty_list() {
        assert!(!is_user_allowlisted("root", &[]));
    }
}
