pub mod c2_callback;
pub mod container_escape;
pub mod credential_stuffing;
pub mod distributed_ssh;
pub mod suspicious_login;

/// Returns true if the IP is private, loopback, link-local, or documentation range.
/// These should never be treated as external attackers.
pub fn is_internal_ip(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    match addr {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}
pub mod docker_anomaly;
pub mod execution_guard;
pub mod integrity_alert;
pub mod osquery_anomaly;
pub mod port_scan;
pub mod process_tree;
pub mod search_abuse;
pub mod ssh_bruteforce;
pub mod sudo_abuse;
pub mod suricata_alert;
pub mod user_agent_scanner;
pub mod web_scan;
