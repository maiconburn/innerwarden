//! Mesh network integration — wraps innerwarden-mesh for the agent.
//!
//! Compiled only with `--features mesh`. Without it, provides no-op stubs.

use crate::config::MeshNetworkConfig;
use std::path::Path;

#[cfg(feature = "mesh")]
#[allow(dead_code)]
mod inner {
    use super::*;
    use innerwarden_mesh::config::{MeshConfig, PeerEntry};
    use innerwarden_mesh::node::MeshNode;
    use innerwarden_mesh::MeshTickResult;
    use std::net::SocketAddr;

    pub struct MeshIntegration {
        node: MeshNode,
    }

    impl MeshIntegration {
        pub fn new(cfg: &MeshNetworkConfig, data_dir: &Path) -> anyhow::Result<Self> {
            let mesh_cfg = MeshConfig {
                enabled: cfg.enabled,
                bind: cfg.bind.clone(),
                peers: cfg
                    .peers
                    .iter()
                    .map(|p| PeerEntry {
                        endpoint: p.endpoint.clone(),
                        public_key: p.public_key.clone(),
                        label: p.label.clone(),
                    })
                    .collect(),
                poll_secs: cfg.poll_secs,
                auto_broadcast: cfg.auto_broadcast,
                max_signals_per_hour: cfg.max_signals_per_hour,
                max_staged: 10_000,
            };
            let node = MeshNode::new(mesh_cfg, data_dir)?;
            Ok(Self { node })
        }

        pub async fn start_listener(
            &self,
        ) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
            self.node.start_listener().await
        }

        pub async fn broadcast_local_block(
            &self,
            ip: &str,
            detector: &str,
            confidence: f32,
            evidence: &[u8],
            ttl_secs: u64,
        ) {
            self.node
                .broadcast_local_block(ip, detector, confidence, evidence, ttl_secs)
                .await;
        }

        pub fn tick(&mut self) -> MeshTickResult {
            self.node.tick()
        }

        pub fn is_mesh_blocked(&self, ip: &str) -> bool {
            self.node.is_mesh_blocked(ip)
        }

        pub fn confirm_local_incident(&self, ip: &str) {
            self.node.confirm_local_incident(ip);
        }

        pub fn persist(&self) -> anyhow::Result<()> {
            self.node.persist()
        }

        pub fn node_id(&self) -> &str {
            self.node.node_id()
        }

        pub fn peer_count(&self) -> usize {
            self.node.peer_count()
        }

        pub fn staged_count(&self) -> usize {
            self.node.staged_count()
        }

        pub fn active_block_count(&self) -> usize {
            self.node.active_block_count()
        }
    }
}

#[cfg(not(feature = "mesh"))]
#[allow(dead_code)]
mod inner {
    use super::*;

    /// No-op stub when mesh feature is disabled.
    pub struct MeshIntegration;

    impl MeshIntegration {
        pub fn new(_cfg: &MeshNetworkConfig, _data_dir: &Path) -> anyhow::Result<Self> {
            Ok(Self)
        }

        pub async fn start_listener(
            &self,
        ) -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
            anyhow::bail!("mesh feature not enabled")
        }

        pub async fn broadcast_local_block(
            &self,
            _ip: &str,
            _detector: &str,
            _confidence: f32,
            _evidence: &[u8],
            _ttl_secs: u64,
        ) {
        }

        pub fn tick(&mut self) -> StubTickResult {
            StubTickResult
        }

        pub fn is_mesh_blocked(&self, _ip: &str) -> bool {
            false
        }

        pub fn confirm_local_incident(&self, _ip: &str) {}

        pub fn persist(&self) -> anyhow::Result<()> {
            Ok(())
        }

        pub fn node_id(&self) -> &str {
            "disabled"
        }

        pub fn peer_count(&self) -> usize {
            0
        }

        pub fn staged_count(&self) -> usize {
            0
        }

        pub fn active_block_count(&self) -> usize {
            0
        }
    }

    pub struct StubTickResult;
    impl StubTickResult {
        pub fn block_ips(&self) -> &[(String, u64)] {
            &[]
        }
        pub fn unblock_ips(&self) -> &[String] {
            &[]
        }
    }
}

pub use inner::MeshIntegration;
