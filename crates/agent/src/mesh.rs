//! Mesh network integration — wraps innerwarden-mesh for the agent.
//!
//! Always compiled. Disabled by default via config (`mesh.enabled = false`).

use std::net::SocketAddr;
use std::path::Path;

use innerwarden_mesh::config::{MeshConfig, PeerEntry};
use innerwarden_mesh::node::MeshNode;
pub use innerwarden_mesh::MeshTickResult;

use crate::config::MeshNetworkConfig;

#[allow(dead_code)]
pub struct MeshIntegration {
    node: MeshNode,
}

#[allow(dead_code)]
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
            initial_trust: 0.5,
        };
        let node = MeshNode::new(mesh_cfg, data_dir)?;
        Ok(Self { node })
    }

    pub async fn start_listener(
        &self,
    ) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
        self.node.start_listener().await
    }

    pub async fn discover_peers(&mut self) {
        self.node.discover_peers().await;
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
