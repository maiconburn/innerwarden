use std::future::Future;
use std::pin::Pin;

use tracing::info;

use crate::skills::{ResponseSkill, SkillContext, SkillResult, SkillTier};

/// Premium skill: controlled honeypot demo marker (not a real honeypot).
///
/// Current phase behavior:
/// - Produces a demo/simulation signal that can be used in narrative and product demos.
/// - Does NOT expose decoy services and does NOT redirect real attacker traffic.
///
/// TODO(real honeypot rebuild):
/// - Replace this demo behavior with dedicated infrastructure for decoy services,
///   traffic redirection, and safe forensic capture in a future phase.
pub struct Honeypot;

impl ResponseSkill for Honeypot {
    fn id(&self) -> &'static str { "honeypot" }
    fn name(&self) -> &'static str { "Honeypot Demo Marker (Premium)" }
    fn description(&self) -> &'static str {
        "Creates a controlled DEMO/SIMULATION/DECOY marker indicating an attacker \
         'fell into honeypot' for narrative and product demo flows. \
         This phase does not run real honeypot infrastructure."
    }
    fn tier(&self) -> SkillTier { SkillTier::Premium }
    fn applicable_to(&self) -> &'static [&'static str] { &[] }

    fn execute<'a>(
        &'a self,
        ctx: &'a SkillContext,
        _dry_run: bool,
    ) -> Pin<Box<dyn Future<Output = SkillResult> + Send + 'a>> {
        Box::pin(async move {
            let ip = ctx.target_ip.as_deref().unwrap_or("unknown");
            info!(
                ip,
                "[PREMIUM] honeypot demo marker triggered for {ip} \
                 (DEMO/SIMULATION/DECOY mode; no real honeypot infrastructure)"
            );
            SkillResult {
                success: true,
                message: format!(
                    "[PREMIUM DEMO] Honeypot simulation marker armed for {ip}. \
                     TODO: future phase will replace this with a real honeypot implementation."
                ),
            }
        })
    }
}
