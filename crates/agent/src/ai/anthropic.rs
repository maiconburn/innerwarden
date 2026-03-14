use anyhow::Result;
use async_trait::async_trait;
use tracing::info;

use super::{AiDecision, AiProvider, DecisionContext};

/// Anthropic (Claude) provider — not yet implemented.
///
/// We'd love your contribution! Implementing this provider means:
/// 1. POST to https://api.anthropic.com/v1/messages
/// 2. Use the same DecisionContext and AiDecision types as OpenAI
/// 3. Parse the JSON response into AiDecision
///
/// See openai.rs for a reference implementation.
/// Open a PR at: https://github.com/maiconburn/innerwarden
pub struct AnthropicProvider;

#[async_trait]
impl AiProvider for AnthropicProvider {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    async fn decide(&self, _ctx: &DecisionContext<'_>) -> Result<AiDecision> {
        info!(
            provider = "anthropic",
            "🚧 Anthropic provider is not yet implemented. \
             Contributions welcome: https://github.com/maiconburn/innerwarden \
             — falling back to ignore."
        );
        Ok(AiDecision::ignore("Anthropic provider not yet implemented"))
    }
}
