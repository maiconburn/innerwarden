use anyhow::Result;
use async_trait::async_trait;
use tracing::info;

use super::{AiDecision, AiProvider, DecisionContext};

/// Ollama (local LLM) provider — not yet implemented.
///
/// Ollama allows running models like Llama3, Mistral, etc. locally —
/// great for air-gapped or privacy-sensitive deployments.
///
/// We'd love your contribution! Implementing this provider means:
/// 1. POST to http://localhost:11434/api/chat (or configurable endpoint)
/// 2. Use the same DecisionContext and AiDecision types as OpenAI
/// 3. Parse the streaming or non-streaming JSON response
///
/// See openai.rs for a reference implementation.
/// Open a PR at: https://github.com/maiconburn/innerwarden
pub struct OllamaProvider;

#[async_trait]
impl AiProvider for OllamaProvider {
    fn name(&self) -> &'static str {
        "ollama"
    }

    async fn decide(&self, _ctx: &DecisionContext<'_>) -> Result<AiDecision> {
        info!(
            provider = "ollama",
            "🚧 Ollama provider is not yet implemented. \
             Contributions welcome: https://github.com/maiconburn/innerwarden \
             — falling back to ignore."
        );
        Ok(AiDecision::ignore("Ollama provider not yet implemented"))
    }
}
