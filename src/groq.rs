// ── Legacy Groq client (backward-compatible wrapper) ─────────────────
//
// Phase 0 introduced the provider-agnostic client in `llm.rs`. This module
// keeps the original `GroqClient` name and API (`from_env` + `chat`) so every
// existing caller (verify, fix, attack, rag, review, trace, zeroday) compiles
// and behaves exactly as before.
//
// `GroqClient::from_env()` honors the active provider — by default Groq, but
// set `CIPHER_AI_PROVIDER=openai|anthropic` to route all existing commands
// through another provider without touching their code.

use anyhow::Result;

use crate::llm::{AiClient, AiProvider};

/// Groq API client for chat completions.
///
/// Now backed by the shared multi-provider [`AiClient`]; the name is retained
/// for backward compatibility with the original single-provider design.
pub struct GroqClient {
    inner: AiClient,
}

impl GroqClient {
    /// Create a client for the active AI provider.
    ///
    /// Reads the API key from the provider's environment variable
    /// (`GROQ_API_KEY`, `OPENAI_API_KEY`, or `ANTHROPIC_API_KEY`) falling back
    /// to the persisted config file, and honors `CIPHER_AI_BASE_URL` /
    /// `CIPHER_AI_MODEL` overrides.
    pub fn from_env() -> Result<Self> {
        // Explicitly request the Groq provider from a real Groq key? No —
        // honor the active provider so multi-provider works everywhere.
        Ok(Self {
            inner: AiClient::from_env()?,
        })
    }

    /// Send a chat completion request to the active AI provider.
    pub async fn chat(
        &self,
        system_prompt: &str,
        user_message: &str,
        model: Option<&str>,
    ) -> Result<String> {
        self.inner.chat(system_prompt, user_message, model).await
    }

    /// The provider this client is talking to.
    pub fn provider(&self) -> AiProvider {
        self.inner.provider()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_groq_client_rejects_missing_key() {
        // No API key in env or config (typical test environment) — must error
        // cleanly rather than panic.
        if std::env::var("GROQ_API_KEY").is_ok()
            || crate::config::stored_api_key().is_some()
        {
            return;
        }
        assert!(GroqClient::from_env().is_err());
    }
}
