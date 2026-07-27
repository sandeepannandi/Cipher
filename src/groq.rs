use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const GROQ_API_BASE: &str = "https://api.groq.com/openai/v1";
const DEFAULT_CHAT_MODEL: &str = "llama-3.3-70b-versatile";

/// Groq API client for chat completions
pub struct GroqClient {
    client: Client,
    api_key: String,
}

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<Message>,
    temperature: f32,
    max_tokens: u32,
    stream: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
    #[allow(dead_code)]
    usage: Option<Usage>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: Message,
    #[allow(dead_code)]
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Usage {
    #[allow(dead_code)]
    prompt_tokens: u32,
    #[allow(dead_code)]
    completion_tokens: u32,
    #[allow(dead_code)]
    total_tokens: u32,
}

impl GroqClient {
    /// Create a new Groq client from the API key in environment variable GROQ_API_KEY
    pub fn from_env() -> Result<Self> {
        let api_key = std::env::var("GROQ_API_KEY")
            .or_else(|_| Self::read_key_from_config())
            .context(
                "GROQ_API_KEY not found. Set it via:\n  export GROQ_API_KEY=gsk_your_key_here\n  or add it to a .env file in your project root.",
            )?;

        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()?;

        Ok(Self { client, api_key })
    }

    /// Read API key from .cipher-ai/config.json
    fn read_key_from_config() -> Result<String> {
        let config_path = std::env::current_dir()?.join(".cipher").join("config.json");
        if config_path.exists() {
            #[derive(Deserialize)]
            struct Config {
                groq_api_key: Option<String>,
            }
            let config: Config =
                serde_json::from_str(&std::fs::read_to_string(&config_path)?)?;
            if let Some(key) = config.groq_api_key {
                return Ok(key);
            }
        }
        anyhow::bail!("no API key found")
    }

    /// Send a chat completion request to Groq
    pub async fn chat(
        &self,
        system_prompt: &str,
        user_message: &str,
        model: Option<&str>,
    ) -> Result<String> {
        let model = model.unwrap_or(DEFAULT_CHAT_MODEL);

        let request = ChatRequest {
            model: model.to_string(),
            messages: vec![
                Message {
                    role: "system".to_string(),
                    content: system_prompt.to_string(),
                },
                Message {
                    role: "user".to_string(),
                    content: user_message.to_string(),
                },
            ],
            temperature: 0.1,
            max_tokens: 4096,
            stream: false,
        };

        let response = self
            .client
            .post(format!("{}/chat/completions", GROQ_API_BASE))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to send chat request to Groq API")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Groq API error ({}): {}", status, body);
        }

        let chat_response: ChatResponse = response
            .json()
            .await
            .context("Failed to parse Groq chat response")?;

        let content = chat_response
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .unwrap_or_default();

        Ok(content)
    }
}
