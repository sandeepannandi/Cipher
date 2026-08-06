// ── Multi-provider AI client ─────────────────────────────────────────
//
// Phase 0 of the autonomous pentester: a single client that talks to any
// supported LLM provider so the agent brain is provider-agnostic.
//
// This file also carries the Phase 0 agent tool-calling protocol (see the
// "Agent tool-calling protocol" section below): a provider-agnostic,
// JSON-based `agent_turn` contract the pentester agent loop will use to
// plan and execute tool calls.
//
// Provider resolution (in priority order):
//   1. CIPHER_AI_PROVIDER env var      → "groq" (default) | "openai" | "anthropic"
//   2. provider field in ~/.cipher-ai/config.json
//   3. "groq" (backward compatible with the original single-provider tool)
//
// API key resolution (per provider):
//   - env var GROQ_API_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY
//   - fallback: the persisted key for that provider in the config file
//
// Overrides:
//   - CIPHER_AI_BASE_URL → route all traffic through a gateway / proxy
//     (LiteLLM, vLLM, Ollama bridge, corporate proxy — Shannon-style)
//   - CIPHER_AI_MODEL    → default model when the caller passes None
//
// Groq and OpenAI both speak the OpenAI-compatible `/chat/completions`
// protocol; Anthropic uses the Messages API. Both are implemented here.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const PROVIDER_GROQ: &str = "groq";
pub const PROVIDER_OPENAI: &str = "openai";
pub const PROVIDER_ANTHROPIC: &str = "anthropic";

/// Environment variable that selects the active provider.
pub const ENV_PROVIDER: &str = "CIPHER_AI_PROVIDER";
/// Environment variable that overrides the API base URL for any provider.
pub const ENV_BASE_URL: &str = "CIPHER_AI_BASE_URL";
/// Environment variable that overrides the default model for any provider.
pub const ENV_MODEL: &str = "CIPHER_AI_MODEL";

/// Request timeout (matches the original Groq client behavior).
const TIMEOUT_SECS: u64 = 120;
/// Max output tokens per chat call.
const MAX_TOKENS: u32 = 4096;
/// Low temperature: deterministic, security-focused output.
const TEMPERATURE: f32 = 0.1;
/// Anthropic API version header value.
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Supported AI providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiProvider {
    Groq,
    OpenAI,
    Anthropic,
}

impl AiProvider {
    /// Parse a provider string (case-insensitive, with the `claude` alias).
    pub fn parse(s: &str) -> Option<AiProvider> {
        match s.trim().to_ascii_lowercase().as_str() {
            "groq" => Some(AiProvider::Groq),
            "openai" => Some(AiProvider::OpenAI),
            "anthropic" | "claude" => Some(AiProvider::Anthropic),
            _ => None,
        }
    }

    /// Canonical string form (matches the `config set provider` values).
    pub fn as_str(&self) -> &'static str {
        match self {
            AiProvider::Groq => PROVIDER_GROQ,
            AiProvider::OpenAI => PROVIDER_OPENAI,
            AiProvider::Anthropic => PROVIDER_ANTHROPIC,
        }
    }

    /// Human-friendly display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            AiProvider::Groq => "Groq",
            AiProvider::OpenAI => "OpenAI",
            AiProvider::Anthropic => "Anthropic",
        }
    }

    /// The environment variable holding this provider's API key.
    pub fn env_var(&self) -> &'static str {
        match self {
            AiProvider::Groq => "GROQ_API_KEY",
            AiProvider::OpenAI => "OPENAI_API_KEY",
            AiProvider::Anthropic => "ANTHROPIC_API_KEY",
        }
    }

    /// The `cipher-ai config set <key>` name for this provider's key.
    pub fn config_key(&self) -> &'static str {
        match self {
            AiProvider::Groq => "groq-api-key",
            AiProvider::OpenAI => "openai-api-key",
            AiProvider::Anthropic => "anthropic-api-key",
        }
    }

    /// Default API base URL (overridable via CIPHER_AI_BASE_URL).
    pub fn default_base_url(&self) -> &'static str {
        match self {
            AiProvider::Groq => "https://api.groq.com/openai/v1",
            AiProvider::OpenAI => "https://api.openai.com/v1",
            AiProvider::Anthropic => "https://api.anthropic.com/v1",
        }
    }

    /// Default model ID (overridable via CIPHER_AI_MODEL or the `model` arg).
    pub fn default_model(&self) -> &'static str {
        match self {
            AiProvider::Groq => "llama-3.3-70b-versatile",
            AiProvider::OpenAI => "gpt-4o-mini",
            AiProvider::Anthropic => "claude-3-7-sonnet-20250219",
        }
    }

    /// True for providers that speak the OpenAI-compatible chat API.
    pub fn is_openai_compatible(&self) -> bool {
        matches!(self, AiProvider::Groq | AiProvider::OpenAI)
    }

    /// All supported providers.
    pub fn all() -> [AiProvider; 3] {
        [AiProvider::Groq, AiProvider::OpenAI, AiProvider::Anthropic]
    }
}

/// A provider-agnostic chat client.
pub struct AiClient {
    provider: AiProvider,
    api_key: String,
    base_url: String,
    http: Client,
}

impl AiClient {
    /// Build a client for the active provider (CIPHER_AI_PROVIDER, then the
    /// persisted config provider, then groq).
    pub fn from_env() -> Result<Self> {
        Self::from_provider(resolve_provider()?)
    }

    /// Build a client for a specific provider.
    pub fn from_provider(provider: AiProvider) -> Result<Self> {
        let api_key = resolve_api_key(provider)
            .ok_or_else(|| anyhow::anyhow!("{}", missing_key_message(provider)))?;

        // Custom base URL override (LiteLLM / vLLM / Ollama / corporate gateway).
        let base_url = std::env::var(ENV_BASE_URL)
            .ok()
            .map(|u| u.trim_end_matches('/').to_string())
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| provider.default_base_url().to_string());

        let http = Client::builder()
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            provider,
            api_key,
            base_url,
            http,
        })
    }

    /// The active provider.
    pub fn provider(&self) -> AiProvider {
        self.provider
    }

    /// The API base URL this client talks to.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Send a chat completion request.
    pub async fn chat(
        &self,
        system_prompt: &str,
        user_message: &str,
        model: Option<&str>,
    ) -> Result<String> {
        match self.provider {
            AiProvider::Anthropic => {
                self.chat_anthropic(system_prompt, user_message, model, false)
                    .await
            }
            _ => {
                self.chat_openai_compatible(system_prompt, user_message, model, false)
                    .await
            }
        }
    }

    /// Send a chat completion request and encourage a structured JSON response.
    ///
    /// Uses `response_format: json_object` on OpenAI-compatible providers
    /// (requires the prompt to mention JSON, which we append) and a prompt
    /// instruction on Anthropic, which has no equivalent field.
    pub async fn chat_json(
        &self,
        system_prompt: &str,
        user_message: &str,
        model: Option<&str>,
    ) -> Result<String> {
        match self.provider {
            AiProvider::Anthropic => {
                self.chat_anthropic(system_prompt, user_message, model, true)
                    .await
            }
            _ => {
                self.chat_openai_compatible(system_prompt, user_message, model, true)
                    .await
            }
        }
    }

    /// Run a single agent turn against the active provider.
    ///
    /// Composes the system prompt (base instructions plus the rendered tool
    /// catalog and output contract) and the conversation history into one
    /// JSON-mode request, then parses and validates the reply into an
    /// [`AgentTurn`].
    ///
    /// Returns a structured [`AgentTurnError`] on failure so callers can feed
    /// [`recovery_message`] back to the model and retry instead of
    /// terminating a run on one malformed reply.
    pub async fn agent_turn(
        &self,
        system_prompt: &str,
        history: &[AgentMessage],
        tools: &[ToolSchema],
        model: Option<&str>,
    ) -> Result<AgentTurn, AgentTurnError> {
        let system = build_agent_system_prompt(system_prompt, tools);
        let user = build_agent_user_prompt(history);
        let raw = self
            .chat_json(&system, &user, model)
            .await
            .map_err(|e| AgentTurnError::Api {
                message: format!("{:#}", e),
            })?;
        parse_agent_turn(&raw, tools)
    }

    /// Run [`AiClient::agent_turn`] with automatic recovery.
    ///
    /// Structured parse errors are fed back to the model as corrective
    /// observations (up to `max_retries` times); transient API errors back
    /// off briefly before retrying. Returns the first successful turn, or the
    /// last error once retries are exhausted.
    pub async fn agent_turn_with_retries(
        &self,
        system_prompt: &str,
        history: &[AgentMessage],
        tools: &[ToolSchema],
        model: Option<&str>,
        max_retries: usize,
    ) -> Result<AgentTurn, AgentTurnError> {
        let mut working = history.to_vec();
        for attempt in 0..=max_retries {
            match self.agent_turn(system_prompt, &working, tools, model).await {
                Ok(turn) => return Ok(turn),
                Err(err) => {
                    if attempt == max_retries {
                        return Err(err);
                    }
                    match &err {
                        AgentTurnError::Api { .. } => {
                            tokio::time::sleep(std::time::Duration::from_millis(
                                500 * (attempt as u64 + 1),
                            ))
                            .await;
                        }
                        _ => {
                            working.push(AgentMessage {
                                role: AgentRole::Tool,
                                content: recovery_message(&err),
                            });
                        }
                    }
                }
            }
        }
        unreachable!("loop always returns by attempt == max_retries")
    }

    /// Resolve the model to use: explicit arg > CIPHER_AI_MODEL > provider default.
    fn resolve_model(&self, model: Option<&str>) -> String {
        model
            .map(str::to_string)
            .or_else(|| std::env::var(ENV_MODEL).ok())
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| self.provider.default_model().to_string())
    }

    // ── OpenAI-compatible (Groq + OpenAI) ─────────────────────────────

    async fn chat_openai_compatible(
        &self,
        system: &str,
        user: &str,
        model: Option<&str>,
        json_mode: bool,
    ) -> Result<String> {
        let mut user_message = user.to_string();
        if json_mode {
            user_message.push_str(
                "\n\nRespond with ONLY valid JSON. Do not include any other text or markdown formatting.",
            );
        }

        let request = ChatRequest {
            model: self.resolve_model(model),
            messages: vec![
                ChatMessage {
                    role: "system",
                    content: system.to_string(),
                },
                ChatMessage {
                    role: "user",
                    content: user_message,
                },
            ],
            temperature: TEMPERATURE,
            max_tokens: MAX_TOKENS,
            stream: false,
            response_format: if json_mode {
                Some(ResponseFormat {
                    kind: "json_object",
                })
            } else {
                None
            },
        };

        let response = self
            .http
            .post(format!("{}/chat/completions", self.base_url))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to send chat request to AI provider")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            let message = extract_error_message(&body).unwrap_or(body);
            anyhow::bail!(
                "{} API error ({}): {}",
                self.provider.display_name(),
                status,
                message
            );
        }

        let chat_response: ChatResponse = response
            .json()
            .await
            .context("Failed to parse AI chat response")?;

        chat_response
            .choices
            .into_iter()
            .next()
            .and_then(|c| c.message.content)
            .filter(|c| !c.trim().is_empty())
            .context("AI returned an empty response")
    }

    // ── Anthropic Messages API ────────────────────────────────────────

    async fn chat_anthropic(
        &self,
        system: &str,
        user: &str,
        model: Option<&str>,
        json_mode: bool,
    ) -> Result<String> {
        let mut user_message = user.to_string();
        if json_mode {
            user_message.push_str(
                "\n\nRespond with ONLY valid JSON. Do not include any other text or markdown formatting.",
            );
        }

        let request = AnthropicRequest {
            model: self.resolve_model(model),
            max_tokens: MAX_TOKENS,
            temperature: TEMPERATURE,
            system: system.to_string(),
            messages: vec![AnthropicMessage {
                role: "user",
                content: user_message,
            }],
        };

        let response = self
            .http
            .post(format!("{}/messages", self.base_url))
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to send chat request to Anthropic API")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            let message = extract_error_message(&body).unwrap_or(body);
            anyhow::bail!("Anthropic API error ({}): {}", status, message);
        }

        let parsed: AnthropicResponse = response
            .json()
            .await
            .context("Failed to parse Anthropic chat response")?;

        parsed
            .content
            .into_iter()
            .find(|c| c.kind.as_deref() == Some("text"))
            .and_then(|c| c.text)
            .filter(|t| !t.trim().is_empty())
            .context("AI returned an empty response")
    }
}

// ── Request / response models ────────────────────────────────────────

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: &'static str,
    content: String,
}

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: f32,
    max_tokens: u32,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
}

#[derive(Debug, Serialize)]
struct ResponseFormat {
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Debug, serde::Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Debug, serde::Deserialize)]
struct ChatChoice {
    message: ChatResponseMessage,
}

#[derive(Debug, serde::Deserialize)]
struct ChatResponseMessage {
    content: Option<String>,
}

#[derive(Debug, Serialize)]
struct AnthropicMessage {
    role: &'static str,
    content: String,
}

#[derive(Debug, Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    temperature: f32,
    system: String,
    messages: Vec<AnthropicMessage>,
}

#[derive(Debug, serde::Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContent>,
}

#[derive(Debug, serde::Deserialize)]
struct AnthropicContent {
    #[serde(rename = "type")]
    kind: Option<String>,
    text: Option<String>,
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Resolve the active provider: CIPHER_AI_PROVIDER > config provider > groq.
fn resolve_provider() -> Result<AiProvider> {
    let raw = std::env::var(ENV_PROVIDER)
        .ok()
        .or_else(crate::config::stored_provider)
        .unwrap_or_else(|| PROVIDER_GROQ.to_string());

    AiProvider::parse(&raw).context(format!(
        "Unknown AI provider '{}' (set via {} or `cipher-ai config set provider`). Supported: {}",
        raw,
        ENV_PROVIDER,
        AiProvider::all()
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// Resolve the API key for a provider: env var first, then the persisted
/// config-file key for that provider.
fn resolve_api_key(provider: AiProvider) -> Option<String> {
    let from_env = std::env::var(provider.env_var()).ok();
    let from_config: Option<String> = match provider {
        AiProvider::Groq => crate::config::stored_api_key(),
        AiProvider::OpenAI => crate::config::stored_openai_api_key(),
        AiProvider::Anthropic => crate::config::stored_anthropic_api_key(),
    };
    from_env.filter(|k| !k.is_empty()).or(from_config)
}

/// Build the actionable "missing key" error for a provider.
fn missing_key_message(provider: AiProvider) -> String {
    format!(
        "{} not found. Set it via:\n  export {}=your_key_here\n  or add it to a .env file in your project root.\n  or persist it with: cipher-ai config set {} <key>",
        provider.env_var(),
        provider.env_var(),
        provider.config_key()
    )
}

/// Pull `error.message` out of a provider error body. Both the OpenAI-compatible
/// and Anthropic APIs shape errors as `{"error": {"message": "..."}}`.
fn extract_error_message(body: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct ErrorBody {
        error: Option<ErrorDetail>,
    }
    #[derive(serde::Deserialize)]
    struct ErrorDetail {
        message: Option<String>,
    }

    serde_json::from_str::<ErrorBody>(body)
        .ok()?
        .error?
        .message
        .filter(|m| !m.trim().is_empty())
}

// ── Agent tool-calling protocol ─────────────────────────────────────
//
// Phase 0 of the autonomous pentester: a structured, provider-agnostic
// tool-call protocol layered on top of [`AiClient::chat_json`]. The Phase 1
// agent loop (src/pentest/agent.rs) builds a tool catalog and conversation
// history, calls [`AiClient::agent_turn`], executes the returned tool call,
// appends the observation, and repeats until the model emits a `summary`.
//
// Every model reply is a single JSON object with one of two shapes:
//
//   1. Call a tool:  {"thought": "...", "action": {"tool": "...", "args": {...}}}
//   2. Finish:       {"thought": "...", "summary": {"summary": "...", "findings": [...]}}
//
// Responses that fail validation are classified into a structured
// [`AgentTurnError`] so the loop can feed a corrective observation back to
// the model and retry instead of dying on one bad turn.

/// Description of a tool the agent may call.
///
/// `parameters` is a JSON Schema object (subset) describing the tool's
/// arguments. Use [`ToolSchema::no_params`] for argument-less tools.
#[derive(Debug, Clone, Serialize)]
pub struct ToolSchema {
    /// Tool name as the model references it (lower_snake_case).
    pub name: &'static str,
    /// What the tool does, when to use it, and what it returns.
    pub description: &'static str,
    /// JSON Schema for `args` (defaults to an object with no properties).
    #[serde(default = "default_tool_parameters")]
    pub parameters: serde_json::Value,
}

/// Default (empty) JSON Schema for a tool that takes no arguments.
fn default_tool_parameters() -> serde_json::Value {
    serde_json::json!({ "type": "object", "properties": {} })
}

/// Default (empty) arguments object for tool calls that omit `args`.
fn default_empty_object() -> serde_json::Value {
    serde_json::json!({})
}

impl ToolSchema {
    /// Build a schema for a tool that takes no arguments.
    pub fn no_params(name: &'static str, description: &'static str) -> Self {
        Self {
            name,
            description,
            parameters: default_tool_parameters(),
        }
    }
}

/// A single agent action: invoke a tool from the catalog.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolCall {
    /// Tool name (must exist in the catalog).
    pub tool: String,
    /// Arguments as a JSON object; empty object when the tool takes none.
    #[serde(default = "default_empty_object")]
    pub args: serde_json::Value,
}

/// A candidate finding the agent reports when it finishes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentFinding {
    pub title: String,
    /// "critical" | "high" | "medium" | "low" | "info"
    #[serde(default = "default_finding_severity")]
    pub severity: String,
    /// Target endpoint (e.g. "POST /api/login"), when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub description: String,
    /// Request/response evidence proving the finding.
    #[serde(default)]
    pub evidence: Vec<String>,
}

fn default_finding_severity() -> String {
    "medium".to_string()
}

/// The agent's decision that the objective is complete.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentSummary {
    /// Final summary of what was done and discovered.
    pub summary: String,
    /// Findings discovered during the run (may be empty).
    #[serde(default)]
    pub findings: Vec<AgentFinding>,
}

/// One turn of the agent loop, produced by the model.
///
/// Exactly one of `action` / `summary` is set; `summary` means the agent is
/// done and no further turns should be requested.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentTurn {
    /// The agent's reasoning for this turn.
    pub thought: String,
    /// The tool to invoke, when the agent is not finished.
    #[serde(default)]
    pub action: Option<ToolCall>,
    /// The terminal summary, when the agent is finished.
    #[serde(default)]
    pub summary: Option<AgentSummary>,
}

impl AgentTurn {
    /// True when the agent decided it is done (summary present).
    pub fn is_terminal(&self) -> bool {
        self.summary.is_some()
    }

    /// The tool call to execute, if this turn invokes a tool.
    pub fn tool_call(&self) -> Option<&ToolCall> {
        self.action.as_ref()
    }
}

/// Role of a message in the agent conversation history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRole {
    /// The user's objective (typically the first message).
    User,
    /// A prior agent turn (thought + tool call).
    Assistant,
    /// The observation returned after executing a tool.
    Tool,
}

/// One entry in the agent conversation history.
#[derive(Debug, Clone)]
pub struct AgentMessage {
    pub role: AgentRole,
    pub content: String,
}

/// A structured reason why an [`AgentTurn`] could not be produced.
///
/// The agent loop inspects this variant to feed a corrective observation
/// back to the model ([`recovery_message`]) and retry, so a single
/// malformed reply never terminates a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentTurnError {
    /// The model output contained no usable JSON object.
    NotJson,
    /// The JSON object was missing the required `thought` field.
    MissingThought,
    /// Neither `action` nor `summary` was present.
    MissingAction,
    /// Both `action` and `summary` were present in the same turn.
    AmbiguousTurn,
    /// `action.tool` is not in the provided catalog.
    UnknownTool { tool: String },
    /// `action.args` is present but not a JSON object.
    InvalidArgs { tool: String, detail: String },
    /// `summary` is present but not a valid [`AgentSummary`].
    InvalidSummary { detail: String },
    /// The model API request itself failed (network, auth, rate limit).
    Api { message: String },
}

impl std::fmt::Display for AgentTurnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentTurnError::NotJson => write!(f, "model response was not valid JSON"),
            AgentTurnError::MissingThought => {
                write!(f, "model response missing required \"thought\" field")
            }
            AgentTurnError::MissingAction => {
                write!(
                    f,
                    "model response contained neither \"action\" nor \"summary\""
                )
            }
            AgentTurnError::AmbiguousTurn => {
                write!(
                    f,
                    "model response contained both \"action\" and \"summary\""
                )
            }
            AgentTurnError::UnknownTool { tool } => {
                write!(f, "model referenced unknown tool \"{}\"", tool)
            }
            AgentTurnError::InvalidArgs { tool, detail } => {
                write!(f, "invalid arguments for tool \"{}\": {}", tool, detail)
            }
            AgentTurnError::InvalidSummary { detail } => {
                write!(f, "invalid summary object: {}", detail)
            }
            AgentTurnError::Api { message } => write!(f, "agent API error: {}", message),
        }
    }
}

impl std::error::Error for AgentTurnError {}

// ── Prompt construction ─────────────────────────────────────────────

/// Output contract appended to every agent system prompt.
const AGENT_OUTPUT_CONTRACT: &str = "OUTPUT CONTRACT — respond with exactly one JSON object.\n\
You MUST either call a tool or finish with a summary — never both in one turn.\n\
To call a tool:    {\"thought\": \"<why>\", \"action\": {\"tool\": \"<name>\", \"args\": {<parameters>}}}\n\
To finish:         {\"thought\": \"<why>\", \"summary\": {\"summary\": \"<final summary>\", \"findings\": [{\"title\": \"...\", \"severity\": \"critical|high|medium|low|info\", \"endpoint\": \"...\", \"description\": \"...\", \"evidence\": [\"...\"]}]}}\n\
Findings may be an empty array. Do not emit markdown fences or any text outside the JSON object.";

/// Termination guidance appended to every agent system prompt.
const AGENT_TERMINATION_RULES: &str = "TERMINATION — only emit \"summary\" once the objective is complete and every \
relevant tool result has been considered. While you still need information or action, emit \"action\".";

/// Compose the full agent system prompt: role instructions + tool catalog
/// + the output contract.
fn build_agent_system_prompt(base: &str, tools: &[ToolSchema]) -> String {
    format!(
        "{}\n\n{}\n\n{}\n\n{}",
        base.trim(),
        render_tool_catalog(tools),
        AGENT_OUTPUT_CONTRACT,
        AGENT_TERMINATION_RULES
    )
}

/// Compose the user prompt for an agent turn from the conversation history.
fn build_agent_user_prompt(history: &[AgentMessage]) -> String {
    format!(
        "CONVERSATION SO FAR\n{}\nRespond with the next JSON object.",
        render_agent_history(history)
    )
}

/// Render the tool catalog for inclusion in the system prompt.
pub fn render_tool_catalog(tools: &[ToolSchema]) -> String {
    let mut out = String::from("AVAILABLE TOOLS\n");
    for tool in tools {
        let params = render_parameters(tool);
        let params = if params.is_empty() {
            String::new()
        } else {
            format!("({})", params)
        };
        out.push_str(&format!(
            "- {}{}\n    {}\n",
            tool.name, params, tool.description
        ));
    }
    out.push_str("\nCall only tools listed here with the exact argument names given.\n");
    out
}

/// Render a tool's JSON Schema properties as `name: type` (required marked
/// with `*`).
fn render_parameters(tool: &ToolSchema) -> String {
    let Some(props) = tool
        .parameters
        .get("properties")
        .and_then(|p| p.as_object())
    else {
        return String::new();
    };
    let required: Vec<&str> = tool
        .parameters
        .pointer("/required")
        .and_then(|r| r.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();

    let parts: Vec<String> = props
        .iter()
        .map(|(name, schema)| {
            let ty = schema.get("type").and_then(|v| v.as_str()).unwrap_or("any");
            let marker = if required.contains(&name.as_str()) {
                "*"
            } else {
                ""
            };
            format!("{}{}: {}", name, marker, ty)
        })
        .collect();
    parts.join(", ")
}

/// Render the conversation history as a compact transcript for the model.
pub fn render_agent_history(history: &[AgentMessage]) -> String {
    let mut out = String::new();
    for msg in history {
        let tag = match msg.role {
            AgentRole::User => "OBJECTIVE",
            AgentRole::Assistant => "AGENT",
            AgentRole::Tool => "OBSERVATION",
        };
        out.push_str(&format!("[{}] {}\n", tag, msg.content.trim()));
    }
    out
}

// ── Parsing and validation ──────────────────────────────────────────

/// Extract the first JSON object from a model response, tolerating markdown
/// fences, prose, and trailing content.
pub fn extract_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let end = raw[start..].rfind('}').map(|i| start + i + 1)?;
    Some(&raw[start..end])
}

/// Parse and validate a raw model response into an [`AgentTurn`].
///
/// Returns a structured [`AgentTurnError`] on failure so the caller can feed
/// [`recovery_message`] back to the model and retry.
pub fn parse_agent_turn(raw: &str, tools: &[ToolSchema]) -> Result<AgentTurn, AgentTurnError> {
    let json_str = extract_json_object(raw).ok_or(AgentTurnError::NotJson)?;
    let value: serde_json::Value =
        serde_json::from_str(json_str).map_err(|_| AgentTurnError::NotJson)?;

    let has_thought = value
        .get("thought")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .is_some_and(|t| !t.is_empty());
    let has_action = value.get("action").is_some();
    let has_summary = value.get("summary").is_some();

    if !has_thought {
        return Err(AgentTurnError::MissingThought);
    }
    if has_action && has_summary {
        return Err(AgentTurnError::AmbiguousTurn);
    }
    if !has_action && !has_summary {
        return Err(AgentTurnError::MissingAction);
    }

    // Best-effort tool name so `InvalidArgs` recovery messages name the tool.
    let action_tool = value
        .pointer("/action/tool")
        .and_then(|t| t.as_str())
        .map(str::to_string);

    let turn: AgentTurn = serde_json::from_value(value).map_err(|e| {
        if has_summary {
            AgentTurnError::InvalidSummary {
                detail: format!("{}", e),
            }
        } else {
            AgentTurnError::InvalidArgs {
                tool: action_tool
                    .clone()
                    .unwrap_or_else(|| "<unknown>".to_string()),
                detail: format!("{}", e),
            }
        }
    })?;

    // Reject `"action": null` / `"summary": null`, which deserialize to
    // `None` and would otherwise leave the agent loop with neither a tool
    // call nor a terminal summary.
    if turn.action.is_none() && turn.summary.is_none() {
        return Err(AgentTurnError::MissingAction);
    }

    if let Some(call) = &turn.action {
        validate_tool_call(call, tools)?;
    }
    Ok(turn)
}

/// Validate a parsed tool call against the catalog.
fn validate_tool_call(call: &ToolCall, tools: &[ToolSchema]) -> Result<(), AgentTurnError> {
    if !tools.iter().any(|t| t.name == call.tool) {
        return Err(AgentTurnError::UnknownTool {
            tool: call.tool.clone(),
        });
    }
    if !call.args.is_object() {
        return Err(AgentTurnError::InvalidArgs {
            tool: call.tool.clone(),
            detail: format!(
                "args must be a JSON object, got {}",
                describe_value_type(&call.args)
            ),
        });
    }
    Ok(())
}

/// Short human-readable type name for a JSON value (error messages).
fn describe_value_type(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// The corrective message to append to the history after a failed turn.
///
/// The agent loop appends this as a `Tool`-role observation and retries, so
/// the model learns precisely what it got wrong.
pub fn recovery_message(err: &AgentTurnError) -> String {
    match err {
        AgentTurnError::NotJson => {
            "Your previous response was not valid JSON. Reply with ONLY a single JSON object."
                .to_string()
        }
        AgentTurnError::MissingThought => {
            "Your previous JSON object was missing the required \"thought\" field.".to_string()
        }
        AgentTurnError::MissingAction => {
            "Your previous JSON object contained neither \"action\" nor \"summary\". \
             You must either call a tool or finish with a summary."
                .to_string()
        }
        AgentTurnError::AmbiguousTurn => {
            "Your previous JSON object contained BOTH \"action\" and \"summary\". \
             Provide exactly one of them."
                .to_string()
        }
        AgentTurnError::UnknownTool { tool } => {
            format!(
                "Tool \"{}\" is not in the catalog. Use one of the AVAILABLE TOOLS.",
                tool
            )
        }
        AgentTurnError::InvalidArgs { tool, detail } => {
            format!(
                "Invalid arguments for tool \"{}\": {}. Fix the args and retry.",
                tool, detail
            )
        }
        AgentTurnError::InvalidSummary { detail } => {
            format!(
                "Your summary object was invalid: {}. Fix it and retry.",
                detail
            )
        }
        AgentTurnError::Api { message } => {
            format!(
                "The model API request failed: {}. Retry the request.",
                message
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that touch process-global environment variables so
    /// parallel cargo-test threads cannot interfere with each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Run `f` with `key` set to `value`, restoring the previous state after.
    ///
    /// Acquires [`ENV_LOCK`] exactly once. For nested env mutations inside
    /// `f`, use [`set_env_guarded`] / [`remove_env_guarded`] instead, since
    /// `std::sync::Mutex` is not reentrant and re-locking would deadlock.
    fn with_env(key: &str, value: &str, f: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_env_guarded(key, value, f);
    }

    /// Set `key` and run `f`, restoring the previous value after.
    ///
    /// Caller MUST already hold [`ENV_LOCK`] (i.e. be inside a `with_env`
    /// or a `let _guard = ENV_LOCK.lock()` block).
    fn set_env_guarded(key: &str, value: &str, f: impl FnOnce()) {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        f();
        match previous {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    /// Remove `key` and run `f`, restoring the previous value after.
    ///
    /// Caller MUST already hold [`ENV_LOCK`].
    fn remove_env_guarded(key: &str, f: impl FnOnce()) {
        let previous = std::env::var(key).ok();
        std::env::remove_var(key);
        f();
        if let Some(v) = previous {
            std::env::set_var(key, v);
        }
    }

    #[test]
    fn test_provider_parse_valid() {
        assert_eq!(AiProvider::parse("groq"), Some(AiProvider::Groq));
        assert_eq!(AiProvider::parse("openai"), Some(AiProvider::OpenAI));
        assert_eq!(AiProvider::parse("anthropic"), Some(AiProvider::Anthropic));
        // Aliases + case-insensitivity + whitespace tolerance
        assert_eq!(AiProvider::parse("claude"), Some(AiProvider::Anthropic));
        assert_eq!(AiProvider::parse("GROQ"), Some(AiProvider::Groq));
        assert_eq!(AiProvider::parse(" OpenAI "), Some(AiProvider::OpenAI));
    }

    #[test]
    fn test_provider_parse_invalid() {
        assert_eq!(AiProvider::parse("gemini"), None);
        assert_eq!(AiProvider::parse(""), None);
        assert_eq!(AiProvider::parse("groqai"), None);
    }

    #[test]
    fn test_provider_metadata() {
        assert_eq!(AiProvider::Groq.env_var(), "GROQ_API_KEY");
        assert_eq!(AiProvider::OpenAI.env_var(), "OPENAI_API_KEY");
        assert_eq!(AiProvider::Anthropic.env_var(), "ANTHROPIC_API_KEY");
        assert_eq!(AiProvider::Groq.config_key(), "groq-api-key");
        assert_eq!(AiProvider::OpenAI.config_key(), "openai-api-key");
        assert_eq!(AiProvider::Anthropic.config_key(), "anthropic-api-key");
        assert!(AiProvider::Groq.is_openai_compatible());
        assert!(AiProvider::OpenAI.is_openai_compatible());
        assert!(!AiProvider::Anthropic.is_openai_compatible());
        assert_eq!(AiProvider::all().len(), 3);
    }

    #[test]
    fn test_provider_defaults() {
        // The historical default — must stay stable for backward compatibility.
        assert_eq!(AiProvider::Groq.default_model(), "llama-3.3-70b-versatile");
        assert_eq!(AiProvider::OpenAI.default_model(), "gpt-4o-mini");
        assert_eq!(
            AiProvider::Anthropic.default_model(),
            "claude-3-7-sonnet-20250219"
        );
        assert_eq!(
            AiProvider::Groq.default_base_url(),
            "https://api.groq.com/openai/v1"
        );
        assert_eq!(
            AiProvider::OpenAI.default_base_url(),
            "https://api.openai.com/v1"
        );
        assert_eq!(
            AiProvider::Anthropic.default_base_url(),
            "https://api.anthropic.com/v1"
        );
    }

    #[test]
    fn test_missing_key_message_mentions_env_and_config() {
        let msg = missing_key_message(AiProvider::OpenAI);
        assert!(msg.contains("OPENAI_API_KEY"));
        assert!(msg.contains("openai-api-key"));
        let msg = missing_key_message(AiProvider::Groq);
        assert!(msg.contains("GROQ_API_KEY"));
    }

    #[test]
    fn test_from_provider_requires_key() {
        // No keys configured in this environment — from_provider must error.
        // The removals are nested so the assertion runs while the keys are
        // actually absent (each `remove_env_guarded` restores on exit).
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        remove_env_guarded("GROQ_API_KEY", || {
            remove_env_guarded("OPENAI_API_KEY", || {
                remove_env_guarded("ANTHROPIC_API_KEY", || {
                    assert!(AiClient::from_provider(AiProvider::OpenAI).is_err());
                });
            });
        });
    }

    #[test]
    fn test_from_provider_honors_base_url_override() {
        with_env("OPENAI_API_KEY", "sk-test-123", || {
            set_env_guarded(
                "CIPHER_AI_BASE_URL",
                "https://gateway.example.com/v1/",
                || {
                    let client = AiClient::from_provider(AiProvider::OpenAI).unwrap();
                    assert_eq!(client.base_url(), "https://gateway.example.com/v1");
                    assert_eq!(client.provider(), AiProvider::OpenAI);
                },
            );
        });
    }

    #[test]
    fn test_from_provider_uses_default_base_url() {
        with_env("ANTHROPIC_API_KEY", "sk-ant-test", || {
            remove_env_guarded("CIPHER_AI_BASE_URL", || {
                let client = AiClient::from_provider(AiProvider::Anthropic).unwrap();
                assert_eq!(client.base_url(), "https://api.anthropic.com/v1");
            });
        });
    }

    #[test]
    fn test_resolve_model_priority() {
        with_env("OPENAI_API_KEY", "sk-test", || {
            set_env_guarded("CIPHER_AI_MODEL", "gpt-4o", || {
                let client = AiClient::from_provider(AiProvider::OpenAI).unwrap();
                // Explicit arg beats env override beats default.
                assert_eq!(client.resolve_model(Some("custom-model")), "custom-model");
                assert_eq!(client.resolve_model(None), "gpt-4o");
                remove_env_guarded("CIPHER_AI_MODEL", || {
                    assert_eq!(
                        client.resolve_model(None),
                        AiProvider::OpenAI.default_model()
                    );
                });
            });
        });
    }

    #[test]
    fn test_resolve_provider_env_wins_over_config() {
        // Config provider is only consulted when the env var is absent.
        with_env("CIPHER_AI_PROVIDER", "openai", || {
            assert_eq!(resolve_provider().unwrap(), AiProvider::OpenAI);
        });
    }

    #[test]
    fn test_resolve_provider_defaults_to_groq() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        remove_env_guarded("CIPHER_AI_PROVIDER", || {
            // A real config file on disk may pin a provider; only assert the
            // default when no config provider is stored.
            if crate::config::stored_provider().is_none() {
                assert_eq!(resolve_provider().unwrap(), AiProvider::Groq);
            }
        });
    }

    #[test]
    fn test_resolve_provider_rejects_unknown() {
        with_env("CIPHER_AI_PROVIDER", "gemini", || {
            assert!(resolve_provider().is_err());
        });
    }

    #[test]
    fn test_extract_error_message() {
        let body = r#"{"error": {"type": "invalid_request_error", "message": "Invalid model"}}"#;
        assert_eq!(
            extract_error_message(body).as_deref(),
            Some("Invalid model")
        );
        assert_eq!(extract_error_message("not json"), None);
        assert_eq!(extract_error_message(r#"{"ok": true}"#), None);
        assert_eq!(extract_error_message(r#"{"error": {"message": ""}}"#), None);
    }

    #[test]
    fn test_chat_request_serializes_json_mode() {
        let req = ChatRequest {
            model: "m".to_string(),
            messages: vec![
                ChatMessage {
                    role: "system",
                    content: "sys".to_string(),
                },
                ChatMessage {
                    role: "user",
                    content: "usr".to_string(),
                },
            ],
            temperature: 0.1,
            max_tokens: 4096,
            stream: false,
            response_format: Some(ResponseFormat {
                kind: "json_object",
            }),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"response_format\":{\"type\":\"json_object\"}"));
        assert!(json.contains("\"role\":\"system\""));
    }

    #[test]
    fn test_chat_request_omits_json_mode_when_disabled() {
        let req = ChatRequest {
            model: "m".to_string(),
            messages: vec![],
            temperature: 0.1,
            max_tokens: 4096,
            stream: false,
            response_format: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("response_format"));
    }

    #[test]
    fn test_anthropic_request_shape() {
        let req = AnthropicRequest {
            model: "claude-3-7-sonnet-20250219".to_string(),
            max_tokens: 4096,
            temperature: 0.1,
            system: "sys".to_string(),
            messages: vec![AnthropicMessage {
                role: "user",
                content: "hello".to_string(),
            }],
        };
        let json = serde_json::to_string(&req).unwrap();
        // Anthropic requires: system top-level, max_tokens top-level, messages array.
        assert!(json.contains("\"system\":\"sys\""));
        assert!(json.contains("\"max_tokens\":4096"));
        assert!(json.contains("\"role\":\"user\""));
    }

    #[test]
    fn test_anthropic_response_parses_text() {
        let body = r#"{
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": "hello from claude"}
            ],
            "stop_reason": "end_turn"
        }"#;
        let parsed: AnthropicResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.content.len(), 1);
        assert_eq!(parsed.content[0].kind.as_deref(), Some("text"));
        assert_eq!(parsed.content[0].text.as_deref(), Some("hello from claude"));
    }

    #[test]
    fn test_openai_response_parses_content() {
        let body = r#"{
            "choices": [
                {"message": {"role": "assistant", "content": "hello from openai"}, "finish_reason": "stop"}
            ]
        }"#;
        let parsed: ChatResponse = serde_json::from_str(body).unwrap();
        assert_eq!(
            parsed.choices[0].message.content.as_deref(),
            Some("hello from openai")
        );
    }

    // ── Agent tool-calling protocol ─────────────────────────────────

    fn test_tools() -> [ToolSchema; 2] {
        [
            ToolSchema {
                name: "read_code",
                description: "Read a range of lines from a source file.",
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "file": {"type": "string"},
                        "start_line": {"type": "integer"}
                    },
                    "required": ["file"]
                }),
            },
            ToolSchema::no_params("list_files", "List files in the repository."),
        ]
    }

    #[test]
    fn test_parse_agent_turn_action() {
        let tools = test_tools();
        let raw = r#"{"thought": "inspect the route handler", "action": {"tool": "read_code", "args": {"file": "src/main.rs", "start_line": 10}}}"#;
        let turn = parse_agent_turn(raw, &tools).unwrap();
        assert_eq!(turn.thought, "inspect the route handler");
        let call = turn.tool_call().unwrap();
        assert_eq!(call.tool, "read_code");
        assert_eq!(call.args["file"], "src/main.rs");
        assert!(!turn.is_terminal());
    }

    #[test]
    fn test_parse_agent_turn_defaults_args_to_object() {
        let tools = test_tools();
        let raw = r#"{"thought": "t", "action": {"tool": "list_files"}}"#;
        let turn = parse_agent_turn(raw, &tools).unwrap();
        assert!(turn.tool_call().unwrap().args.is_object());
    }

    #[test]
    fn test_parse_agent_turn_summary() {
        let tools = test_tools();
        let raw = r#"{"thought": "done", "summary": {"summary": "Pentest complete", "findings": [{"title": "SQL Injection", "severity": "high", "endpoint": "POST /api/login", "description": "Error-based SQLi on the email field", "evidence": ["POST /api/login with 1' OR '1'='1 -> 500 + SQL syntax error"]}]}}"#;
        let turn = parse_agent_turn(raw, &tools).unwrap();
        assert!(turn.is_terminal());
        assert!(turn.action.is_none());
        let summary = turn.summary.unwrap();
        assert_eq!(summary.summary, "Pentest complete");
        assert_eq!(summary.findings.len(), 1);
        let finding = &summary.findings[0];
        assert_eq!(finding.title, "SQL Injection");
        assert_eq!(finding.severity, "high");
        assert_eq!(finding.endpoint.as_deref(), Some("POST /api/login"));
        assert_eq!(finding.evidence.len(), 1);
    }

    #[test]
    fn test_parse_agent_turn_summary_defaults_findings() {
        let raw = r#"{"thought": "done", "summary": {"summary": "all clear"}}"#;
        let turn = parse_agent_turn(raw, &[]).unwrap();
        assert!(turn.summary.unwrap().findings.is_empty());
    }

    #[test]
    fn test_parse_agent_turn_tolerates_markdown_fences() {
        let raw = "Here is the result:\n```json\n{\"thought\": \"ok\", \"summary\": {\"summary\": \"done\", \"findings\": []}}\n```\n";
        let turn = parse_agent_turn(raw, &[]).unwrap();
        assert!(turn.is_terminal());
    }

    #[test]
    fn test_parse_agent_turn_unknown_tool() {
        let tools = test_tools();
        let raw = r#"{"thought": "t", "action": {"tool": "delete_everything", "args": {}}}"#;
        assert_eq!(
            parse_agent_turn(raw, &tools),
            Err(AgentTurnError::UnknownTool {
                tool: "delete_everything".into()
            })
        );
    }

    #[test]
    fn test_parse_agent_turn_missing_thought() {
        let raw = r#"{"action": {"tool": "x", "args": {}}}"#;
        assert_eq!(
            parse_agent_turn(raw, &[]),
            Err(AgentTurnError::MissingThought)
        );
    }

    #[test]
    fn test_parse_agent_turn_missing_action_and_summary() {
        let raw = r#"{"thought": "hmm"}"#;
        assert_eq!(
            parse_agent_turn(raw, &[]),
            Err(AgentTurnError::MissingAction)
        );
    }

    #[test]
    fn test_parse_agent_turn_rejects_null_action_and_summary() {
        // Explicit nulls pass the presence checks but deserialize to None,
        // yielding a turn with neither a tool call nor a summary — reject it.
        let raw = r#"{"thought": "t", "action": null}"#;
        assert_eq!(
            parse_agent_turn(raw, &[]),
            Err(AgentTurnError::MissingAction)
        );
        let raw = r#"{"thought": "t", "summary": null}"#;
        assert_eq!(
            parse_agent_turn(raw, &[]),
            Err(AgentTurnError::MissingAction)
        );
    }

    #[test]
    fn test_parse_agent_turn_ambiguous() {
        let raw = r#"{"thought": "t", "action": {"tool": "x", "args": {}}, "summary": {"summary": "s", "findings": []}}"#;
        assert_eq!(
            parse_agent_turn(raw, &[]),
            Err(AgentTurnError::AmbiguousTurn)
        );
    }

    #[test]
    fn test_parse_agent_turn_args_must_be_object() {
        let tools = test_tools();
        let raw = r#"{"thought": "t", "action": {"tool": "list_files", "args": "everything"}}"#;
        assert!(matches!(
            parse_agent_turn(raw, &tools),
            Err(AgentTurnError::InvalidArgs { tool, .. }) if tool == "list_files"
        ));
    }

    #[test]
    fn test_parse_agent_turn_invalid_summary() {
        let raw = r#"{"thought": "t", "summary": "not an object"}"#;
        assert!(matches!(
            parse_agent_turn(raw, &[]),
            Err(AgentTurnError::InvalidSummary { .. })
        ));
    }

    #[test]
    fn test_parse_agent_turn_not_json() {
        assert_eq!(
            parse_agent_turn("the model rambled", &[]),
            Err(AgentTurnError::NotJson)
        );
        assert_eq!(parse_agent_turn("", &[]), Err(AgentTurnError::NotJson));
        assert_eq!(parse_agent_turn("[]", &[]), Err(AgentTurnError::NotJson));
    }

    #[test]
    fn test_recovery_message_covers_every_error() {
        let cases = [
            AgentTurnError::NotJson,
            AgentTurnError::MissingThought,
            AgentTurnError::MissingAction,
            AgentTurnError::AmbiguousTurn,
            AgentTurnError::UnknownTool {
                tool: "nope".into(),
            },
            AgentTurnError::InvalidArgs {
                tool: "x".into(),
                detail: "bad".into(),
            },
            AgentTurnError::InvalidSummary {
                detail: "bad".into(),
            },
            AgentTurnError::Api {
                message: "boom".into(),
            },
        ];
        for err in cases {
            let msg = recovery_message(&err);
            assert!(
                !msg.trim().is_empty(),
                "recovery message for {:?} was empty",
                err
            );
        }
        assert!(recovery_message(&AgentTurnError::UnknownTool {
            tool: "nope".into()
        })
        .contains("nope"));
    }

    #[test]
    fn test_agent_turn_error_is_std_error() {
        let err = AgentTurnError::UnknownTool { tool: "x".into() };
        let boxed: Box<dyn std::error::Error> = Box::new(err.clone());
        assert_eq!(boxed.to_string(), err.to_string());
        assert!(err.to_string().contains("x"));
    }

    #[test]
    fn test_render_tool_catalog_lists_tools_and_params() {
        let catalog = render_tool_catalog(&test_tools());
        assert!(catalog.contains("read_code"));
        assert!(catalog.contains("file*: string")); // required marked
        assert!(catalog.contains("start_line: integer"));
        assert!(catalog.contains("list_files"));
    }

    #[test]
    fn test_tool_schema_no_params_renders_empty() {
        let tool = ToolSchema::no_params("list_files", "List files.");
        assert!(render_parameters(&tool).is_empty());
    }

    #[test]
    fn test_render_agent_history_tags_roles() {
        let history = vec![
            AgentMessage {
                role: AgentRole::User,
                content: "Pentest /api/login".into(),
            },
            AgentMessage {
                role: AgentRole::Assistant,
                content: "call http_request".into(),
            },
            AgentMessage {
                role: AgentRole::Tool,
                content: "200 OK".into(),
            },
        ];
        let transcript = render_agent_history(&history);
        assert!(transcript.contains("[OBJECTIVE] Pentest /api/login"));
        assert!(transcript.contains("[AGENT] call http_request"));
        assert!(transcript.contains("[OBSERVATION] 200 OK"));
    }

    #[test]
    fn test_extract_json_object_handles_nested_braces() {
        let raw = r#"prefix {"a": {"b": [1, 2]}} suffix"#;
        assert_eq!(extract_json_object(raw), Some(r#"{"a": {"b": [1, 2]}}"#));
        assert_eq!(extract_json_object("no braces here"), None);
    }
}
