use anyhow::{Context, Result};
use colored::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const DEFAULT_MODELS: &[&str] = &[
    "llama-3.3-70b-versatile",
    "mixtral-8x7b-32768",
    "gemma2-9b-it",
];

/// Valid values for the `provider` config key.
const VALID_PROVIDERS: &[&str] = &["groq", "openai", "anthropic"];

#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct Config {
    /// Legacy Groq key (also accepted via the generic `api-key` / `key` aliases).
    pub(crate) groq_api_key: Option<String>,
    #[serde(default)]
    pub(crate) openai_api_key: Option<String>,
    #[serde(default)]
    pub(crate) anthropic_api_key: Option<String>,
    /// Active AI provider: "groq" | "openai" | "anthropic" (defaults to groq).
    #[serde(default)]
    pub(crate) provider: Option<String>,
    pub(crate) default_model: Option<String>,
}

/// Canonical location of the CipherAI config file.
/// All API key / model persistence goes through this single path.
pub(crate) fn config_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .context("Cannot find home directory")?;
    Ok(PathBuf::from(home).join(".cipher-ai").join("config.json"))
}

pub(crate) fn load_config() -> Result<Config> {
    let path = config_path()?;
    if path.exists() {
        let content = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&content).unwrap_or(Config::default()))
    } else {
        Ok(Config::default())
    }
}

fn save_config(config: &Config) -> Result<()> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(config)?;
    std::fs::write(&path, json)?;
    Ok(())
}

/// Persist the API key to the canonical config file, unless a key is
/// already configured. Used by `init` so the env var is remembered.
pub(crate) fn save_api_key_if_unset(key: &str) -> Result<()> {
    let mut config = load_config()?;
    if config.groq_api_key.is_none() {
        config.groq_api_key = Some(key.to_string());
        save_config(&config)?;
    }
    Ok(())
}

/// Read the stored API key from the canonical config file, if any.
pub(crate) fn stored_api_key() -> Option<String> {
    load_config().ok().and_then(|c| c.groq_api_key)
}

/// Read the stored OpenAI API key from the canonical config file, if any.
pub(crate) fn stored_openai_api_key() -> Option<String> {
    load_config().ok().and_then(|c| c.openai_api_key)
}

/// Read the stored Anthropic API key from the canonical config file, if any.
pub(crate) fn stored_anthropic_api_key() -> Option<String> {
    load_config().ok().and_then(|c| c.anthropic_api_key)
}

/// Read the persisted provider selection (None = default groq).
pub(crate) fn stored_provider() -> Option<String> {
    load_config().ok().and_then(|c| c.provider)
}

pub fn run_config_set(key: &str, value: &str) -> Result<()> {
    let mut config = load_config()?;
    match key {
        "groq-api-key" | "api-key" | "key" => {
            config.groq_api_key = Some(value.to_string());
            println!("  {} Groq API key set", "[OK]".green().bold());
        }
        "openai-api-key" => {
            config.openai_api_key = Some(value.to_string());
            println!("  {} OpenAI API key set", "[OK]".green().bold());
        }
        "anthropic-api-key" => {
            config.anthropic_api_key = Some(value.to_string());
            println!("  {} Anthropic API key set", "[OK]".green().bold());
        }
        "provider" => {
            let lower = value.to_ascii_lowercase();
            let normalized = match lower.as_str() {
                "claude" => "anthropic",
                other => other,
            };
            if !VALID_PROVIDERS.contains(&normalized) {
                anyhow::bail!(
                    "Unknown provider '{}'. Valid providers: {}",
                    value,
                    VALID_PROVIDERS.join(", ")
                );
            }
            config.provider = Some(normalized.to_string());
            println!(
                "  {} AI provider set to: {}",
                "[OK]".green().bold(),
                normalized
            );
        }
        "default-model" | "model" => {
            if !DEFAULT_MODELS.contains(&value) {
                eprintln!(
                    "  {} Unknown model '{}'. Available (Groq): {}",
                    "[!]".yellow(),
                    value,
                    DEFAULT_MODELS.join(", ")
                );
                println!("  Setting anyway — model may not work.");
            }
            config.default_model = Some(value.to_string());
            println!(
                "  {} Default model set to: {}",
                "[OK]".green().bold(),
                value
            );
        }
        _ => {
            anyhow::bail!(
                "Unknown config key: {key}. Valid keys: groq-api-key, openai-api-key, anthropic-api-key, provider, default-model"
            );
        }
    }
    save_config(&config)?;
    Ok(())
}

fn print_key_status(env_var: &str, stored: Option<&String>) {
    match (std::env::var(env_var).ok(), stored) {
        (Some(_), _) => println!("(set via {env_var} env var)"),
        (None, Some(v)) => println!("{v}"),
        (None, None) => println!("(not set)"),
    }
}

pub fn run_config_get(key: &str) -> Result<()> {
    let config = load_config()?;
    match key {
        "groq-api-key" | "api-key" | "key" => {
            print_key_status("GROQ_API_KEY", config.groq_api_key.as_ref());
        }
        "openai-api-key" => {
            print_key_status("OPENAI_API_KEY", config.openai_api_key.as_ref());
        }
        "anthropic-api-key" => {
            print_key_status("ANTHROPIC_API_KEY", config.anthropic_api_key.as_ref());
        }
        "provider" => match std::env::var("CIPHER_AI_PROVIDER").ok().or(config.provider) {
            Some(v) => println!("{v}"),
            None => println!("groq"),
        },
        "default-model" | "model" => match &config.default_model {
            Some(v) => println!("{v}"),
            None => println!("{}", DEFAULT_MODELS[0]),
        },
        _ => {
            anyhow::bail!(
                "Unknown config key: {key}. Valid keys: groq-api-key, openai-api-key, anthropic-api-key, provider, default-model"
            );
        }
    }
    Ok(())
}

/// Render one provider's key line: name, status, and the env var that sets it.
fn render_key_line(name: &str, env_var: &str, is_set: bool) -> String {
    format!(
        "  {} {}\n        {}",
        format!("{name}:").bold(),
        if is_set {
            "set [OK]".green().to_string()
        } else {
            "not set [WARN]".red().to_string()
        },
        format!("(env: {env_var})").dimmed()
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorKeyStatus {
    pub provider: String,
    pub key: String,
    pub env_var: String,
    pub configured: bool,
    pub value: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub provider: String,
    pub config_path: String,
    pub active_key_status: DoctorKeyStatus,
    pub provider_key_status: Vec<DoctorKeyStatus>,
    pub action: String,
    pub suggestion: String,
}

pub fn doctor_report() -> Result<DoctorReport> {
    let config = load_config().unwrap_or_default();
    let provider = std::env::var("CIPHER_AI_PROVIDER")
        .ok()
        .or(config.provider.clone())
        .unwrap_or_else(|| "groq".to_string());

    let active_provider =
        crate::llm::AiProvider::parse(&provider).unwrap_or(crate::llm::AiProvider::Groq);

    let provider_key_status: Vec<DoctorKeyStatus> = crate::llm::AiProvider::all()
        .iter()
        .map(|p| {
            let env_present = std::env::var(p.env_var())
                .ok()
                .filter(|v| !v.trim().is_empty())
                .is_some();
            let config_present = match p {
                crate::llm::AiProvider::Groq => config.groq_api_key.as_ref().is_some(),
                crate::llm::AiProvider::OpenAI => config.openai_api_key.as_ref().is_some(),
                crate::llm::AiProvider::Anthropic => config.anthropic_api_key.as_ref().is_some(),
            };
            let configured = env_present || config_present;
            let source = if env_present {
                "env".to_string()
            } else if config_present {
                "config".to_string()
            } else {
                "missing".to_string()
            };
            DoctorKeyStatus {
                provider: p.as_str().to_string(),
                key: p.env_var().to_string(),
                env_var: p.env_var().to_string(),
                configured,
                value: None,
                source,
            }
        })
        .collect();

    let active_key_status = provider_key_status
        .iter()
        .find(|status| status.provider == active_provider.as_str())
        .cloned()
        .unwrap_or(DoctorKeyStatus {
            provider: active_provider.as_str().to_string(),
            key: active_provider.env_var().to_string(),
            env_var: active_provider.env_var().to_string(),
            configured: false,
            value: None,
            source: "missing".to_string(),
        });

    let action = if active_key_status.configured {
        "ready".to_string()
    } else {
        "needs-setup".to_string()
    };

    let config_path = config_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    let mut suggestion = format!(
        "Run 'cipher-ai config set {} <key>' or export {}=your_key_here",
        active_provider.config_key(),
        active_provider.env_var()
    );
    if config_path == "<unknown>" {
        suggestion = "Export HOME or USERPROFILE to a valid writable directory, then retry 'cipher-ai doctor'.".to_string();
    } else if active_key_status.configured {
        suggestion = "No action required for the active provider.".to_string();
    }

    Ok(DoctorReport {
        provider,
        config_path,
        active_key_status,
        provider_key_status,
        action,
        suggestion,
    })
}

pub fn run_config_show() -> Result<()> {
    let config = load_config()?;

    let provider = std::env::var("CIPHER_AI_PROVIDER")
        .ok()
        .or(config.provider.clone())
        .unwrap_or_else(|| "groq".to_string());

    let groq_key = std::env::var("GROQ_API_KEY").ok().or(config.groq_api_key);
    let openai_key = std::env::var("OPENAI_API_KEY")
        .ok()
        .or(config.openai_api_key);
    let anthropic_key = std::env::var("ANTHROPIC_API_KEY")
        .ok()
        .or(config.anthropic_api_key);

    println!();
    println!("{}", "Configuration".bold());
    println!("  {}", "-".repeat(40).dimmed());
    println!("  {} {}", "AI Provider:".bold(), provider.cyan().bold());
    if std::env::var("CIPHER_AI_PROVIDER").is_ok() {
        println!(
            "        {} overridden by CIPHER_AI_PROVIDER env var",
            "(i)".blue().dimmed()
        );
    }
    println!(
        "  {} {}",
        "Default Model:".bold(),
        config
            .default_model
            .as_deref()
            .unwrap_or(DEFAULT_MODELS[0])
            .cyan()
    );
    if std::env::var("CIPHER_AI_MODEL").is_ok() {
        println!(
            "        {} overridden by CIPHER_AI_MODEL env var",
            "(i)".blue().dimmed()
        );
    }
    if let Ok(base) = std::env::var("CIPHER_AI_BASE_URL") {
        println!(
            "        {} base URL: {}",
            "[GW]".cyan().dimmed(),
            base.dimmed()
        );
    }
    println!();
    println!("  {} {}", "API Keys:".bold(), "".dimmed());
    println!(
        "{}",
        render_key_line("Groq", "GROQ_API_KEY", groq_key.is_some())
    );
    println!(
        "{}",
        render_key_line("OpenAI", "OPENAI_API_KEY", openai_key.is_some())
    );
    println!(
        "{}",
        render_key_line("Anthropic", "ANTHROPIC_API_KEY", anthropic_key.is_some())
    );
    println!(
        "  {} {}",
        "Config File:".bold(),
        config_path()
            .unwrap_or_default()
            .display()
            .to_string()
            .dimmed()
    );
    println!();
    println!(
        "  {} Use 'cipher-ai config set <key> <value>' to change settings.",
        "[IDEA]".bold()
    );
    println!("  {} Supported keys: groq-api-key, openai-api-key, anthropic-api-key, provider, default-model", "     ".bold());
    Ok(())
}

pub fn run_doctor(format: &str) -> Result<()> {
    let report = doctor_report()?;
    if format.eq_ignore_ascii_case("json") {
        let json = serde_json::to_string_pretty(&report)?;
        if !report.active_key_status.configured {
            println!("{json}");
            return Err(anyhow::anyhow!(report.suggestion.clone()));
        }
        println!("{json}");
        return Ok(());
    }

    println!("{}", "CipherAI doctor".bold());
    println!("  {} {}", "Provider:".bold(), report.provider.cyan());
    println!("  {} {}", "Config:".bold(), report.config_path.dimmed());
    println!("  {} {}", "Status:".bold(), report.action.green());

    println!("  {}", "Key status:".bold());
    for status in &report.provider_key_status {
        let state = if status.configured {
            "configured".green()
        } else {
            "missing".red()
        };
        println!(
            "    - {} ({}): {} [{}]",
            status.provider, status.env_var, state, status.source
        );
    }

    let active = &report.active_key_status;
    if !active.configured {
        eprintln!(
            "\n{} {}",
            "Missing active key for {}".red().bold(),
            active.provider
        );
        eprintln!("  {}", report.suggestion.yellow());
        return Err(anyhow::anyhow!(report.suggestion.clone()));
    }

    println!("  {} {}", "Guidance:".bold(), report.suggestion.green());
    Ok(())
}

pub fn run_config(action: Option<&str>, key: Option<&str>, value: Option<&str>) -> Result<()> {
    match action {
        Some("set") => {
            let k = key.context("Usage: config set <key> <value>")?;
            let v = value.context("Usage: config set <key> <value>")?;
            run_config_set(k, v)
        }
        Some("get") => {
            let k = key.context("Usage: config get <key>")?;
            run_config_get(k)
        }
        _ => run_config_show(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_doctor_report_masks_secret_status() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("CIPHER_AI_PROVIDER", "openai");
        std::env::remove_var("GROQ_API_KEY");
        std::env::remove_var("OPENAI_API_KEY");
        std::env::remove_var("ANTHROPIC_API_KEY");

        let report = doctor_report().unwrap();
        assert_eq!(report.provider, "openai");
        assert_eq!(report.active_key_status.key, "OPENAI_API_KEY");
        assert_eq!(report.active_key_status.env_var, "OPENAI_API_KEY");
        assert!(!report.active_key_status.configured);
        assert!(report.provider_key_status.iter().all(|s| s.value.is_none()));
    }

    #[test]
    fn test_doctor_report_handles_missing_home_actionably() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous_home = std::env::var("HOME").ok();
        let previous_userprofile = std::env::var("USERPROFILE").ok();
        std::env::remove_var("HOME");
        std::env::remove_var("USERPROFILE");

        let report = doctor_report().unwrap();
        assert_eq!(report.config_path, "<unknown>");
        assert!(
            report.suggestion.to_ascii_lowercase().contains("home")
                || report
                    .suggestion
                    .to_ascii_lowercase()
                    .contains("userprofile")
        );

        match previous_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match previous_userprofile {
            Some(v) => std::env::set_var("USERPROFILE", v),
            None => std::env::remove_var("USERPROFILE"),
        }
    }

    #[test]
    fn test_config_path_missing_home_returns_error() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous_home = std::env::var("HOME").ok();
        let previous_userprofile = std::env::var("USERPROFILE").ok();
        std::env::remove_var("HOME");
        std::env::remove_var("USERPROFILE");

        let result = config_path();

        match previous_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match previous_userprofile {
            Some(v) => std::env::set_var("USERPROFILE", v),
            None => std::env::remove_var("USERPROFILE"),
        }

        assert!(result.is_err());
    }
}
