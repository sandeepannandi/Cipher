use anyhow::{Context, Result};
use colored::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const DEFAULT_MODELS: &[&str] = &[
    "llama-3.3-70b-versatile",
    "mixtral-8x7b-32768",
    "gemma2-9b-it",
];

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    groq_api_key: Option<String>,
    default_model: Option<String>,
}

fn config_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .context("Cannot find home directory")?;
    Ok(PathBuf::from(home).join(".cipher-ai").join("config.json"))
}

fn load_config() -> Result<Config> {
    let path = config_path()?;
    if path.exists() {
        let content = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&content).unwrap_or(Config {
            groq_api_key: None,
            default_model: None,
        }))
    } else {
        Ok(Config {
            groq_api_key: None,
            default_model: None,
        })
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

pub fn run_config_set(key: &str, value: &str) -> Result<()> {
    let mut config = load_config()?;
    match key {
        "groq-api-key" | "api-key" | "key" => {
            config.groq_api_key = Some(value.to_string());
            println!("  {} Groq API key set", "[OK]".green().bold());
        }
        "default-model" | "model" => {
            if !DEFAULT_MODELS.contains(&value) {
                eprintln!(
                    "  {} Unknown model '{}'. Available: {}",
                    "[!]".yellow(),
                    value,
                    DEFAULT_MODELS.join(", ")
                );
                println!("  Setting anyway — model may not work.");
            }
            config.default_model = Some(value.to_string());
            println!("  {} Default model set to: {}", "[OK]".green().bold(), value);
        }
        _ => {
            anyhow::bail!("Unknown config key: {}. Valid keys: groq-api-key, default-model", key);
        }
    }
    save_config(&config)?;
    Ok(())
}

pub fn run_config_get(key: &str) -> Result<()> {
    let config = load_config()?;
    let env_key = std::env::var("GROQ_API_KEY").ok();
    match key {
        "groq-api-key" | "api-key" | "key" => {
            match (env_key, &config.groq_api_key) {
                (Some(_), _) => println!("(set via GROQ_API_KEY env var)"),
                (None, Some(v)) => println!("{}", v),
                (None, None) => println!("(not set)"),
            }
        }
        "default-model" | "model" => {
            match &config.default_model {
                Some(v) => println!("{}", v),
                None => println!("{}", DEFAULT_MODELS[0]),
            }
        }
        _ => {
            anyhow::bail!("Unknown config key: {}. Valid keys: groq-api-key, default-model", key);
        }
    }
    Ok(())
}

pub fn run_config_show() -> Result<()> {
    let config = load_config()?;
    let api_key = std::env::var("GROQ_API_KEY").ok()
        .or(config.groq_api_key);

    println!();
    println!("{}", "Configuration".bold());
    println!("  {}", "-".repeat(40).dimmed());
    println!(
        "  {} {}",
        "Groq API Key:".bold(),
        if api_key.is_some() {
            "set [OK]".green().to_string()
        } else {
            "not set [WARN]".red().to_string()
        }
    );
    println!(
        "  {} {}",
        "Default Model:".bold(),
        config.default_model.as_deref().unwrap_or(DEFAULT_MODELS[0]).cyan()
    );
    println!(
        "  {} {}",
        "Config File:".bold(),
        config_path().unwrap_or_default().display().to_string().dimmed()
    );
    println!();
    println!("  {} Use 'cipher-ai config set <key> <value>' to change settings.", "[IDEA]".bold());
    println!("  {} Supported keys: groq-api-key, default-model", "     ".bold());
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
