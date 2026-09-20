//! Guided first-run setup (`cipher-ai setup`).
//!
//! Walks the user through picking an AI provider and storing its API key,
//! then verifies the result with the same checks `doctor` runs. Secrets are
//! never echoed, printed, or committed: the key is read hidden (interactive),
//! from stdin (`--key-stdin`), or detected in the environment, and the config
//! file is written owner-only (0600 on Unix).

use anyhow::{Context, Result};
use colored::*;
use std::io::{BufRead, IsTerminal, Write};

use crate::config;
use crate::llm::AiProvider;

/// How the API key reached the config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// Read hidden on the terminal or piped via --key-stdin, then persisted.
    Persisted,
    /// Already present in the provider's env var; nothing written.
    Environment,
}

/// Outcome of a setup run, for deterministic verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupOutcome {
    pub provider: String,
    pub source: KeySource,
    pub config_path: Option<String>,
    /// True when `doctor_report` confirms the active provider has a key.
    pub verified: bool,
}

/// Persist `key` for `provider` (owner-only file) and verify via the same
/// report `cipher-ai doctor` builds. This is the tested core; interactive
/// and scripted entry points both end here.
pub fn setup_with_key(provider: AiProvider, key: &str) -> Result<SetupOutcome> {
    let trimmed = key.trim();
    anyhow::ensure!(
        !trimmed.is_empty(),
        "Empty API key. Paste the full key for {}.",
        provider.display_name()
    );
    anyhow::ensure!(
        !trimmed.chars().any(char::is_whitespace),
        "API key contains whitespace - paste only the key itself."
    );

    config::set_provider_choice(provider.as_str())?;
    config::set_provider_key(provider, trimmed)?;
    let path = config::config_path()?;

    let verified = config::doctor_report()
        .map(|r| r.active_key_status.configured)
        .unwrap_or(false);

    Ok(SetupOutcome {
        provider: provider.as_str().to_string(),
        source: KeySource::Persisted,
        config_path: Some(path.display().to_string()),
        verified,
    })
}

/// Key already in the environment: verify and report without persisting.
pub fn setup_from_env(provider: AiProvider) -> Result<SetupOutcome> {
    let verified = config::doctor_report()
        .map(|r| r.active_key_status.configured)
        .unwrap_or(false);
    Ok(SetupOutcome {
        provider: provider.as_str().to_string(),
        source: KeySource::Environment,
        config_path: None,
        verified,
    })
}

fn print_outcome(outcome: &SetupOutcome, provider: AiProvider) {
    println!();
    match outcome.source {
        KeySource::Persisted => {
            println!(
                "  {} {} key saved (owner-only) to {}",
                "[OK]".green().bold(),
                provider.display_name(),
                outcome
                    .config_path
                    .as_deref()
                    .unwrap_or("<unknown>")
                    .dimmed()
            );
        }
        KeySource::Environment => {
            println!(
                "  {} {} key found in {} - nothing written.",
                "[OK]".green().bold(),
                provider.display_name(),
                provider.env_var()
            );
        }
    }
    if outcome.verified {
        println!(
            "  {} doctor check passed: {} is ready.",
            "[OK]".green().bold(),
            outcome.provider
        );
    }
    println!();
    println!("  {} Next steps:", "[>]".cyan().bold());
    println!("    cipher-ai init                 index your codebase");
    println!("    cipher-ai ask \"...\"            ask a security question");
    println!("    cipher-ai review               run the OWASP scan");
    println!("    cipher-ai doctor               re-check this setup anytime");
}

fn env_key_for(provider: AiProvider) -> Option<String> {
    std::env::var(provider.env_var())
        .ok()
        .filter(|v| !v.trim().is_empty())
}

fn prompt_provider(stdin: &std::io::Stdin) -> Result<AiProvider> {
    println!("  Which AI provider?");
    for (i, p) in AiProvider::all().iter().enumerate() {
        println!(
            "    {}. {} (env: {})",
            i + 1,
            p.display_name(),
            p.env_var().dimmed()
        );
    }
    print!("  Choice [1]: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let choice = line.trim();
    if choice.is_empty() {
        return Ok(AiProvider::Groq);
    }
    let idx: usize = choice
        .parse()
        .with_context(|| format!("'{choice}' is not a number from the list"))?;
    AiProvider::all()
        .get(idx.wrapping_sub(1))
        .copied()
        .with_context(|| format!("'{choice}' is not a number from the list"))
}

/// `cipher-ai setup` entry point.
pub fn run_setup(provider_flag: Option<&str>, key_stdin: bool) -> Result<()> {
    println!("{}", "CipherAI setup".bold());
    println!("  {}", "-".repeat(40).dimmed());

    let stdin = std::io::stdin();
    let interactive = stdin.is_terminal();

    // 1. Provider: flag > prompt (TTY) > default with a note.
    let provider = match provider_flag {
        Some(name) => AiProvider::parse(name).with_context(|| {
            format!("Unknown provider '{name}'. Valid: groq, openai, anthropic")
        })?,
        None if interactive => prompt_provider(&stdin)?,
        None => {
            println!(
                "  {} No --provider given; defaulting to groq.",
                "(i)".blue().dimmed()
            );
            AiProvider::Groq
        }
    };

    // 2. Key: env > --key-stdin > hidden prompt. Never echoed back.
    let outcome = if env_key_for(provider).is_some() && !key_stdin {
        println!(
            "  {} {} is already set in the environment.",
            "(i)".blue().dimmed(),
            provider.env_var()
        );
        setup_from_env(provider)?
    } else if key_stdin {
        let mut raw = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut raw)
            .context("Failed to read the API key from stdin")?;
        setup_with_key(provider, &raw)?
    } else if interactive {
        let raw = rpassword::prompt_password(format!(
            "  Paste your {} API key (input hidden): ",
            provider.display_name()
        ))
        .context("Failed to read the API key")?;
        setup_with_key(provider, &raw)?
    } else {
        anyhow::bail!(
            "No key available and stdin is not a terminal. Re-run with --key-stdin: \
             echo $KEY | cipher-ai setup --provider {}",
            provider.as_str()
        );
    };

    print_outcome(&outcome, provider);
    if !outcome.verified {
        anyhow::bail!(
            "doctor could not confirm the {} key - run 'cipher-ai doctor' for details.",
            outcome.provider
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_rejects_empty_key() {
        let err = setup_with_key(AiProvider::Groq, "   ").unwrap_err();
        assert!(err.to_string().contains("Empty API key"), "{err}");
    }

    #[test]
    fn test_setup_rejects_whitespace_in_key() {
        let err = setup_with_key(AiProvider::Groq, "gsk_ abc").unwrap_err();
        assert!(err.to_string().contains("whitespace"), "{err}");
    }

    #[test]
    fn test_setup_rejects_unknown_provider_parse() {
        assert!(AiProvider::parse("not-a-provider").is_none());
    }
}
