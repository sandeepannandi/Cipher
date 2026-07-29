use crate::{deps, review, secrets};
use anyhow::Result;
use colored::*;
use std::path::Path;

/// Run the `cipher-ai ci` command — runs all scanners and exits with consolidated code.
pub async fn run_ci(
    project_path: &Path,
    fail_on: Option<&str>,
    use_ai: bool,
) -> Result<()> {
    let fail_severity = fail_on.and_then(|s| match s.to_lowercase().as_str() {
        "critical" => Some(0),
        "high" => Some(1),
        "medium" => Some(2),
        "low" => Some(3),
        _ => None,
    });

    println!(
        "{} {}\n",
        "[CI]".bright_blue().bold(),
        "CipherAI — Running All Scans".bold()
    );

    // Step 1: Security review
    println!("  {} Running security review...", "[1/3]".cyan());
    let review_result = review::collect_review_findings(project_path, use_ai, None).await?;
    let review_critical = review_result.findings.iter().filter(|f| f.severity.score() >= 4).count();
    let review_high = review_result.findings.iter().filter(|f| f.severity.score() >= 3).count();
    println!(
        "  {} Review: {} critical, {} high, {} total",
        "[OK]".green(),
        review_critical.to_string().red().bold(),
        review_high.to_string().yellow().bold(),
        review_result.len()
    );

    // Step 2: Secrets scan
    println!("  {} Scanning for secrets...", "[2/3]".cyan());
    let secrets_result = secrets::collect_secrets_findings(project_path)?;
    let secrets_critical = secrets_result.findings.iter().filter(|f| f.severity.score() >= 4).count();
    let secrets_high = secrets_result.findings.iter().filter(|f| f.severity.score() >= 3).count();
    println!(
        "  {} Secrets: {} critical, {} high, {} total",
        "[OK]".green(),
        secrets_critical.to_string().red().bold(),
        secrets_high.to_string().yellow().bold(),
        secrets_result.len()
    );

    // Step 3: Deps check
    println!("  {} Checking dependencies...", "[3/3]".cyan());
    let deps_result = deps::collect_deps_findings(project_path, false).await?;
    let deps_critical = deps_result.findings.iter().filter(|f| f.severity.score() >= 4).count();
    let deps_high = deps_result.findings.iter().filter(|f| f.severity.score() >= 3).count();
    println!(
        "  {} Deps: {} critical, {} high, {} total",
        "[OK]".green(),
        deps_critical.to_string().red().bold(),
        deps_high.to_string().yellow().bold(),
        deps_result.len()
    );

    // Summary
    let total_critical = review_critical + secrets_critical + deps_critical;
    let total_high = review_high + secrets_high + deps_high;
    let total_findings = review_result.len() + secrets_result.len() + deps_result.len();

    println!();
    println!("{}", "══════════════════════════════════════".dimmed());
    println!(
        "{} CI Summary: {} critical, {} high, {} total",
        "[CI]".bold(),
        total_critical.to_string().red().bold(),
        total_high.to_string().yellow().bold(),
        total_findings.to_string().bold()
    );
    println!("{}", "══════════════════════════════════════".dimmed());

    // Determine exit code
    let should_fail = match fail_severity {
        Some(0) => total_critical > 0,
        Some(1) => total_critical + total_high > 0,
        Some(2) => total_findings > 0,
        Some(_) => total_critical + total_high > 0,
        None => false,
    };

    if should_fail && total_findings > 0 {
        println!(
            "  {} CI check failed: findings exceed --fail-on threshold.",
            "[FAIL]".red().bold()
        );
        std::process::exit(1);
    }

    if total_findings == 0 {
        println!("  {} No issues found! Your codebase looks clean.", "[PASS]".green().bold());
    } else {
        println!("  {} CI check passed (--fail-on threshold not exceeded).", "[PASS]".green().bold());
    }

    Ok(())
}
