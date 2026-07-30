use crate::{deps, review, secrets, zeroday, sbom, attack};
use anyhow::Result;
use colored::*;
use serde::Serialize;
use std::path::Path;

/// Per-step scan result for summary/reporting
#[derive(Serialize)]
struct CiStepResult {
    step: &'static str,
    critical: usize,
    high: usize,
    total: usize,
}

#[derive(Serialize)]
struct CiJsonReport {
    status: String,
    summary: CiSummary,
    steps: Vec<CiStepResult>,
    timestamp: String,
}

#[derive(Serialize)]
struct CiSummary {
    total_critical: usize,
    total_high: usize,
    total_findings: usize,
    failed: bool,
}

/// Run the `cipher-ai ci` command — runs all scanners and exits with consolidated code.
pub async fn run_ci(
    project_path: &Path,
    fail_on: Option<&str>,
    use_ai: bool,
    format: &str,
    output: Option<&str>,
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

    let mut steps: Vec<CiStepResult> = Vec::new();
    let mut total_critical = 0usize;
    let mut total_high = 0usize;
    let mut total_findings = 0usize;

    // Step 1: Security review
    println!("  {} Running security review...", "[1/5]".cyan());
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
    steps.push(CiStepResult { step: "review", critical: review_critical, high: review_high, total: review_result.len() });
    total_critical += review_critical;
    total_high += review_high;
    total_findings += review_result.len();

    // Step 2: Secrets scan
    println!("  {} Scanning for secrets...", "[2/5]".cyan());
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
    steps.push(CiStepResult { step: "secrets", critical: secrets_critical, high: secrets_high, total: secrets_result.len() });
    total_critical += secrets_critical;
    total_high += secrets_high;
    total_findings += secrets_result.len();

    // Step 3: Deps check
    println!("  {} Checking dependencies...", "[3/5]".cyan());
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
    steps.push(CiStepResult { step: "deps", critical: deps_critical, high: deps_high, total: deps_result.len() });
    total_critical += deps_critical;
    total_high += deps_high;
    total_findings += deps_result.len();

    // Step 4: Zero-day anomaly scan
    println!("  {} Scanning for zero-day anomalies...", "[4/5]".cyan());
    let zeroday_report = zeroday::collect_zeroday_findings(project_path, false, false).await?;
    let zd_critical = zeroday_report.anomalies.iter().chain(zeroday_report.flow_findings.iter()).filter(|f| f.finding.severity.score() >= 4).count();
    let zd_high = zeroday_report.anomalies.iter().chain(zeroday_report.flow_findings.iter()).filter(|f| f.finding.severity.score() >= 3).count();
    let zd_total = zeroday_report.total();
    println!(
        "  {} Zero-day: {} critical, {} high, {} total",
        "[OK]".green(),
        zd_critical.to_string().red().bold(),
        zd_high.to_string().yellow().bold(),
        zd_total
    );
    steps.push(CiStepResult { step: "zeroday", critical: zd_critical, high: zd_high, total: zd_total });
    total_critical += zd_critical;
    total_high += zd_high;
    total_findings += zd_total;

    // Step 5: Attack path analysis
    println!("  {} Analyzing attack paths...", "[5/5]".cyan());
    let attack_count = match attack::collect_attack_summary(project_path).await {
        Ok(count) => {
            println!(
                "  {} Attack paths: {} chains found",
                "[OK]".green(),
                count.to_string().bold()
            );
            steps.push(CiStepResult { step: "attack", critical: 0, high: 0, total: count });
            count
        }
        Err(_) => {
            println!("  {} Attack analysis skipped (no findings to chain)", "[OK]".dimmed());
            steps.push(CiStepResult { step: "attack", critical: 0, high: 0, total: 0 });
            0
        }
    };

    // Generate SBOM (informational only)
    println!("  {} Generating SBOM...", "[i]".dimmed());
    match sbom::collect_sbom_summary(project_path).await {
        Ok(dep_count) => {
            println!(
                "  {} SBOM: {} dependencies cataloged",
                "[OK]".dimmed(),
                dep_count.to_string().dimmed()
            );
        }
        Err(_) => {
            println!("  {} SBOM generation skipped", "[i]".dimmed());
        }
    }

    // Summary
    println!();
    println!("{}", "══════════════════════════════════════".dimmed());
    println!(
        "{} CI Summary: {} critical, {} high, {} findings, {} attack chains",
        "[CI]".bold(),
        total_critical.to_string().red().bold(),
        total_high.to_string().yellow().bold(),
        total_findings.to_string().bold(),
        attack_count.to_string().bold()
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

    // Handle JSON output
    if format == "json" {
        let json_report = CiJsonReport {
            status: if should_fail && total_findings > 0 { "failed".to_string() } else { "passed".to_string() },
            summary: CiSummary {
                total_critical,
                total_high,
                total_findings,
                failed: should_fail && total_findings > 0,
            },
            steps,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let json_str = serde_json::to_string_pretty(&json_report)?;
        if let Some(out_path) = output {
            std::fs::write(out_path, &json_str)?;
            println!(
                "  {} JSON output written to {}",
                "[FILE]".cyan(),
                out_path.yellow()
            );
        } else {
            println!("{}", json_str);
        }
        // Exit if failed
        if should_fail && total_findings > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    if should_fail && total_findings > 0 {
        println!(
            "  {} CI check failed: findings exceed --fail-on threshold.",
            "[FAIL]".red().bold()
        );
        std::process::exit(1);
    }

    if total_findings == 0 && attack_count == 0 {
        println!("  {} No issues found! Your codebase looks clean.", "[PASS]".green().bold());
    } else {
        println!("  {} CI check passed (--fail-on threshold not exceeded).", "[PASS]".green().bold());
    }

    println!();
    println!("  {} Run {} to view detailed findings.", "[IDEA]".bold(), "cipher-ai review".yellow());
    println!("  {} Run {} for SBOM output.", "[IDEA]".bold(), "cipher-ai sbom".yellow());

    Ok(())
}
