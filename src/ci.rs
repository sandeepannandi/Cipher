use crate::{deps, review, secrets, zeroday, sbom, attack, output};
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
    output_path: Option<&str>,
) -> Result<()> {
    let fail_severity = fail_on.and_then(|s| match s.to_lowercase().as_str() {
        "critical" => Some(0),
        "high" => Some(1),
        "medium" => Some(2),
        "low" => Some(3),
        _ => None,
    });

    output::print_header("CipherAI CI Pipeline", Some("Running all security scans"));

    let mut steps: Vec<CiStepResult> = Vec::new();
    let mut total_critical = 0usize;
    let mut total_high = 0usize;
    let mut total_findings = 0usize;

    // Step 1: Security review
    output::print_step(1, 5, "Running security review");
    let review_result = review::collect_review_findings(project_path, use_ai, None).await?;
    let review_critical = review_result.findings.iter().filter(|f| f.severity.score() >= 4).count();
    let review_high = review_result.findings.iter().filter(|f| f.severity.score() >= 3).count();
    output::print_ok("Review", &format!(
        "{} critical, {} high, {} total",
        review_critical.to_string().red().bold(),
        review_high.to_string().yellow().bold(),
        review_result.len().to_string().bold()
    ));
    steps.push(CiStepResult { step: "review", critical: review_critical, high: review_high, total: review_result.len() });
    total_critical += review_critical;
    total_high += review_high;
    total_findings += review_result.len();

    // Step 2: Secrets scan
    output::print_step(2, 5, "Scanning for secrets and credentials");
    let secrets_result = secrets::collect_secrets_findings(project_path)?;
    let secrets_critical = secrets_result.findings.iter().filter(|f| f.severity.score() >= 4).count();
    let secrets_high = secrets_result.findings.iter().filter(|f| f.severity.score() >= 3).count();
    output::print_ok("Secrets", &format!(
        "{} critical, {} high, {} total",
        secrets_critical.to_string().red().bold(),
        secrets_high.to_string().yellow().bold(),
        secrets_result.len().to_string().bold()
    ));
    steps.push(CiStepResult { step: "secrets", critical: secrets_critical, high: secrets_high, total: secrets_result.len() });
    total_critical += secrets_critical;
    total_high += secrets_high;
    total_findings += secrets_result.len();

    // Step 3: Deps check
    output::print_step(3, 5, "Checking dependencies for vulnerabilities");
    let deps_result = deps::collect_deps_findings(project_path, false).await?;
    let deps_critical = deps_result.findings.iter().filter(|f| f.severity.score() >= 4).count();
    let deps_high = deps_result.findings.iter().filter(|f| f.severity.score() >= 3).count();
    output::print_ok("Deps", &format!(
        "{} critical, {} high, {} total",
        deps_critical.to_string().red().bold(),
        deps_high.to_string().yellow().bold(),
        deps_result.len().to_string().bold()
    ));
    steps.push(CiStepResult { step: "deps", critical: deps_critical, high: deps_high, total: deps_result.len() });
    total_critical += deps_critical;
    total_high += deps_high;
    total_findings += deps_result.len();

    // Step 4: Zero-day anomaly scan
    output::print_step(4, 5, "Scanning for zero-day anomalies");
    let zeroday_report = zeroday::collect_zeroday_findings(project_path, false, false).await?;
    let zd_critical = zeroday_report.anomalies.iter().chain(zeroday_report.flow_findings.iter()).filter(|f| f.finding.severity.score() >= 4).count();
    let zd_high = zeroday_report.anomalies.iter().chain(zeroday_report.flow_findings.iter()).filter(|f| f.finding.severity.score() >= 3).count();
    let zd_total = zeroday_report.total();
    output::print_ok("Zero-day", &format!(
        "{} critical, {} high, {} total",
        zd_critical.to_string().red().bold(),
        zd_high.to_string().yellow().bold(),
        zd_total.to_string().bold()
    ));
    steps.push(CiStepResult { step: "zeroday", critical: zd_critical, high: zd_high, total: zd_total });
    total_critical += zd_critical;
    total_high += zd_high;
    total_findings += zd_total;

    // Step 5: Attack path analysis
    output::print_step(5, 5, "Analyzing attack paths");
    let attack_count = match attack::collect_attack_summary(project_path).await {
        Ok(count) => {
            output::print_ok("Attack paths", &format!("{} attack chains found", count.to_string().bold()));
            steps.push(CiStepResult { step: "attack", critical: 0, high: 0, total: count });
            count
        }
        Err(_) => {
            output::print_warn("Attack paths", "skipped (no findings to chain)");
            steps.push(CiStepResult { step: "attack", critical: 0, high: 0, total: 0 });
            0
        }
    };

    // Generate SBOM (informational)
    output::print_info("SBOM", "Generating software bill of materials...");
    match sbom::collect_sbom_summary(project_path).await {
        Ok(dep_count) => {
            output::print_ok("SBOM", &format!("{} dependencies cataloged", dep_count.to_string().bold()));
        }
        Err(_) => {
            output::print_warn("SBOM", "generation skipped");
        }
    }

    // Summary box
    let should_fail = match fail_severity {
        Some(0) => total_critical > 0,
        Some(1) => total_critical + total_high > 0,
        Some(2) => total_findings > 0,
        Some(_) => total_critical + total_high > 0,
        None => false,
    };

    let pass_fail = if should_fail && total_findings > 0 { "FAILED" } else { "PASSED" };
    let pass_fail_styled = if should_fail && total_findings > 0 { pass_fail.red().bold().to_string() } else { pass_fail.green().bold().to_string() };

    output::print_summary_box("CI Pipeline Results", &[
        ("Status", &pass_fail_styled),
        ("Critical", &total_critical.to_string().red().bold().to_string()),
        ("High", &total_high.to_string().yellow().bold().to_string()),
        ("Total Findings", &total_findings.to_string().bold().to_string()),
        ("Attack Chains", &attack_count.to_string().bold().to_string()),
    ]);

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
        if let Some(out_path) = output_path {
            std::fs::write(out_path, &json_str)?;
            output::print_ok("Output", &format!("JSON written to {}", out_path.yellow()));
        } else {
            println!("{}", json_str);
        }
        if should_fail && total_findings > 0 {
            std::process::exit(1);
        }
        return Ok(());
    }

    if should_fail && total_findings > 0 {
        output::print_fail("CI", "check failed — findings exceed --fail-on threshold");
        output::print_hint("Run with --fail-on critical to only fail on critical issues");
        std::process::exit(1);
    }

    if total_findings == 0 && attack_count == 0 {
        output::print_success("No issues found! Your codebase looks clean.");
    } else {
        output::print_ok("CI", "check passed (--fail-on threshold not exceeded)");
    }

    output::print_recommendations(&[
        "Run cipher-ai review for detailed findings",
        "Run cipher-ai sbom for SBOM output",
        "Run cipher-ai fix --risk critical to fix critical issues",
    ]);

    output::print_footer();
    Ok(())
}
