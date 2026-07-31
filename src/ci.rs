use crate::finding::{dedup_findings, Finding, Severity};
use crate::{attack, deps, output, review, sbom, secrets, zeroday};
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

/// Count findings at exactly the given severity
fn count_exact(findings: &[Finding], severity: Severity) -> usize {
    findings.iter().filter(|f| f.severity == severity).count()
}

/// Compute the severity totals from a deduplicated finding set.
fn compute_totals(findings: &[Finding]) -> (usize, usize, usize, usize, usize) {
    let critical = count_exact(findings, Severity::Critical);
    let high = count_exact(findings, Severity::High);
    let medium = count_exact(findings, Severity::Medium);
    let low = count_exact(findings, Severity::Low);
    (critical, high, medium, low, findings.len())
}

/// Decide whether the pipeline should fail given a `--fail-on` level.
///
/// Semantics (increasing strictness):
/// - critical: fail if any critical finding exists
/// - high:     fail if any critical or high finding exists
/// - medium:   fail if any critical, high, or medium finding exists
/// - low:      fail if any finding at all exists
fn should_fail(
    fail_severity: Option<Severity>,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
) -> bool {
    match fail_severity {
        Some(Severity::Critical) => critical > 0,
        Some(Severity::High) => critical + high > 0,
        Some(Severity::Medium) => critical + high + medium > 0,
        Some(Severity::Low) => critical + high + medium + low > 0,
        // Info findings never cause a pipeline failure
        Some(Severity::Info) => false,
        None => false,
    }
}

/// Run the `cipher-ai ci` command — runs all scanners and exits with consolidated code.
pub async fn run_ci(
    project_path: &Path,
    fail_on: Option<&str>,
    use_ai: bool,
    format: &str,
    output_path: Option<&str>,
) -> Result<()> {
    let fail_severity = fail_on.and_then(Severity::from_fail_on);

    output::print_header("CipherAI CI Pipeline", Some("Running all security scans"));

    let mut steps: Vec<CiStepResult> = Vec::new();
    let mut merged: Vec<Finding> = Vec::new();

    // Step 1: Security review
    output::print_step(1, 5, "Running security review");
    let review_result = review::collect_review_findings(project_path, use_ai, None).await?;
    let review_critical = count_exact(&review_result.findings, Severity::Critical);
    let review_high = count_exact(&review_result.findings, Severity::High);
    output::print_ok("Review", &format!(
        "{} critical, {} high, {} total",
        review_critical.to_string().red().bold(),
        review_high.to_string().yellow().bold(),
        review_result.len().to_string().bold()
    ));
    steps.push(CiStepResult { step: "review", critical: review_critical, high: review_high, total: review_result.len() });
    merged.extend(review_result.findings);

    // Step 2: Secrets scan
    output::print_step(2, 5, "Scanning for secrets and credentials");
    let secrets_result = secrets::collect_secrets_findings(project_path)?;
    let secrets_critical = count_exact(&secrets_result.findings, Severity::Critical);
    let secrets_high = count_exact(&secrets_result.findings, Severity::High);
    output::print_ok("Secrets", &format!(
        "{} critical, {} high, {} total",
        secrets_critical.to_string().red().bold(),
        secrets_high.to_string().yellow().bold(),
        secrets_result.len().to_string().bold()
    ));
    steps.push(CiStepResult { step: "secrets", critical: secrets_critical, high: secrets_high, total: secrets_result.len() });
    merged.extend(secrets_result.findings);

    // Step 3: Deps check
    output::print_step(3, 5, "Checking dependencies for vulnerabilities");
    let deps_result = deps::collect_deps_findings(project_path, false).await?;
    let deps_critical = count_exact(&deps_result.findings, Severity::Critical);
    let deps_high = count_exact(&deps_result.findings, Severity::High);
    output::print_ok("Deps", &format!(
        "{} critical, {} high, {} total",
        deps_critical.to_string().red().bold(),
        deps_high.to_string().yellow().bold(),
        deps_result.len().to_string().bold()
    ));
    steps.push(CiStepResult { step: "deps", critical: deps_critical, high: deps_high, total: deps_result.len() });
    merged.extend(deps_result.findings);

    // Step 4: Zero-day anomaly scan
    output::print_step(4, 5, "Scanning for zero-day anomalies");
    let zeroday_report = zeroday::collect_zeroday_findings(project_path, false, false).await?;
    let zd_findings = zeroday_report.to_finding_report().findings;
    let zd_critical = count_exact(&zd_findings, Severity::Critical);
    let zd_high = count_exact(&zd_findings, Severity::High);
    output::print_ok("Zero-day", &format!(
        "{} critical, {} high, {} total",
        zd_critical.to_string().red().bold(),
        zd_high.to_string().yellow().bold(),
        zd_findings.len().to_string().bold()
    ));
    steps.push(CiStepResult { step: "zeroday", critical: zd_critical, high: zd_high, total: zd_findings.len() });
    merged.extend(zd_findings);

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

    // Deduplicate findings across scanners, then compute totals
    let deduped = dedup_findings(merged);
    let (total_critical, total_high, total_medium, total_low, total_findings) = compute_totals(&deduped);
    let should_fail = should_fail(fail_severity, total_critical, total_high, total_medium, total_low);

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

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(sev: Severity) -> Finding {
        Finding::new(
            crate::finding::FindingType::Vulnerability,
            "test",
            "test",
            sev,
            crate::finding::Confidence::High,
            "test",
        )
    }

    #[test]
    fn test_should_fail_thresholds() {
        // None → never fail
        assert!(!should_fail(None, 5, 0, 0, 0));
        // critical level: only critical findings cause failure
        assert!(should_fail(Some(Severity::Critical), 1, 0, 0, 0));
        assert!(!should_fail(Some(Severity::Critical), 0, 1, 0, 0));
        // high level: critical or high
        assert!(should_fail(Some(Severity::High), 0, 1, 0, 0));
        assert!(should_fail(Some(Severity::High), 1, 0, 0, 0));
        assert!(!should_fail(Some(Severity::High), 0, 0, 1, 0));
        // medium level: critical/high/medium
        assert!(should_fail(Some(Severity::Medium), 0, 0, 1, 0));
        assert!(!should_fail(Some(Severity::Medium), 0, 0, 0, 1));
        // low level: any finding
        assert!(should_fail(Some(Severity::Low), 0, 0, 0, 1));
        assert!(!should_fail(Some(Severity::Low), 0, 0, 0, 0));
    }

    #[test]
    fn test_compute_totals() {
        let findings = vec![
            finding(Severity::Critical),
            finding(Severity::Critical),
            finding(Severity::High),
            finding(Severity::Medium),
            finding(Severity::Low),
            finding(Severity::Info),
        ];
        let (c, h, m, l, total) = compute_totals(&findings);
        assert_eq!(c, 2);
        assert_eq!(h, 1);
        assert_eq!(m, 1);
        assert_eq!(l, 1);
        assert_eq!(total, 6);
    }

    #[test]
    fn test_count_exact() {
        let findings = vec![finding(Severity::Critical), finding(Severity::High)];
        assert_eq!(count_exact(&findings, Severity::Critical), 1);
        assert_eq!(count_exact(&findings, Severity::High), 1);
        assert_eq!(count_exact(&findings, Severity::Medium), 0);
    }
}
