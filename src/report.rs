use crate::deps;
use crate::finding::{dedup_key, should_collapse, Finding, FindingType, Severity};
use crate::review;
use crate::secrets;
use anyhow::Result;
use colored::*;
use chrono::Utc;
use serde::Serialize;
use std::path::Path;

/// Aggregated findings from all security analysis modules
#[derive(Debug, Clone, Serialize)]
pub struct AggregatedReport {
    /// Findings from pattern-based + AI security review
    pub review: Vec<Finding>,
    /// Findings from dependency vulnerability scanning
    pub deps: Vec<Finding>,
    /// Findings from secret/credential scanning
    pub secrets: Vec<Finding>,
    /// Project path
    pub project_path: String,
    /// Timestamp
    pub created_at: String,
}

impl AggregatedReport {
    pub fn new(project_path: impl Into<String>) -> Self {
        Self {
            review: Vec::new(),
            deps: Vec::new(),
            secrets: Vec::new(),
            project_path: project_path.into(),
            created_at: Utc::now().to_rfc3339(),
        }
    }

    /// Total number of unique findings across all sources (deduplicated)
    pub fn total_findings(&self) -> usize {
        self.deduped_all().len()
    }

    /// Count unique findings by severity across all sources (deduplicated)
    pub fn count_by_severity(&self, severity: Severity) -> usize {
        self.deduped_all()
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }

    /// Count unique findings by type across all sources (deduplicated)
    pub fn count_by_type(&self, finding_type: FindingType) -> usize {
        self.deduped_all()
            .iter()
            .filter(|f| f.finding_type == finding_type)
            .count()
    }

    /// Get all findings as a flat vector, deduplicated across scanners and
    /// sorted by risk score (highest first)
    pub fn all_sorted(&self) -> Vec<&Finding> {
        self.deduped_all()
    }

    /// Merge all findings, sort by risk (descending), then remove duplicates.
    /// Since the list is risk-sorted, the first occurrence of each duplicate
    /// is the highest-risk one — exactly what we want to keep.
    fn deduped_all(&self) -> Vec<&Finding> {
        let mut all: Vec<&Finding> = self
            .review
            .iter()
            .chain(self.deps.iter())
            .chain(self.secrets.iter())
            .collect();
        all.sort_by(|a, b| {
            b.risk_score()
                .partial_cmp(&a.risk_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let mut kept: Vec<&Finding> = Vec::new();
        for f in all {
            let is_duplicate = kept
                .iter()
                .any(|k| dedup_key(k) == dedup_key(f) && should_collapse(k, f));
            if !is_duplicate {
                kept.push(f);
            }
        }
        kept
    }

    /// Compute an overall security score 0–100
    pub fn security_score(&self) -> f64 {
        let total = self.total_findings();
        if total == 0 {
            return 100.0;
        }
        let critical = self.count_by_severity(Severity::Critical) as f64 * 25.0;
        let high = self.count_by_severity(Severity::High) as f64 * 10.0;
        let medium = self.count_by_severity(Severity::Medium) as f64 * 4.0;
        let low = self.count_by_severity(Severity::Low) as f64 * 1.0;
        let penalty = critical + high + medium + low;
        (100.0 - penalty).clamp(0.0, 100.0)
    }

    /// Average risk score 0–10
    pub fn avg_risk_score(&self) -> f64 {
        let all = self.all_sorted();
        if all.is_empty() {
            return 0.0;
        }
        all.iter().map(|f| f.risk_score()).sum::<f64>() / all.len() as f64
    }
}

/// Run the `cipher-ai report` command
pub async fn run_report(
    project_path: &Path,
    report_type: &str,
    format: &str,
    output_file: Option<&str>,
) -> Result<()> {
    let canonical_path = std::fs::canonicalize(project_path)?;
    println!(
        "{} {}",
        "[STATS]".bright_blue(),
        format!("Generating security report for {}...", canonical_path.display()).bold()
    );

    // Phase 1: Collect findings from all sources
    println!("  {} Running security review...", "[*]".cyan());
    let review_report = review::collect_review_findings(&canonical_path, false, None).await?;

    println!("  {} Scanning dependencies...", "[PKG]".cyan());
    let deps_report = deps::collect_deps_findings(&canonical_path, false).await?;

    println!("  {} Scanning for secrets...", "[*]".cyan());
    let secrets_report = secrets::collect_secrets_findings(&canonical_path)?;

    // Phase 2: Build aggregated report
    let mut agg = AggregatedReport::new(canonical_path.to_string_lossy());
    agg.review = review_report.findings;
    agg.deps = deps_report.findings;
    agg.secrets = secrets_report.findings;

    // Phase 3: Generate output
    match format {
        "json" => {
            let json = generate_json(&agg);
            write_or_print(&json, output_file)?;
        }
        "markdown" | "md" => {
            let md = generate_markdown(&agg, report_type);
            write_or_print(&md, output_file)?;
        }
        _ => {
            // terminal (default)
            print_terminal(&agg, report_type);
        }
    }

    Ok(())
}

/// Write content to file or print to stdout
fn write_or_print(content: &str, output_file: Option<&str>) -> Result<()> {
    if let Some(path) = output_file {
        std::fs::write(path, content)?;
        println!(
            "  {} Report written to {}",
            "[FILE]".green(),
            path.yellow().bold()
        );
    } else {
        println!("{}", content);
    }
    Ok(())
}

/// Generate a JSON report
fn generate_json(report: &AggregatedReport) -> String {
    #[derive(Serialize)]
    struct JsonOutput<'a> {
        project_path: &'a str,
        created_at: &'a str,
        security_score: f64,
        total_findings: usize,
        summary: JsonSummary,
        findings: Vec<&'a Finding>,
    }

    #[derive(Serialize)]
    struct JsonSummary {
        critical: usize,
        high: usize,
        medium: usize,
        low: usize,
    }

    let output = JsonOutput {
        project_path: &report.project_path,
        created_at: &report.created_at,
        security_score: report.security_score(),
        total_findings: report.total_findings(),
        summary: JsonSummary {
            critical: report.count_by_severity(Severity::Critical),
            high: report.count_by_severity(Severity::High),
            medium: report.count_by_severity(Severity::Medium),
            low: report.count_by_severity(Severity::Low),
        },
        findings: report.all_sorted(),
    };

    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
}

/// Generate a Markdown report
fn generate_markdown(report: &AggregatedReport, report_type: &str) -> String {
    match report_type {
        "executive" => generate_executive_md(report),
        "ci" => generate_ci_md(report),
        _ => generate_developer_md(report), // default
    }
}

/// Generate an executive summary (non-technical, for managers)
fn generate_executive_md(report: &AggregatedReport) -> String {
    let score = report.security_score();
    let score_badge = if score >= 80.0 {
        "[GREEN]"
    } else if score >= 50.0 {
        "[YELLOW]"
    } else {
        "[RED]"
    };

    let mut md = String::new();

    md.push_str("# Security Report — Executive Summary\n\n");
    md.push_str(&format!(
        "**Project:** `{}`  \n", report.project_path
    ));
    md.push_str(&format!(
        "**Generated:** {}  \n", report.created_at
    ));
    md.push_str("**Tool:** CipherAI — AI-Powered Security Analysis\n\n");

    md.push_str("## Overall Security Score\n\n");
    md.push_str(&format!(
        "{} **{:.0}/100**\n\n", score_badge, score
    ));

    if score >= 80.0 {
        md.push_str("Your project has a **good** security posture. Minor issues to address.\n\n");
    } else if score >= 50.0 {
        md.push_str("Your project has **moderate** security risks that should be addressed soon.\n\n");
    } else {
        md.push_str("Your project has **critical** security risks that need immediate attention.\n\n");
    }

    md.push_str("## Finding Summary\n\n");
    md.push_str("| Severity | Count |\n");
    md.push_str("|----------|------:|\n");
    md.push_str(&format!(
        "| [RED] Critical | {} |\n",
        report.count_by_severity(Severity::Critical)
    ));
    md.push_str(&format!(
        "| 🟠 High | {} |\n",
        report.count_by_severity(Severity::High)
    ));
    md.push_str(&format!(
        "| [YELLOW] Medium | {} |\n",
        report.count_by_severity(Severity::Medium)
    ));
    md.push_str(&format!(
        "| [BLUE] Low | {} |\n",
        report.count_by_severity(Severity::Low)
    ));
    md.push_str(&format!(
        "| **Total** | **{}** |\n\n",
        report.total_findings()
    ));

    md.push_str("## Top Risks\n\n");
    let top = report.all_sorted();
    for (i, finding) in top.iter().take(5).enumerate() {
        md.push_str(&format!(
            "**{}. {}** ({:.0}/10)  \n",
            i + 1,
            finding.title,
            finding.risk_score()
        ));
        if let Some(ref fp) = finding.file_path {
            md.push_str(&format!(
                "   - File: `{}`{}  \n",
                fp,
                finding.line_number.map(|l| format!(":{}", l)).unwrap_or_default()
            ));
        }
        md.push_str(&format!(
            "   - {} — {}  \n\n",
            finding.severity,
            finding.confidence
        ));
    }

    md.push_str("## Recommendations\n\n");
    let critical_high = report.count_by_severity(Severity::Critical) + report.count_by_severity(Severity::High);
    if critical_high > 0 {
        md.push_str(&format!(
            "- [RED] **{} critical/high severity issues** should be fixed immediately.\n",
            critical_high
        ));
    }
    if report.count_by_type(FindingType::Secret) > 0 {
        md.push_str(&format!(
            "- [KEY] **{} secrets/credentials exposed** — rotate them and use a secret manager.\n",
            report.count_by_type(FindingType::Secret)
        ));
    }
    if report.count_by_type(FindingType::Dependency) > 0 {
        md.push_str(&format!(
            "- [PKG] **{} vulnerable dependencies** — update affected packages.\n",
            report.count_by_type(FindingType::Dependency)
        ));
    }
    md.push_str("- Consider running `cipher-ai review --ai` for deeper AI-powered analysis.\n");
    md.push_str("- Run `cipher-ai deps --online` for comprehensive OSV.dev database checks.\n\n");

    md.push_str("---\n\n");
    md.push_str("*Report generated by [CipherAI](https://github.com/sandeepannandi/Cipher)*\n");

    md
}

/// Generate a developer report (detailed, per-finding)
fn generate_developer_md(report: &AggregatedReport) -> String {
    let mut md = String::new();

    md.push_str("# Security Report — Developer Details\n\n");
    md.push_str(&format!("**Project:** `{}`  \n", report.project_path));
    md.push_str(&format!("**Generated:** {}  \n\n", report.created_at));

    md.push_str("## Summary\n\n");
    md.push_str("| Severity | Count |\n|----------|------:|\n");
    md.push_str(&format!("| [RED] Critical | {} |\n", report.count_by_severity(Severity::Critical)));
    md.push_str(&format!("| 🟠 High | {} |\n", report.count_by_severity(Severity::High)));
    md.push_str(&format!("| [YELLOW] Medium | {} |\n", report.count_by_severity(Severity::Medium)));
    md.push_str(&format!("| [BLUE] Low | {} |\n", report.count_by_severity(Severity::Low)));
    md.push_str(&format!("| **Total** | **{}** |\n\n", report.total_findings()));
    md.push_str(&format!("**Security Score:** {:.0}/100  \n\n", report.security_score()));

    let total = report.total_findings();
    if total == 0 {
        md.push_str("[OK] **No security issues found!** Your project looks clean.\n\n");
        return md;
    }

    md.push_str("## Detailed Findings\n\n");

    for (i, finding) in report.all_sorted().iter().enumerate() {
        md.push_str(&format!("### {}. {} ({:.0}/10)\n\n", i + 1, finding.title, finding.risk_score()));

        md.push_str("| Field | Value |\n|-------|-------|\n");
        md.push_str(&format!("| Severity | {} |\n", finding.severity));
        md.push_str(&format!("| Confidence | {} |\n", finding.confidence));
        md.push_str(&format!("| Type | {} |\n", finding.finding_type));
        if let Some(ref owasp) = finding.owasp_category {
            md.push_str(&format!("| OWASP | {} |\n", owasp));
        }
        if let Some(ref cve) = finding.cve_id {
            md.push_str(&format!("| CVE | {} |\n", cve));
        }
        if let Some(ref fp) = finding.file_path {
            let line = finding.line_number.map(|l| format!(":{}", l)).unwrap_or_default();
            md.push_str(&format!("| File | `{}` |\n", fp));
            md.push_str(&format!("| Line | {} |\n", line));
        }
        md.push_str(&format!("| Exploitability | {:.0}% |\n", finding.exploitability * 100.0));
        md.push_str(&format!("| Remediation Effort | {} |\n", finding.remediation_effort));
        md.push_str("\n");

        md.push_str("**Description:**\n\n");
        md.push_str(&format!("{}\n\n", finding.description));

        if let Some(ref code) = finding.code_snippet {
            md.push_str("**Code:**\n\n```\n");
            md.push_str(code);
            md.push_str("\n```\n\n");
        }

        if let Some(ref rem) = finding.remediation {
            md.push_str("**Remediation:**\n\n");
            md.push_str(&format!("{}\n\n", rem));
        }

        md.push_str("---\n\n");
    }

    md.push_str("*Report generated by [CipherAI](https://github.com/sandeepannandi/Cipher)*\n");

    md
}

/// Generate a CI-friendly Markdown report (compact)
fn generate_ci_md(report: &AggregatedReport) -> String {
    let mut md = String::new();
    md.push_str("## CipherAI Security Scan Results\n\n");

    let score = report.security_score();
    let status = if score >= 80.0 {
        "[OK] PASS"
    } else if score >= 50.0 {
        "[!] WARNING"
    } else {
        "[ERR] FAIL"
    };

    md.push_str(&format!("**Status:** {}  \n", status));
    md.push_str(&format!("**Score:** {:.0}/100  \n", score));
    md.push_str(&format!("**Findings:** {}  \n", report.total_findings()));
    md.push_str(&format!(
        "**Critical:** {} | **High:** {} | **Medium:** {} | **Low:** {}  \n\n",
        report.count_by_severity(Severity::Critical),
        report.count_by_severity(Severity::High),
        report.count_by_severity(Severity::Medium),
        report.count_by_severity(Severity::Low),
    ));

    let top = report.all_sorted();
    if !top.is_empty() {
        md.push_str("### Top 10 Findings\n\n");
        md.push_str("| # | Severity | Title | File | Risk |\n|---|---|---|---|---|\n");
        for (i, finding) in top.iter().take(10).enumerate() {
            let fp = finding.file_path.as_deref().unwrap_or("<unknown>");
            let sev_icon = match finding.severity {
                Severity::Critical => "[RED]",
                Severity::High => "🟠",
                Severity::Medium => "[YELLOW]",
                Severity::Low => "[BLUE]",
                Severity::Info => "[WHITE]",
            };
            md.push_str(&format!(
                "| {} | {} | {} | `{}` | {:.0}/10 |\n",
                i + 1,
                sev_icon,
                finding.title,
                fp,
                finding.risk_score()
            ));
        }
    }

    md
}

/// Print the aggregated report to the terminal
fn print_terminal(report: &AggregatedReport, _report_type: &str) {
    let total = report.total_findings();
    let score = report.security_score();

    println!();
    println!("{}", "+----------------------------------------------┐".bright_blue());
    println!(
        "{} {} {}",
        "|".bright_blue(),
        "CipherAI Security Report".bold().white(),
        "|".bright_blue()
    );
    println!("{}", "+----------------------------------------------┘".bright_blue());
    println!();

    let score_color = if score >= 80.0 { "green" } else if score >= 50.0 { "yellow" } else { "red" };
    println!(
        "  {} {}",
        "Security Score:".bold(),
        format!("{:.0}/100", score).color(score_color).bold()
    );
    println!(
        "  {} {}",
        "Average Risk:".bold(),
        format!("{:.1}/10", report.avg_risk_score()).dimmed()
    );
    println!();

    // Summary table
    println!("  {} {}  {} {}  {} {}  {} {}  ({} total)",
        "*".red().bold(),
        report.count_by_severity(Severity::Critical).to_string().red().bold(),
        "*".yellow().bold(),
        report.count_by_severity(Severity::High).to_string().yellow().bold(),
        "*".cyan(),
        report.count_by_severity(Severity::Medium).to_string().cyan(),
        "o".dimmed(),
        report.count_by_severity(Severity::Low).to_string().dimmed(),
        total.to_string().bold()
    );
    println!();

    // Per-source breakdown (deduplicated so the numbers stay consistent)
    let deduped = report.deduped_all();
    println!("  {} {}\n", "[FOLDER]".bold(), "Breakdown by Source".bold());
    println!(
        "    {} Security Review:  {}",
        "[*]".cyan(),
        deduped
            .iter()
            .filter(|f| f.source == "security-review" || f.source == "ai-review")
            .count()
            .to_string()
            .bold()
    );
    println!(
        "    {} Dependencies:     {}",
        "[PKG]".cyan(),
        deduped
            .iter()
            .filter(|f| f.source == "dependency-scanner")
            .count()
            .to_string()
            .bold()
    );
    println!(
        "    {} Secrets:          {}",
        "[KEY]".cyan(),
        deduped
            .iter()
            .filter(|f| f.source == "secret-scanner")
            .count()
            .to_string()
            .bold()
    );
    println!();

    if total == 0 {
        println!("  {} No security issues found!", "[OK]".green().bold());
        println!("  Your project looks clean.");
        println!();
        return;
    }

    // Top findings
    println!("  {} {} (all findings sorted by risk)\n", "[TARGET]".bold(), "Top Findings".bold());
    let all = report.all_sorted();
    let max_show = all.len().min(10);
    for finding in all.iter().take(max_show) {
        let fp = finding.file_path.as_deref().unwrap_or("<unknown>");
        let line = finding.line_number.map(|l| format!(":{}", l)).unwrap_or_default();
        println!(
            "    {}  {}  {}  {}  [{:.0}/10]",
            finding.severity.badge(),
            finding.finding_type.icon(),
            format!("{}", finding.title).bold(),
            format!("{}{}", fp, line).yellow().dimmed(),
            finding.risk_score()
        );
    }
    if all.len() > max_show {
        println!("    ... and {} more findings", (all.len() - max_show).to_string().dimmed());
    }
    println!();

    // Output suggestion
    println!("  {} {}", "[IDEA]".bold(), "For a detailed report:".bold());
    println!("cipher-ai report --format markdown --output report.md");
    println!("cipher-ai report --format json --output report.json");
    println!("cipher-ai report --type executive  (for managers)");
    println!();

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Confidence, FindingType, Severity};

    fn mk(title: &str, source: &str, sev: Severity) -> Finding {
        Finding::new(
            FindingType::Vulnerability,
            title,
            "desc",
            sev,
            Confidence::High,
            source,
        )
    }

    #[test]
    fn test_security_score_clean() {
        let report = AggregatedReport::new("/proj");
        assert_eq!(report.security_score(), 100.0);
    }

    #[test]
    fn test_security_score_penalizes_critical() {
        let mut report = AggregatedReport::new("/proj");
        report.review.push(mk("SQL Injection", "security-review", Severity::Critical));
        assert_eq!(report.security_score(), 75.0);
    }

    #[test]
    fn test_security_score_clamped() {
        let mut report = AggregatedReport::new("/proj");
        // Distinct locations so dedup doesn't collapse them into one finding
        for i in 0..10 {
            let f = mk("SQL Injection", "security-review", Severity::Critical).at(format!("/proj/f{}.py", i), 1);
            report.review.push(f);
        }
        assert_eq!(report.security_score(), 0.0);
    }

    #[test]
    fn test_total_findings_dedup_cross_scanner() {
        let mut report = AggregatedReport::new("/proj");
        let mut review_f = mk("Hardcoded Credentials", "security-review", Severity::High);
        review_f = review_f.at("/proj/a.py", 5);
        let mut secrets_f = mk("Password in Code", "secret-scanner", Severity::High);
        secrets_f = secrets_f.at("/proj/a.py", 5);
        report.review.push(review_f);
        report.secrets.push(secrets_f);

        // Both point at the same credential line — should count once
        assert_eq!(report.total_findings(), 1);
        assert_eq!(report.all_sorted().len(), 1);
    }

    #[test]
    fn test_count_by_severity_deduped() {
        let mut report = AggregatedReport::new("/proj");
        let mut a = mk("Hardcoded Credentials", "security-review", Severity::High);
        a = a.at("/proj/a.py", 5);
        let mut b = mk("Password in Code", "secret-scanner", Severity::High);
        b = b.at("/proj/a.py", 5);
        report.review.push(a);
        report.secrets.push(b);
        assert_eq!(report.count_by_severity(Severity::High), 1);
    }
}
