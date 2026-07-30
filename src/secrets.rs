use crate::finding::{Confidence, Finding, FindingReport, FindingType, RemediationEffort, Severity};
use crate::output;
use crate::scan;
use anyhow::{Context, Result};
use colored::*;
use ignore::WalkBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::Path;

/// A single detection pattern
struct SecretPattern {
    name: &'static str,
    severity: Severity,
    pattern: regex_lite::Regex,
}

/// Build regex patterns for secret detection
fn build_patterns() -> Vec<SecretPattern> {
    let mut patterns = Vec::new();

    // Helper to add a pattern
    macro_rules! add_pattern {
        ($name:expr, $severity:expr, $pattern:expr) => {
            if let Ok(re) = regex_lite::Regex::new($pattern) {
                patterns.push(SecretPattern {
                    name: $name,
                    severity: $severity,
                    pattern: re,
                });
            }
        };
    }

    // API Keys & Tokens
    add_pattern!("AWS Access Key ID", Severity::High,
        r"(?i)(?<![a-zA-Z0-9])(AKIA[0-9A-Z]{16})(?![a-zA-Z0-9])");

    add_pattern!("AWS Secret Access Key", Severity::Critical,
        r"(?i)(?<![a-zA-Z0-9/+=])([a-zA-Z0-9/+=]{40})(?![a-zA-Z0-9/+=])");

    add_pattern!("Google API Key", Severity::High,
        r"(?i)(?<![a-zA-Z0-9])(AIza[0-9A-Za-z\-_]{35})(?![a-zA-Z0-9])");

    add_pattern!("Google OAuth Key", Severity::High,
        r"(?i)(?<![a-zA-Z0-9])([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)");

    add_pattern!("GitHub Personal Access Token", Severity::Critical,
        r"(?i)(ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{36})");

    add_pattern!("GitHub OAuth Token", Severity::Critical,
        r"(?i)(gho_[0-9a-zA-Z]{36})");

    add_pattern!("GitHub App Token", Severity::Critical,
        r"(?i)(ghs_[0-9a-zA-Z]{36})");

    add_pattern!("GitLab Personal Access Token", Severity::Critical,
        r"(?i)(glpat-[0-9a-zA-Z\-_]{20,})");

    add_pattern!("GitLab CI/CD Token", Severity::High,
        r"(?i)(glcbt-[0-9a-zA-Z\-_]{20,})");

    add_pattern!("Slack Token", Severity::Critical,
        r"(?i)(xox[baprs]-[0-9a-zA-Z\-_]{10,})");

    add_pattern!("Discord Bot Token", Severity::Critical,
        r"(?i)([MN][A-Za-z0-9\-_]{23,25}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27})");

    add_pattern!("Stripe Live API Key", Severity::Critical,
        r"(?i)(sk_live_[0-9a-zA-Z]{24,})");

    add_pattern!("Stripe Test API Key", Severity::Low,
        r"(?i)(sk_test_[0-9a-zA-Z]{24,})");

    add_pattern!("Stripe Publishable Key", Severity::Low,
        r"(?i)(pk_test_|pk_live_)[0-9a-zA-Z]{24,}");

    add_pattern!("JWT Token", Severity::Medium,
        r"(?i)(eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_+/=]+)");

    add_pattern!("Azure Storage Key", Severity::High,
        r"(?i)(DefaultEndpointsProtocol=https;AccountName=[a-zA-Z0-9]+;AccountKey=[a-zA-Z0-9+/=]{40,})");

    add_pattern!("Azure Connection String", Severity::High,
        r"(?i)(Server=[a-zA-Z0-9.\-]+;Database=[a-zA-Z0-9]+;User\s*Id=[a-zA-Z0-9@.\-]+;Password=[^;]+)");

    add_pattern!("Heroku API Key", Severity::High,
        r"(?i)([hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})");

    add_pattern!("Generic Private Key", Severity::High,
        r"-----BEGIN\s?(RSA|DSA|EC|OPENSSH|PGP|PRIVATE)\s?KEY-----");

    add_pattern!("Password in Code", Severity::Medium,
        r#"(?i)(password|passwd|pwd)\s*[=:]\s*['"][^'"]{4,}['"]"#);

    add_pattern!("Secret in Code", Severity::Medium,
        r#"(?i)(secret|token|api[_-]?key|auth[_-]?key)\s*[=:]\s*['"][^'"]{8,}['"]"#);

    add_pattern!("Database Connection String", Severity::High,
        r"(?i)(postgresql|mysql|mongodb|redis|rediss)://[a-zA-Z0-9]+:[^@]+@");

    add_pattern!("npm Auth Token", Severity::High,
        r"(?i)(//registry\.npmjs\.org/:_authToken=)[a-zA-Z0-9\-_]+");

    add_pattern!("Slack Webhook URL", Severity::High,
        r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+");

    add_pattern!("Google Service Account", Severity::Critical,
        r#"(?i)"type":\s*"service_account""#);

    add_pattern!("AWS Secret Key Pattern", Severity::Critical,
        r#"(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*['"][a-zA-Z0-9/+=]{40}['"]"#);

    patterns
}

/// Scan a file for secrets
fn scan_file(path: &Path, patterns: &[SecretPattern]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return findings,
    };

    for (line_num, line) in content.lines().enumerate() {
        let line_number = line_num + 1;
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty()
            || trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
        {
            continue;
        }

        for pattern in patterns {
            if pattern.pattern.is_match(line) {
                let exploitability = match pattern.severity {
                    Severity::Critical => 0.9,
                    Severity::High => 0.7,
                    Severity::Medium => 0.5,
                    Severity::Low => 0.3,
                    Severity::Info => 0.1,
                };
                let effort = match pattern.severity {
                    Severity::Critical => RemediationEffort::Hours,
                    Severity::High => RemediationEffort::Hours,
                    Severity::Medium => RemediationEffort::Minutes,
                    Severity::Low => RemediationEffort::Minutes,
                    Severity::Info => RemediationEffort::Minutes,
                };
                findings.push(
                    Finding::new(
                        FindingType::Secret,
                        pattern.name,
                        format!(
                            "{} credential detected in {}",
                            pattern.name,
                            path.display()
                        ),
                        pattern.severity,
                        Confidence::High,
                        "secret-scanner",
                    )
                    .at(path.to_string_lossy().to_string(), line_number)
                    .with_code(line.to_string())
                    .with_remediation(format!(
                        "Remove the {} from the code. Use environment variables or a secret manager instead.",
                        pattern.name
                    ))
                    .with_exploitability(exploitability)
                    .with_effort(effort),
                );
            }
        }
    }

    findings
}

/// Check if a path should be excluded


/// Collect secret findings without displaying them (for report generation)
pub(crate) fn collect_secrets_findings(scan_path: &Path) -> Result<FindingReport> {
    let canonical_path = std::fs::canonicalize(scan_path)
        .with_context(|| format!("Cannot access path: {}", scan_path.display()))?;

    let patterns = build_patterns();
    let walker = WalkBuilder::new(&canonical_path)
        .git_ignore(true)
        .git_global(true)
        .hidden(false)
        .max_depth(Some(scan::MAX_WALK_DEPTH))
        .build();

    let mut report = FindingReport::new("secret-scanner", canonical_path.to_string_lossy());
    let mut file_count = 0;
    for result in walker {
        if file_count >= scan::MAX_SCAN_FILES {
            eprintln!(
                "  {} Reached scan limit of {} files. Some files may not be checked for secrets.",
                "[!]".yellow(),
                scan::MAX_SCAN_FILES
            );
            break;
        }
        if let Ok(entry) = result {
            let path = entry.path();
            if path.is_file() && !scan::should_exclude(path) && !scan::is_binary(path) {
                report.extend(scan_file(path, &patterns));
                file_count += 1;
            }
        }
    }

    Ok(report)
}

/// Run the `cipher-ai secrets` command
pub async fn run_secrets(
    scan_path: &Path,
    format: &str,
    fail_on: Option<&str>,
) -> Result<()> {
    let canonical_path = std::fs::canonicalize(scan_path)
        .with_context(|| format!("Cannot access path: {}", scan_path.display()))?;

    output::print_header("Secrets Scan", Some(&format!("Scanning {}", canonical_path.display())));

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} Scanning files... {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb.set_message("scanning...");

    let report = collect_secrets_findings(&canonical_path)?;

    pb.finish_and_clear();

    // Group by severity for display
    let critical_count = report.findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high_count = report.findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium_count = report.findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low_count = report.findings.iter().filter(|f| f.severity == Severity::Low).count();

    println!();
    println!(
        "{} Scanned project directory",
        "[STATS]".bright_blue()
    );
    println!(
        "  {} {} CRITICAL  {} {} HIGH  {} {} MEDIUM  {} {} LOW",
        "*".red().bold(),
        critical_count.to_string().red().bold(),
        "*".yellow().bold(),
        high_count.to_string().yellow().bold(),
        "*".cyan(),
        medium_count.to_string().cyan(),
        "*".dimmed(),
        low_count.to_string().dimmed(),
    );

    if report.is_empty() {
        println!();
        println!("{} No secrets found! Your codebase looks clean.", "[OK]".green().bold());
        return Ok(());
    }

    // Group findings by file
    use std::collections::BTreeMap;
    let mut by_file: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for finding in &report.findings {
        if let Some(ref fp) = finding.file_path {
            by_file.entry(fp.clone()).or_default().push(finding);
        }
    }

    // Output findings
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&report.findings)?);
    } else if format == "compact" {
        for finding in &report.findings {
            let fp = finding.file_path.as_deref().unwrap_or("<unknown>");
            let ln = finding.line_number.map(|l| l.to_string()).unwrap_or_default();
            println!("{} {}:{} {}", finding.severity.badge(), fp, ln, finding.title.dimmed());
        }
    } else {
        // "pretty" format (default)
        println!();
        for (file_path, findings) in &by_file {
            println!("  {} {}", "[FOLDER]".cyan(), file_path.bold());
            for finding in findings {
                let badge = finding.severity.badge();
                let line_str = finding.line_number.map(|l| format!("Line {}", l)).unwrap_or_default();
                println!("    {} {}  {}", badge, line_str.yellow(), finding.title.bold());
                if let Some(ref snippet) = finding.code_snippet {
                    let shown = snippet.trim();
                    if shown.len() > 100 {
                        println!("      {}...", &shown[..100].dimmed());
                    } else {
                        println!("      {}", shown.dimmed());
                    }
                }
            }
            println!();
        }

        if critical_count > 0 || high_count > 0 {
            println!(
                "{} Found {} critical/high severity secrets. Review and remove them immediately.",
                "[!]".yellow().bold(),
                (critical_count + high_count).to_string().bold()
            );
        }
    }

    // Handle --fail-on (exit with code 1 if threshold exceeded)
    let fail_severity_score = fail_on.and_then(|s| match s.to_lowercase().as_str() {
        "critical" => Some(4),
        "high" => Some(3),
        "medium" => Some(2),
        "low" => Some(1),
        _ => None,
    });
    if let Some(min_score) = fail_severity_score {
        let has_failing = report.findings.iter().any(|f| f.severity.score() >= min_score);
        if has_failing {
            eprintln!(
                "  {} --fail-on threshold exceeded. Exiting with code 1.",
                "[FAIL]".red().bold()
            );
            std::process::exit(1);
        }
    }

    Ok(())
}


