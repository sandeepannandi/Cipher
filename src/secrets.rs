use anyhow::{Context, Result};
use colored::*;
use ignore::WalkBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use std::path::Path;

/// A detected secret
#[derive(Debug, Clone, Serialize)]
pub struct SecretFinding {
    pub file_path: String,
    pub line_number: usize,
    pub line_content: String,
    pub secret_type: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
        }
    }
}

/// A single detection pattern
struct SecretPattern {
    name: &'static str,
    severity: Severity,
    pattern: regex_lite::Regex,
}

/// Files/directories to always exclude from secret scanning
const ALWAYS_EXCLUDE: &[&str] = &[
    ".secagent", ".git", "node_modules", "vendor", "target",
    "__pycache__", ".tox", ".venv", "venv", ".env.example",
    "*.lock", "package-lock.json", "yarn.lock", "Cargo.lock",
    "*.svg", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico",
    "*.woff", "*.woff2", "*.ttf", "*.eot",
    "*.min.js", "*.min.css",
];

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
fn scan_file(path: &Path, patterns: &[SecretPattern]) -> Vec<SecretFinding> {
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
                findings.push(SecretFinding {
                    file_path: path.to_string_lossy().to_string(),
                    line_number,
                    line_content: line.to_string(),
                    secret_type: pattern.name.to_string(),
                    severity: pattern.severity,
                });
                // Don't break - could match multiple patterns on same line
            }
        }
    }

    findings
}

/// Check if a path should be excluded
fn should_exclude(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    for exclude in ALWAYS_EXCLUDE {
        if exclude.starts_with("*.") {
            let ext = &exclude[1..]; // remove the *
            if path_str.ends_with(ext) {
                return true;
            }
        } else if path_str.contains(&exclude.to_lowercase()) {
            return true;
        }
    }
    false
}

/// Run the `sec secrets` command
pub async fn run_secrets(
    scan_path: &Path,
    format: &str,
    fail_on_secret: bool,
) -> Result<()> {
    let canonical_path = std::fs::canonicalize(scan_path)
        .with_context(|| format!("Cannot access path: {}", scan_path.display()))?;

    println!(
        "{} {}",
        "🔎".bright_blue(),
        format!("Scanning for secrets in {}...", canonical_path.display()).bold()
    );

    let patterns = build_patterns();

    // Collect files to scan
    let walker = WalkBuilder::new(&canonical_path)
        .git_ignore(true)
        .git_global(true)
        .hidden(false)
        .build();

    let mut all_findings: Vec<SecretFinding> = Vec::new();
    let mut files_scanned = 0u64;

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} Scanning files... {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    for result in walker {
        match result {
            Ok(entry) => {
                let path = entry.path();
                if path.is_file() && !should_exclude(path) {
                    files_scanned += 1;
                    // Check if it's a binary file first
                    if is_binary(path) {
                        continue;
                    }
                    let findings = scan_file(path, &patterns);
                    all_findings.extend(findings);
                    pb.set_message(format!("scanned {} files", files_scanned));
                }
            }
            Err(_) => {}
        }
    }

    pb.finish_and_clear();

    // Group by severity for display
    let critical_count = all_findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count();
    let high_count = all_findings.iter().filter(|f| matches!(f.severity, Severity::High)).count();
    let medium_count = all_findings.iter().filter(|f| matches!(f.severity, Severity::Medium)).count();
    let low_count = all_findings.iter().filter(|f| matches!(f.severity, Severity::Low)).count();

    println!();
    println!(
        "{} Scanned {} files",
        "📊".bright_blue(),
        files_scanned.to_string().bold()
    );
    println!(
        "  {} {} CRITICAL  {} {} HIGH  {} {} MEDIUM  {} {} LOW",
        "●".red().bold(),
        critical_count.to_string().red().bold(),
        "●".yellow().bold(),
        high_count.to_string().yellow().bold(),
        "●".cyan(),
        medium_count.to_string().cyan(),
        "●".dimmed(),
        low_count.to_string().dimmed(),
    );

    if all_findings.is_empty() {
        println!();
        println!("{} No secrets found! Your codebase looks clean.", "✅".green().bold());
        return Ok(());
    }

    // Group findings by file
    use std::collections::BTreeMap;
    let mut by_file: BTreeMap<String, Vec<&SecretFinding>> = BTreeMap::new();
    for finding in &all_findings {
        by_file
            .entry(finding.file_path.clone())
            .or_default()
            .push(finding);
    }

    // Output findings
    if format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&all_findings)?
        );
    } else if format == "compact" {
        for finding in &all_findings {
            println!(
                "{} {}:{} {}",
                severity_badge(&finding.severity),
                finding.file_path,
                finding.line_number,
                finding.secret_type.dimmed()
            );
        }
    } else {
        // "pretty" format (default)
        println!();
        for (file_path, findings) in &by_file {
            println!("  {} {}", "📁".cyan(), file_path.bold());
            for finding in findings {
                let badge = severity_badge(&finding.severity);
                println!(
                    "    {} {}  {}",
                    badge,
                    format!("Line {}", finding.line_number).yellow(),
                    finding.secret_type.bold()
                );
                let shown_line = finding.line_content.trim();
                if shown_line.len() > 100 {
                    println!(
                        "      {}",
                        format!("{}...", &shown_line[..100]).dimmed()
                    );
                } else {
                    println!("      {}", shown_line.dimmed());
                }
            }
            println!();
        }

        // Summary recommendation
        if critical_count > 0 || high_count > 0 {
            println!(
                "{} Found {} critical/high severity secrets. Review and remove them immediately.",
                "⚠".yellow().bold(),
                (critical_count + high_count).to_string().bold()
            );
        }
    }

    // Exit with error if requested
    if fail_on_secret && critical_count + high_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn severity_badge(severity: &Severity) -> colored::ColoredString {
    match severity {
        Severity::Critical => "●".red().bold(),
        Severity::High => "●".yellow().bold(),
        Severity::Medium => "●".cyan(),
        Severity::Low => "○".dimmed(),
    }
}

/// Rough check if a file is binary by looking at the first few bytes
fn is_binary(path: &Path) -> bool {
    use std::io::Read;
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return true,
    };
    let mut buf = [0u8; 1024];
    let n = match file.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return true,
    };
    // Check for null bytes (common in binary files)
    buf[..n].contains(&0u8)
}
