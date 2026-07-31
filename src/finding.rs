use chrono::Utc;
use colored::*;
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Severity of a security finding
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Return a colored badge string for display
    pub fn badge(&self) -> colored::ColoredString {
        match self {
            Severity::Critical => "*".red().bold(),
            Severity::High => "*".yellow().bold(),
            Severity::Medium => "*".cyan(),
            Severity::Low => "o".dimmed(),
            Severity::Info => "(i)".blue(),
        }
    }

    /// Return a colored label string for display
    pub fn label(&self) -> colored::ColoredString {
        match self {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::High => "HIGH".yellow().bold(),
            Severity::Medium => "MEDIUM".cyan(),
            Severity::Low => "LOW".dimmed(),
            Severity::Info => "INFO".blue(),
        }
    }

    /// Numeric score for sorting (higher = more severe)
    pub fn score(&self) -> u8 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }

    /// Parse a `--fail-on` threshold level into a `Severity`.
    /// Returns `None` for unknown levels.
    pub fn from_fail_on(s: &str) -> Option<Severity> {
        match s.to_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

/// Confidence level in the finding's accuracy
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn label(&self) -> colored::ColoredString {
        match self {
            Confidence::High => "HIGH".green().bold(),
            Confidence::Medium => "MEDIUM".yellow(),
            Confidence::Low => "LOW".dimmed(),
        }
    }

    pub fn score(&self) -> u8 {
        match self {
            Confidence::High => 3,
            Confidence::Medium => 2,
            Confidence::Low => 1,
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Confidence::High => write!(f, "HIGH"),
            Confidence::Medium => write!(f, "MEDIUM"),
            Confidence::Low => write!(f, "LOW"),
        }
    }
}

/// Estimated remediation effort
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RemediationEffort {
    Minutes,
    Hours,
    Days,
}

impl RemediationEffort {
    pub fn label(&self) -> colored::ColoredString {
        match self {
            RemediationEffort::Minutes => "minutes".green(),
            RemediationEffort::Hours => "hours".yellow(),
            RemediationEffort::Days => "days".red(),
        }
    }

    pub fn score(&self) -> u8 {
        match self {
            RemediationEffort::Minutes => 1,
            RemediationEffort::Hours => 2,
            RemediationEffort::Days => 3,
        }
    }
}

impl fmt::Display for RemediationEffort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RemediationEffort::Minutes => write!(f, "minutes"),
            RemediationEffort::Hours => write!(f, "hours"),
            RemediationEffort::Days => write!(f, "days"),
        }
    }
}

/// Category of security finding
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingType {
    Secret,
    Vulnerability,
    Misconfiguration,
    Dependency,
    BusinessLogic,
    Authentication,
    Authorization,
    Injection,
    Cryptography,
}

impl FindingType {
    pub fn icon(&self) -> &'static str {
        match self {
            FindingType::Secret => "[KEY]",
            FindingType::Vulnerability => "[BUG]",
            FindingType::Misconfiguration => "[CFG]",
            FindingType::Dependency => "[PKG]",
            FindingType::BusinessLogic => "[LOGIC]",
            FindingType::Authentication => "[AUTH]",
            FindingType::Authorization => "[SHIELD]",
            FindingType::Injection => "[INJECT]",
            FindingType::Cryptography => "[LOCK]",
        }
    }
}

impl fmt::Display for FindingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingType::Secret => write!(f, "secret"),
            FindingType::Vulnerability => write!(f, "vulnerability"),
            FindingType::Misconfiguration => write!(f, "misconfiguration"),
            FindingType::Dependency => write!(f, "dependency"),
            FindingType::BusinessLogic => write!(f, "business-logic"),
            FindingType::Authentication => write!(f, "authentication"),
            FindingType::Authorization => write!(f, "authorization"),
            FindingType::Injection => write!(f, "injection"),
            FindingType::Cryptography => write!(f, "cryptography"),
        }
    }
}

/// OWASP Top 10 categories
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OwaspCategory {
    A01BrokenAccessControl,
    A02CryptographicFailures,
    A03Injection,
    A04InsecureDesign,
    A05SecurityMisconfiguration,
    A06VulnerableComponents,
    A07AuthFailures,
    A08IntegrityFailures,
    A09LoggingFailures,
    A10SSRF,
}

impl OwaspCategory {
    pub fn code(&self) -> &'static str {
        match self {
            OwaspCategory::A01BrokenAccessControl => "A01:2021",
            OwaspCategory::A02CryptographicFailures => "A02:2021",
            OwaspCategory::A03Injection => "A03:2021",
            OwaspCategory::A04InsecureDesign => "A04:2021",
            OwaspCategory::A05SecurityMisconfiguration => "A05:2021",
            OwaspCategory::A06VulnerableComponents => "A06:2021",
            OwaspCategory::A07AuthFailures => "A07:2021",
            OwaspCategory::A08IntegrityFailures => "A08:2021",
            OwaspCategory::A09LoggingFailures => "A09:2021",
            OwaspCategory::A10SSRF => "A10:2021",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            OwaspCategory::A01BrokenAccessControl => "Broken Access Control",
            OwaspCategory::A02CryptographicFailures => "Cryptographic Failures",
            OwaspCategory::A03Injection => "Injection",
            OwaspCategory::A04InsecureDesign => "Insecure Design",
            OwaspCategory::A05SecurityMisconfiguration => "Security Misconfiguration",
            OwaspCategory::A06VulnerableComponents => "Vulnerable and Outdated Components",
            OwaspCategory::A07AuthFailures => "Identification and Authentication Failures",
            OwaspCategory::A08IntegrityFailures => "Software and Data Integrity Failures",
            OwaspCategory::A09LoggingFailures => "Security Logging and Monitoring Failures",
            OwaspCategory::A10SSRF => "Server-Side Request Forgery",
        }
    }
}

impl fmt::Display for OwaspCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} — {}", self.code(), self.name())
    }
}

/// A unified security finding across all analysis modules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding
    pub id: String,
    /// Type of finding
    pub finding_type: FindingType,
    /// Short title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Severity level
    pub severity: Severity,
    /// Confidence in the finding
    pub confidence: Confidence,
    /// Source file path (if applicable)
    pub file_path: Option<String>,
    /// Line number in source file (if applicable)
    pub line_number: Option<usize>,
    /// Code snippet showing the issue
    pub code_snippet: Option<String>,
    /// Suggested remediation
    pub remediation: Option<String>,
    /// OWASP Top 10 category (if applicable)
    pub owasp_category: Option<OwaspCategory>,
    /// CWE identifier (if applicable), e.g. "CWE-89"
    #[serde(default)]
    pub cwe_id: Option<String>,
    /// CVE identifier (if applicable)
    pub cve_id: Option<String>,
    /// Exploitability score 0.0–1.0
    pub exploitability: f64,
    /// Business impact score 0.0–1.0 (how damaging this is to the business)
    #[serde(default = "default_business_impact")]
    pub business_impact: f64,
    /// Estimated remediation effort
    pub remediation_effort: RemediationEffort,
    /// Timestamp when the finding was created
    pub created_at: String,
    /// Source module that produced this finding
    pub source: String,
}

/// Default business impact (moderate) for findings deserialized from older reports
fn default_business_impact() -> f64 {
    0.5
}

impl Finding {
    /// Create a new finding with sensible defaults
    pub fn new(
        finding_type: FindingType,
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        confidence: Confidence,
        source: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            finding_type,
            title: title.into(),
            description: description.into(),
            severity,
            confidence,
            file_path: None,
            line_number: None,
            code_snippet: None,
            remediation: None,
            owasp_category: None,
            cwe_id: None,
            cve_id: None,
            exploitability: 0.5,
            business_impact: 0.5,
            remediation_effort: RemediationEffort::Hours,
            created_at: Utc::now().to_rfc3339(),
            source: source.into(),
        }
    }

    /// Chainable setter for file_path and line_number
    pub fn at(mut self, file_path: impl Into<String>, line_number: usize) -> Self {
        self.file_path = Some(file_path.into());
        self.line_number = Some(line_number);
        self
    }

    /// Chainable setter for code_snippet
    pub fn with_code(mut self, snippet: impl Into<String>) -> Self {
        self.code_snippet = Some(snippet.into());
        self
    }

    /// Chainable setter for remediation
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Chainable setter for owasp_category
    pub fn with_owasp(mut self, category: OwaspCategory) -> Self {
        self.owasp_category = Some(category);
        self
    }

    /// Chainable setter for cwe_id
    pub fn with_cwe(mut self, cwe: impl Into<String>) -> Self {
        self.cwe_id = Some(cwe.into());
        self
    }

    /// Chainable setter for exploitability
    pub fn with_exploitability(mut self, score: f64) -> Self {
        self.exploitability = score.clamp(0.0, 1.0);
        self
    }

    /// Chainable setter for business impact
    pub fn with_business_impact(mut self, score: f64) -> Self {
        self.business_impact = score.clamp(0.0, 1.0);
        self
    }

    /// Chainable setter for remediation_effort
    pub fn with_effort(mut self, effort: RemediationEffort) -> Self {
        self.remediation_effort = effort;
        self
    }

    /// Chainable setter for cve_id
    pub fn with_cve(mut self, cve: impl Into<String>) -> Self {
        self.cve_id = Some(cve.into());
        self
    }

    /// Compute a risk score 0–10 combining severity, confidence, exploitability,
    /// and business impact.
    ///
    /// - Severity contributes 2–10 (INFO→1 .. CRITICAL→5, doubled)
    /// - Confidence contributes 0.5–1.5
    /// - Exploitability contributes 0–2 (reachability-weighted)
    /// - Business impact contributes 0–2
    pub fn risk_score(&self) -> f64 {
        let sev = self.severity.score() as f64 * 2.0; // 2–10
        let conf = self.confidence.score() as f64 * 0.5; // 0.5–1.5
        let exp = self.exploitability * 2.0; // 0–2
        let impact = self.business_impact * 2.0; // 0–2
        ((sev + conf + exp + impact) / 15.0 * 10.0).clamp(0.0, 10.0)
    }

    /// Display a single-line summary for compact output
    pub fn compact_string(&self) -> String {
        format!(
            "{} {} {} — {}",
            self.severity.badge(),
            self.file_path
                .as_deref()
                .unwrap_or("<unknown>")
                .yellow(),
            self.line_number
                .map(|l| format!(":{}", l))
                .unwrap_or_default(),
            self.title.bold()
        )
    }
}

/// A collection of findings with summary stats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingReport {
    pub findings: Vec<Finding>,
    pub created_at: String,
    pub source: String,
    pub project_path: String,
}

impl FindingReport {
    pub fn new(source: impl Into<String>, project_path: impl Into<String>) -> Self {
        Self {
            findings: Vec::new(),
            created_at: Utc::now().to_rfc3339(),
            source: source.into(),
            project_path: project_path.into(),
        }
    }

    pub fn add(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn extend(&mut self, findings: Vec<Finding>) {
        self.findings.extend(findings);
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Sort findings by risk score (highest first)
    pub fn sort_by_risk(&mut self) {
        self.findings
            .sort_by(|a, b| b.risk_score().partial_cmp(&a.risk_score()).unwrap_or(std::cmp::Ordering::Equal));
    }

    /// Count by severity
    pub fn count_by_severity(&self, severity: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == severity).count()
    }

    /// Count by type
    pub fn count_by_type(&self, finding_type: FindingType) -> usize {
        self.findings.iter().filter(|f| f.finding_type == finding_type).count()
    }

    /// Print a summary header
    pub fn print_summary(&self) {
        let critical = self.count_by_severity(Severity::Critical);
        let high = self.count_by_severity(Severity::High);
        let medium = self.count_by_severity(Severity::Medium);
        let low = self.count_by_severity(Severity::Low);

        println!();
        println!(
            "{} {}",
            "[STATS]".bright_blue(),
            "Findings Summary".bold()
        );
        println!("  {}", "-".repeat(40).dimmed());
        println!(
            "  {} {}  {} {}  {} {}  {} {}  ({} total)",
            "*".red().bold(),
            critical.to_string().red().bold(),
            "*".yellow().bold(),
            high.to_string().yellow().bold(),
            "*".cyan(),
            medium.to_string().cyan(),
            "o".dimmed(),
            low.to_string().dimmed(),
            self.len().to_string().bold()
        );

        if !self.findings.is_empty() {
            let avg_risk: f64 =
                self.findings.iter().map(|f| f.risk_score()).sum::<f64>() / self.len() as f64;
            println!(
                "  {} Average risk score: {:.1}/10",
                "[TARGET]".bold(),
                avg_risk
            );
        }
    }

    /// Print all findings in detail
    pub fn print_detailed(&self) {
        for finding in &self.findings {
            println!();
            println!(
                "  {} [{}] {}",
                finding.finding_type.icon(),
                finding.severity.label(),
                finding.title.bold()
            );
            if let Some(ref owasp) = finding.owasp_category {
                println!("    {} {}", "OWASP:".bold().dimmed(), owasp);
            }
            if let Some(ref cwe) = finding.cwe_id {
                println!("    {} {}", "CWE:".bold().dimmed(), cwe.yellow());
            }
            if let Some(ref file) = finding.file_path {
                let line_info = finding
                    .line_number
                    .map(|l| format!(":{}", l))
                    .unwrap_or_default();
                println!("    {} {}{}", "File:".bold().dimmed(), file.yellow(), line_info);
            }
            if let Some(ref code) = finding.code_snippet {
                for line in code.lines().take(5) {
                    println!("    | {}", line.dimmed());
                }
                if code.lines().count() > 5 {
                    println!("    | {} more lines...", (code.lines().count() - 5).to_string().dimmed());
                }
            }
            println!("    {}", finding.description.trim());
            println!(
                "    {} Confidence: {} | Exploitability: {:.0}% | Effort: {}",
                "->".bold(),
                finding.confidence.label(),
                finding.exploitability * 100.0,
                finding.remediation_effort.label()
            );
            if let Some(ref remediation) = finding.remediation {
                println!("    {} {}", "Fix:".bold().green(), remediation.trim());
            }
        }
    }
}

/// Map a finding's title + type to a stable CWE identifier.
///
/// Falls back on the finding type when no title keyword matches.
pub fn cwe_for_title(title: &str, finding_type: FindingType) -> Option<String> {
    let t = title.to_lowercase();

    let cwe = if t.contains("sql injection") {
        "CWE-89"
    } else if t.contains("command injection") {
        "CWE-78"
    } else if t.contains("path traversal") {
        "CWE-22"
    } else if t.contains("template injection") {
        "CWE-1336"
    } else if t.contains("xss") {
        "CWE-79"
    } else if t.contains("ssrf") {
        "CWE-918"
    } else if t.contains("md5") || t.contains("sha1") || t.contains("weak hash") {
        "CWE-328"
    } else if t.contains("weak encryption") || t.contains("ecb")
        || t.contains("des_ede3") || t.contains("3des") || t.contains("tripledes") {
        // NOTE: match "weak encryption" (both DES & ECB titles contain it)
        // instead of bare "des", which would also match "deserialization".
        "CWE-327"
    } else if t.contains("hardcoded cryptographic key") || t.contains("encryption_key")
        || t.contains("aes_key") || t.contains("secret_key") {
        "CWE-321"
    } else if t.contains("hardcoded") && (t.contains("credential") || t.contains("password")) {
        "CWE-798"
    } else if t.contains("jwt") || t.contains("token_secret") || t.contains("signing_key") {
        "CWE-345"
    } else if t.contains("cookie") && (t.contains("insecure") || t.contains("httponly") || t.contains("samesite")) {
        "CWE-614"
    } else if t.contains("debug") {
        "CWE-489"
    } else if t.contains("cors") {
        "CWE-942"
    } else if t.contains("idor") || t.contains("object reference") {
        "CWE-639"
    } else if t.contains("deserialization") {
        "CWE-502"
    } else if t.contains("mass assignment") || t.contains("autobinding") {
        "CWE-915"
    } else if t.contains("logging") && t.contains("sensitive") {
        "CWE-532"
    } else if t.contains("ssl") || t.contains("tls") || t.contains("verification") {
        "CWE-295"
    } else if t.contains("dependency") || t.contains("cve") || t.contains("vulnerable package") {
        "CWE-1104"
    } else if t.contains("secret") || t.contains("api key") || t.contains("apikey")
        || t.contains("token") || t.contains("credential") {
        "CWE-798"
    } else if t.contains("auth") || t.contains("login") || t.contains("session") {
        "CWE-287"
    } else if t.contains("access control") || t.contains("authorization") || t.contains("permission") {
        "CWE-862"
    } else if t.contains("boundary") || t.contains("bounds") {
        "CWE-125"
    } else if t.contains("race") || t.contains("toctou") {
        "CWE-362"
    } else if t.contains("injection") {
        "CWE-74"
    } else {
        match finding_type {
            FindingType::Secret => "CWE-798",
            FindingType::Injection => "CWE-74",
            FindingType::Authentication => "CWE-287",
            FindingType::Authorization => "CWE-862",
            FindingType::Cryptography => "CWE-327",
            FindingType::Dependency => "CWE-1104",
            FindingType::Misconfiguration => "CWE-16",
            FindingType::BusinessLogic => "CWE-840",
            FindingType::Vulnerability => "CWE-693",
        }
    };
    Some(cwe.to_string())
}

/// Returns true if a finding's title indicates a credential/secret exposure.
/// Used by dedup: the review scanner and the secret scanner both report
/// credential-style issues at the same file:line, so they should collapse.
fn is_credential_like(f: &Finding) -> bool {
    let t = f.title.to_lowercase();
    [
        "password", "credential", "secret", "api key", "apikey", "token",
        "private key", "jwt", "aws", "github", "gitlab", "stripe", "slack",
        "discord", "heroku", "connection string", "service account",
    ]
    .iter()
    .any(|k| t.contains(k))
}

/// Compute the dedup key for a finding — the location (+ credential bucket)
/// used to decide whether two findings could be the same issue.
pub(crate) fn dedup_key(f: &Finding) -> (String, usize, String) {
    match (&f.file_path, f.line_number) {
        (Some(fp), Some(ln)) => {
            let bucket = if is_credential_like(f) {
                "credential".to_string()
            } else {
                f.title.to_lowercase()
            };
            (fp.clone(), ln, bucket)
        }
        _ => (format!("{}:{}", f.source, f.title.to_lowercase()), 0, String::new()),
    }
}

/// Decide whether two findings at the same location are duplicates.
///
/// Collapses when:
/// - their titles match case-insensitively (true duplicates), or
/// - both are credential-like AND reported by different scanners — the
///   classic overlap where `review` finds "Hardcoded Credentials" and
///   `secrets` finds "Password in Code" on the same line.
///
/// Two distinct secrets from the *same* scanner on the same line (e.g. an
/// AWS access key ID + secret access key pair) are NOT collapsed.
pub(crate) fn should_collapse(a: &Finding, b: &Finding) -> bool {
    let same_title = a.title.to_lowercase() == b.title.to_lowercase();
    if same_title {
        return true;
    }
    is_credential_like(a) && is_credential_like(b) && a.source != b.source
}

/// Remove cross-scanner duplicate findings, keeping the highest-risk version
/// of each duplicate. See [`Finding::risk_score`].
pub fn dedup_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut result: Vec<Finding> = Vec::new();

    for f in findings {
        let key = dedup_key(&f);
        let mut duplicate_idx = None;
        for (idx, existing) in result.iter().enumerate() {
            if dedup_key(existing) == key && should_collapse(existing, &f) {
                duplicate_idx = Some(idx);
                break;
            }
        }
        match duplicate_idx {
            Some(idx) => {
                // Keep the higher-risk version of the duplicate
                if f.risk_score() > result[idx].risk_score() {
                    result[idx] = f;
                }
            }
            None => result.push(f),
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(title: &str, path: &str, line: usize) -> Finding {
        Finding::new(
            FindingType::Vulnerability,
            title,
            "desc",
            Severity::High,
            Confidence::High,
            "test",
        )
        .at(path, line)
    }

    #[test]
    fn test_dedup_collapses_credential_overlap() {
        // review scanner + secrets scanner both flag the same line
        let mut f1 = mk("Hardcoded Credentials", "/proj/a.py", 10);
        f1.source = "security-review".to_string();
        let mut f2 = mk("Password in Code", "/proj/a.py", 10);
        f2.source = "secret-scanner".to_string();
        assert_eq!(dedup_findings(vec![f1, f2]).len(), 1);
    }

    #[test]
    fn test_dedup_keeps_distinct_same_line() {
        // Two genuinely different vulnerabilities on the same line survive
        let findings = vec![
            mk("SQL Injection", "/proj/a.py", 10),
            mk("Command Injection", "/proj/a.py", 10),
        ];
        assert_eq!(dedup_findings(findings).len(), 2);
    }

    #[test]
    fn test_dedup_keeps_different_lines() {
        let findings = vec![
            mk("Hardcoded Credentials", "/proj/a.py", 10),
            mk("Password in Code", "/proj/a.py", 20),
        ];
        assert_eq!(dedup_findings(findings).len(), 2);
    }

    #[test]
    fn test_dedup_keeps_distinct_same_scanner_secrets() {
        // Two distinct secrets from the SAME scanner on one line survive
        let mut f1 = mk("AWS Access Key ID", "/proj/.env", 2);
        f1.source = "secret-scanner".to_string();
        let mut f2 = mk("AWS Secret Access Key", "/proj/.env", 2);
        f2.source = "secret-scanner".to_string();
        assert_eq!(dedup_findings(vec![f1, f2]).len(), 2);
    }

    #[test]
    fn test_dedup_collapses_cross_scanner_credentials() {
        let mut f1 = mk("Hardcoded Credentials", "/proj/a.py", 10);
        f1.source = "security-review".to_string();
        let mut f2 = mk("Password in Code", "/proj/a.py", 10);
        f2.source = "secret-scanner".to_string();
        let result = dedup_findings(vec![f1, f2]);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_dedup_keeps_highest_risk() {
        let mut low = mk("Hardcoded Credentials", "/proj/a.py", 10);
        low.source = "security-review".to_string();
        low = low.with_effort(RemediationEffort::Minutes);
        let mut high = mk("Password in Code", "/proj/a.py", 10);
        high.source = "secret-scanner".to_string();
        high = high.with_exploitability(0.9);
        let result = dedup_findings(vec![low, high]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].source, "secret-scanner");
    }

    #[test]
    fn test_severity_from_fail_on() {
        assert_eq!(Severity::from_fail_on("critical"), Some(Severity::Critical));
        assert_eq!(Severity::from_fail_on("HIGH"), Some(Severity::High));
        assert_eq!(Severity::from_fail_on("Medium"), Some(Severity::Medium));
        assert_eq!(Severity::from_fail_on("low"), Some(Severity::Low));
        assert_eq!(Severity::from_fail_on("bogus"), None);
    }

    #[test]
    fn test_risk_score_sorting() {
        let critical = Finding::new(
            FindingType::Vulnerability,
            "c", "", Severity::Critical, Confidence::High, "t",
        );
        let low = Finding::new(
            FindingType::Vulnerability,
            "l", "", Severity::Low, Confidence::Low, "t",
        );
        assert!(critical.risk_score() > low.risk_score());
    }
}
