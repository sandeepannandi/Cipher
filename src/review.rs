use crate::finding::{
    stable_fingerprints, stable_rule_id, Confidence, Finding, FindingReport, FindingType,
    OwaspCategory, RemediationEffort, Severity,
};
use crate::groq::GroqClient;
use crate::indexer;
use crate::output;
use crate::scan;
use anyhow::Result;
use colored::*;
use ignore::WalkBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use serde::Serialize;
use std::path::Path;

/// A single vulnerability detection pattern
struct VulnPattern {
    name: &'static str,
    description: &'static str,
    severity: Severity,
    confidence: Confidence,
    owasp: Option<OwaspCategory>,
    /// Regex pattern to match in code
    pattern: Regex,
    /// Optional regex: when the matched line also matches this, the finding is
    /// suppressed (e.g. a cookie call that already sets the security flags).
    ///
    /// Exists because the `regex` crate has no look-around, so "match X unless
    /// Y" cannot be expressed in a single pattern. This is a whole-line check:
    /// a cookie literally named "Secure" is therefore treated as flagged.
    negative: Option<Regex>,
    /// File extensions to target (empty = all supported)
    target_extensions: &'static [&'static str],
    /// Remediation suggestion template
    remediation: &'static str,
}

/// Build all vulnerability detection patterns
fn build_vuln_patterns() -> Vec<VulnPattern> {
    let mut patterns = Vec::new();

    // Helper macro
    macro_rules! add_vuln {
        ($name:expr, $desc:expr, $sev:expr, $conf:expr, $owasp:expr, $re:expr, $exts:expr, $fix:expr) => {
            add_vuln!($name, $desc, $sev, $conf, $owasp, $re, None, $exts, $fix)
        };
        ($name:expr, $desc:expr, $sev:expr, $conf:expr, $owasp:expr, $re:expr, $neg:expr, $exts:expr, $fix:expr) => {
            if let (Ok(re), Ok(negative)) = (Regex::new($re), $neg.map(Regex::new).transpose()) {
                patterns.push(VulnPattern {
                    name: $name,
                    description: $desc,
                    severity: $sev,
                    confidence: $conf,
                    owasp: $owasp,
                    pattern: re,
                    negative,
                    target_extensions: $exts,
                    remediation: $fix,
                });
            }
        };
    }

    // -- Injection --

    add_vuln!(
        "SQL Injection — String Concatenation",
        "SQL queries built with string concatenation or interpolation are vulnerable to SQL injection. Use parameterized queries or an ORM instead.",
        Severity::Critical, Confidence::High, Some(OwaspCategory::A03Injection),
        // Matches: keyword("...${var}...") or keyword("...{var}...") or keyword("$var")
        // Requires actual interpolation syntax inside the string argument
        r#"(?i)(?:execute|query|raw|select|insert|update|delete)\s*\(\s*['\"][^'\"]*(?:\$\{|\{[A-Za-z_])"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Replace string concatenation with parameterized queries. Use prepared statements or an ORM's query builder."
    );

    add_vuln!(
        "SQL Injection — ORM Raw Queries",
        "Raw SQL queries bypass ORM protections. Review for potential injection vectors.",
        Severity::High, Confidence::Medium, Some(OwaspCategory::A03Injection),
        r#"(?i)(raw_sql|execute_sql|rawQuery|nativeQuery|createNativeQuery|raw\(|\.sql\()"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Use the ORM's query builder instead of raw SQL. If raw SQL is required, use parameterized queries."
    );

    add_vuln!(
        "Command Injection",
        "User input is passed to a shell command, which could allow command injection attacks.",
        Severity::Critical, Confidence::High, Some(OwaspCategory::A03Injection),
        // Require evidence of shell evaluation or string composition. Merely
        // constructing a process with a fixed executable and argument vector is safe.
        r#"(?i)(?:(?:exec|system|popen|shell_exec|subprocess\.\w+)\s*\([^)]*\$\{|Command::new\(\s*["'](?:sh|bash|zsh|cmd|powershell)(?:\.exe)?["']\s*\).*\.arg\(\s*["'](?:-c|/c)["']\s*\)|Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+)"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php"],
        "Avoid shell execution with user input. Use safer APIs that don't invoke a shell, and validate/sanitize all input."
    );

    add_vuln!(
        "Path Traversal",
        "File operations using user-controlled paths can allow directory traversal attacks.",
        Severity::High, Confidence::Medium, Some(OwaspCategory::A01BrokenAccessControl),
        r#"(?i)(?:read_to_string|read_file|File::open|fs::read|fs::write|file_get_contents)\s*\([^)]*\$\{|(?:readFile|writeFile)\s*\([^)]*\+"#,
        &["rs", "py", "js", "ts", "go", "rb", "php", "java"],
        "Validate and sanitize file paths. Use allowlists for permitted paths and reject '..' sequences."
    );

    add_vuln!(
        "Server-Side Template Injection (SSTI)",
        "User input is passed directly to a template engine, enabling SSTI attacks.",
        Severity::Critical, Confidence::Medium, Some(OwaspCategory::A03Injection),
        // Matches: .render(user_var) or jinja2.Template(user_var) etc.
        r#"(?i)(?:\.render\(|\.template\(|\.parse\(|jinja2\.Template|pug\.compile|ejs\.render|handlebars\.compile)\s*(?:[^)]*\$|\b(?:request|params|body|query|input|user_data)\b)"#,
        &["py", "js", "ts", "rb", "php"],
        "Never pass user input directly to template engines. Use context-aware escaping and sandboxed templates."
    );

    // -- Cryptography --

    add_vuln!(
        "Weak Hash Algorithm — MD5",
        "MD5 is cryptographically broken and unsuitable for security purposes. Use bcrypt, argon2, or SHA-256/512.",
        Severity::High, Confidence::High, Some(OwaspCategory::A02CryptographicFailures),
        r#"(?i)(?:\bmd5\s*\(|MessageDigest\.getInstance\(\s*"MD5"\s*\))"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Replace MD5 with a secure hash function like SHA-256, SHA-512, or bcrypt/argon2 for passwords."
    );

    add_vuln!(
        "Weak Hash Algorithm — SHA1",
        "SHA-1 is cryptographically weakened and should not be used for security contexts. Use SHA-256/512 or argon2.",
        Severity::Medium, Confidence::High, Some(OwaspCategory::A02CryptographicFailures),
        r#"(?i)\b(sha1)\s*\("#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Replace SHA-1 with SHA-256 or SHA-512. For password hashing, use bcrypt or argon2."
    );

    add_vuln!(
        "Weak Encryption — DES",
        "DES is a weak encryption algorithm that can be brute-forced. Use AES-256-GCM or ChaCha20-Poly1305.",
        Severity::High, Confidence::High, Some(OwaspCategory::A02CryptographicFailures),
        r#"(?i)\b(DES|des_ede3|TripleDES|3DES)\b"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Replace DES/TripleDES with AES-256-GCM (authenticated encryption)."
    );

    add_vuln!(
        "Weak Encryption — ECB Mode",
        "ECB mode encryption leaks patterns in the plaintext. Use authenticated encryption like AES-GCM.",
        Severity::High, Confidence::High, Some(OwaspCategory::A02CryptographicFailures),
        r#"(?i)(?:AES|DES|Blowfish)\s*/\s*ECB|ecb_encrypt"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Replace ECB mode with AES-GCM (authenticated encryption with IV/nonce)."
    );

    add_vuln!(
        "Hardcoded Cryptographic Key",
        "Hardcoded encryption keys can be extracted from source code. Use a key management system.",
        Severity::Critical,
        Confidence::Medium,
        Some(OwaspCategory::A02CryptographicFailures),
        r#"(?i)(?:encryption_key|secret_key|cipher_key|aes_key|crypto_key)\s*[=:]\s*['\"][A-Za-z0-9+/=]{16,}['\"]"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Move the key to environment variables or a secret manager. Never hardcode keys in source."
    );

    // -- Authentication & Authorization --

    add_vuln!(
        "Hardcoded Credentials",
        "Hardcoded usernames, passwords, or API keys are a security risk. Use environment variables.",
        Severity::Critical, Confidence::Medium, Some(OwaspCategory::A07AuthFailures),
        // Only match actual hardcoded string literals, not variable assignments from env/functions
        r#"(?i)(?:password|passwd|pwd|secret|api_key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9!@#$%^&*()_+-=]{4,}['\"]"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Remove hardcoded credentials and use environment variables or a secret manager."
    );

    add_vuln!(
        "JWT Secret Hardcoded",
        "JWT signing secrets in source code allow token forgery if exposed.",
        Severity::Critical,
        Confidence::High,
        Some(OwaspCategory::A07AuthFailures),
        r#"(?i)(?:jwt_secret|jwt_key|token_secret|signing_key)\s*[=:]\s*['\"][^'\"]{8,}['\"]"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Use environment variables for JWT secrets. Rotate immediately if exposed."
    );

    add_vuln!(
        "Insecure Cookie Configuration",
        "Cookies missing Secure, HttpOnly, or SameSite flags can be exploited via XSS or MITM.",
        Severity::High,
        Confidence::Medium,
        Some(OwaspCategory::A05SecurityMisconfiguration),
        r#"(?i)(?:cookie|Cookie|set_cookie)\s*\(\s*['\"]\w+['\"]\s*,\s*['\"]\w+['\"]"#,
        Some(r#"(?i)(?:HttpOnly|Secure|SameSite)"#),
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs"],
        "Set Secure, HttpOnly, and SameSite=Lax/Strict flags on all cookies."
    );

    // -- Security Misconfiguration --

    add_vuln!(
        "Debug Mode Enabled",
        "Debug or development mode in production can leak sensitive information.",
        Severity::High, Confidence::High, Some(OwaspCategory::A05SecurityMisconfiguration),
        r#"(?i)(?:debug\s*[=:]\s*true|DEBUG\s*=\s*True|debug=True|DEBUG=true|app\.debug)"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "yaml", "yml", "json", "toml"],
        "Disable debug/development mode in production. Set debug=False and configure proper logging."
    );

    add_vuln!(
        "CORS Misconfiguration",
        "Permissive CORS policy allows any origin to access your API. Restrict to trusted origins.",
        Severity::High,
        Confidence::High,
        Some(OwaspCategory::A05SecurityMisconfiguration),
        r#"(?i)(?:Access-Control-Allow-Origin\s*:\s*\*|allow_origins.*\['\''*|cors.*allow_all)"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs"],
        "Replace wildcard CORS origin with specific allowed origins. Never use '*' in production."
    );

    // -- General Security --

    add_vuln!(
        "Insecure Direct Object Reference (IDOR)",
        "User-controlled IDs in API endpoints without authorization checks can lead to unauthorized access.",
        Severity::High, Confidence::Low, Some(OwaspCategory::A01BrokenAccessControl),
        r#"(?i)(?:find_by_id|findById|get_by_id|getById|find_by_pk|get\(request.*id|params\[.id.\])"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Always verify that the authenticated user has permission to access the requested resource."
    );

    add_vuln!(
        "Insecure Deserialization",
        "Deserializing untrusted data can lead to remote code execution.",
        Severity::Critical, Confidence::Medium, Some(OwaspCategory::A08IntegrityFailures),
        // `yaml.load\b` already excludes `yaml.load_safe` (no word boundary
        // before `_`), so no look-around is needed here.
        r#"(?i)(?:pickle\.loads|marshal\.load|yaml\.load\b|from_string|unserialize|php://input)"#,
        &["py", "rb", "php"],
        "Avoid deserializing untrusted data. If necessary, use safe deserialization and validate the result against a schema."
    );

    add_vuln!(
        "Sensitive Data in Logging",
        "Logging potentially sensitive data (passwords, tokens, PII) can lead to data exposure.",
        Severity::Medium, Confidence::Low, Some(OwaspCategory::A09LoggingFailures),
        r#"(?i)(?:log\.(?:info|debug|warn|error)|console\.log)\s*\([^)]*(?:password|token|secret|credit|ssn)\b[^)]*\)"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs"],
        "Sanitize logs to remove sensitive data. Use structured logging with sensitive field redaction."
    );

    add_vuln!(
        "Mass Assignment / Autobinding",
        "Automatic binding of request parameters to model attributes can allow property tampering.",
        Severity::High,
        Confidence::Medium,
        Some(OwaspCategory::A01BrokenAccessControl),
        r#"(?i)(?:update_attributes|mass_assignment|fillable\s*=\s*\[\s*\*\s*\]|guard\s*=\s*\[\s*\]|@ModelAttribute)"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs"],
        "Use allowlists (fillable/guarded) to restrict which attributes can be mass-assigned."
    );

    add_vuln!(
        "Disabled SSL/TLS Verification",
        "Disabling SSL certificate verification defeats HTTPS protection and enables MITM attacks.",
        Severity::Critical,
        Confidence::High,
        Some(OwaspCategory::A02CryptographicFailures),
        r#"(?i)(?:verify\s*(?:=>|=)\s*false\b|tls_verify\s*[=:]\s*false|dangerous_accept|no_verify)"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs"],
        "Enable SSL/TLS certificate verification. Never disable it in production."
    );

    patterns
}

/// Detect the language for a file based on extension
fn file_extension(path: &Path) -> String {
    path.extension()
        .map(|e| e.to_str().unwrap_or("").to_lowercase())
        .unwrap_or_default()
}

/// Check if a file extension matches the target list
fn matches_extensions(ext: &str, targets: &[&str]) -> bool {
    targets.is_empty() || targets.contains(&ext)
}

/// Parse severity filter string from CLI
pub fn parse_severity_filter(s: &str) -> Option<Severity> {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Some(Severity::Critical),
        "HIGH" => Some(Severity::High),
        "MEDIUM" => Some(Severity::Medium),
        "LOW" => Some(Severity::Low),
        _ => None,
    }
}

/// Parse confidence filter string from CLI
pub fn parse_confidence_filter(s: &str) -> Option<Confidence> {
    match s.to_uppercase().as_str() {
        "HIGH" => Some(Confidence::High),
        "MEDIUM" => Some(Confidence::Medium),
        "LOW" => Some(Confidence::Low),
        _ => None,
    }
}

/// Check if a finding meets the minimum severity threshold
fn meets_severity_threshold(finding: &Finding, min_severity: Option<Severity>) -> bool {
    match min_severity {
        Some(threshold) => finding.severity.score() >= threshold.score(),
        None => true,
    }
}

/// Check if a finding meets the minimum confidence threshold
fn meets_confidence_threshold(finding: &Finding, min_confidence: Option<Confidence>) -> bool {
    match min_confidence {
        Some(threshold) => finding.confidence.score() >= threshold.score(),
        None => true,
    }
}

/// Filter findings by severity and confidence thresholds
pub(crate) fn filter_findings(
    findings: Vec<Finding>,
    min_severity: Option<Severity>,
    min_confidence: Option<Confidence>,
    max_findings: usize,
) -> Vec<Finding> {
    let mut filtered: Vec<Finding> = findings
        .into_iter()
        .filter(|f| meets_severity_threshold(f, min_severity))
        .filter(|f| meets_confidence_threshold(f, min_confidence))
        .collect();

    if filtered.len() > max_findings {
        filtered.truncate(max_findings);
    }

    filtered
}

/// Return true when a generic `secret` binding is used as JWT signing material.
///
/// The generic credential rule still owns unrelated `secret = "..."` bindings.
/// This narrow context check only promotes a binding when the same identifier is
/// interpolated on a non-comment line that also names a JWT or token.
fn is_contextual_jwt_secret(content: &str, assignment_line: &str) -> bool {
    let Ok(binding) = Regex::new(
        r#"(?i)\b(?:const|let|var|static|final)?\s*([a-z_][a-z0-9_]*)\s*[=:]\s*['\"][^'\"]{8,}['\"]"#,
    ) else {
        return false;
    };
    let Some(captures) = binding.captures(assignment_line) else {
        return false;
    };
    let Some(identifier) = captures.get(1).map(|capture| capture.as_str()) else {
        return false;
    };
    if identifier.to_ascii_lowercase().contains("jwt")
        || ["token_secret", "signing_key"].contains(&identifier.to_ascii_lowercase().as_str())
    {
        return true;
    }
    if !matches!(identifier.to_ascii_lowercase().as_str(), "secret" | "key") {
        return false;
    }

    let reference = Regex::new(&format!(r"(?i)\b{}\b", regex::escape(identifier))).ok();
    content.lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with("//")
            && !trimmed.starts_with('#')
            && (line.to_ascii_lowercase().contains("jwt")
                || line.to_ascii_lowercase().contains("token"))
            && reference.as_ref().is_some_and(|re| re.is_match(line))
    })
}

/// Scan a single file for vulnerability patterns
fn scan_file_for_vulns(path: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let ext = file_extension(path);

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return findings,
    };
    if crate::workflow::is_github_workflow(path, &content) {
        findings.extend(crate::workflow::scan_workflow(path, &content));
    }
    let js_path_traversal_sinks = js_path_traversal_sink_lines(&content, &ext);
    let python_path_traversal_sinks = python_path_traversal_sink_lines(&content, &ext);
    let java_path_traversal_sinks = java_path_traversal_sink_lines(&content, &ext);
    let go_path_traversal_sinks = go_path_traversal_sink_lines(&content, &ext);
    let python_md5_alias_calls = python_md5_alias_call_lines(&content, &ext);
    let sql_injection_sinks = sql_injection_sink_lines(&content, &ext);

    for (line_num, line) in content.lines().enumerate() {
        let line_number = line_num + 1;
        let trimmed = line.trim();

        // Skip comments
        if trimmed.is_empty()
            || trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
        {
            continue;
        }

        let contextual_jwt_secret = is_contextual_jwt_secret(&content, line);

        for pattern in patterns {
            if !matches_extensions(&ext, pattern.target_extensions) {
                continue;
            }

            let pattern_matches = pattern.pattern.is_match(line)
                || (pattern.name == "JWT Secret Hardcoded" && contextual_jwt_secret)
                || (pattern.name == "Path Traversal"
                    && (js_path_traversal_sinks.contains(&line_number)
                        || python_path_traversal_sinks.contains(&line_number)
                        || java_path_traversal_sinks.contains(&line_number)
                        || go_path_traversal_sinks.contains(&line_number)))
                || (pattern.name == "Weak Hash Algorithm — MD5"
                    && python_md5_alias_calls.contains(&line_number))
                || (pattern.name == "SQL Injection — String Concatenation"
                    && sql_injection_sinks.contains(&line_number));
            if !pattern_matches {
                continue;
            }

            // A credential that is specifically JWT signing material should be
            // reported once under the more precise rule, not again generically.
            if pattern.name == "Hardcoded Credentials" && contextual_jwt_secret {
                continue;
            }

            // Suppress matches that also hit the negative filter, e.g. a
            // cookie call that already sets HttpOnly/Secure/SameSite.
            if pattern
                .negative
                .as_ref()
                .is_some_and(|neg| neg.is_match(line))
            {
                continue;
            }

            let exploitability = match pattern.severity {
                Severity::Critical => 0.8,
                Severity::High => 0.6,
                Severity::Medium => 0.4,
                Severity::Low => 0.2,
                Severity::Info => 0.1,
            };

            let effort = match pattern.severity {
                Severity::Critical => RemediationEffort::Hours,
                Severity::High => RemediationEffort::Hours,
                Severity::Medium => RemediationEffort::Minutes,
                Severity::Low => RemediationEffort::Minutes,
                Severity::Info => RemediationEffort::Minutes,
            };

            let mut finding = Finding::new(
                FindingType::Vulnerability,
                pattern.name,
                pattern.description,
                pattern.severity,
                pattern.confidence,
                "security-review",
            )
            .at(path.to_string_lossy().to_string(), line_number)
            .with_code(line.to_string())
            .with_remediation(pattern.remediation)
            .with_exploitability(exploitability)
            .with_effort(effort);

            if let Some(owasp) = pattern.owasp {
                finding = finding.with_owasp(owasp);
            }

            // Attach a stable CWE identifier derived from the pattern title
            if let Some(cwe) =
                crate::finding::cwe_for_title(pattern.name, FindingType::Vulnerability)
            {
                finding = finding.with_cwe(cwe);
            }

            findings.push(finding);
        }
    }

    findings
}

/// Collect review findings without displaying them (for report generation)
pub(crate) async fn collect_review_findings(
    project_path: &Path,
    use_ai: bool,
    model: Option<&str>,
) -> Result<FindingReport> {
    let canonical_path = std::fs::canonicalize(project_path)?;

    let patterns = build_vuln_patterns();
    let mut report = FindingReport::new("security-review", canonical_path.to_string_lossy());

    // Walk source files with exclusions, depth limit, and file cap
    let walker = WalkBuilder::new(&canonical_path)
        .git_ignore(true)
        .git_global(true)
        .hidden(false)
        .max_depth(Some(scan::MAX_WALK_DEPTH))
        .build();

    let mut file_count = 0;
    for result in walker {
        if file_count >= scan::MAX_SCAN_FILES {
            eprintln!(
                "  {} Reached scan limit of {} files. Some files may not be checked.",
                "[!]".yellow(),
                scan::MAX_SCAN_FILES
            );
            break;
        }

        if let Ok(entry) = result {
            let path = entry.path();
            if path.is_file() && !scan::should_exclude(path) && !scan::is_binary(path) {
                let ext = file_extension(path);
                if !ext.is_empty() && is_supported_extension(&ext) {
                    let findings = scan_file_for_vulns(path, &patterns);
                    report.extend(findings);
                    file_count += 1;
                }
            }
        }
    }

    // AI-powered deep analysis
    if use_ai {
        if let Ok(ai_findings) = run_ai_review(&canonical_path, model).await {
            report.extend(ai_findings);
        }
    }

    report.sort_by_risk();
    Ok(report)
}

/// Run the `cipher-ai review` command
#[allow(clippy::too_many_arguments)]
pub async fn run_review(
    project_path: &Path,
    use_ai: bool,
    verify: bool,
    model: Option<&str>,
    max_findings: Option<usize>,
    min_severity: Option<Severity>,
    min_confidence: Option<Confidence>,
    format: &str,
    output: Option<&str>,
    policy_path: Option<&Path>,
    write_policy_baseline: Option<&Path>,
    fail_on_policy: bool,
) -> Result<FindingReport> {
    let canonical_path = std::fs::canonicalize(project_path)?;

    output::print_header(
        "Security Review",
        Some(&format!("Scanning {}", canonical_path.display())),
    );

    // Phase 1: Pattern-based scanning
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} Scanning for vulnerability patterns...")
            .unwrap(),
    );
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));

    let mut report = collect_review_findings(&canonical_path, false, None).await?;

    let total_raw = report.len();
    spinner.finish_with_message(format!(
        "{} files scanned — {} raw issues found",
        "[OK]".green(),
        total_raw
    ));

    // Phase 1b: AI verification — confirm real issues, filter false positives
    if verify {
        if report.is_empty() {
            println!("  {} No findings to verify.", "(i)".blue());
        } else {
            println!(
                "  {} AI-verifying {} findings... (filtering false positives)\n",
                "[AI]".bright_green(),
                report.len().to_string().bold()
            );
            let spinner = ProgressBar::new_spinner();
            spinner.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} Asking AI to confirm findings...")
                    .unwrap(),
            );
            spinner.enable_steady_tick(std::time::Duration::from_millis(100));

            let verified = crate::verify::verify_findings(report.findings.clone(), model).await;
            let dropped = report.len().saturating_sub(verified.len());
            spinner.finish_and_clear();

            if dropped > 0 {
                eprintln!(
                    "  {} AI verification filtered {} potential false positives\n",
                    "[!]".yellow(),
                    dropped.to_string().yellow().bold()
                );
            }
            report.findings = verified;
            report.sort_by_risk();
        }
    }

    // Phase 2: AI-powered deep analysis (only if requested)
    if use_ai {
        println!(
            "  {} Running AI-powered deep analysis... (this may take a moment)",
            "[AI]".bright_green()
        );
        match run_ai_review(&canonical_path, model).await {
            Ok(ai_findings) => {
                let existing_keys: std::collections::HashSet<(String, Option<String>)> = report
                    .findings
                    .iter()
                    .map(|f| (f.title.clone(), f.file_path.clone()))
                    .collect();
                for finding in ai_findings {
                    let key = (finding.title.clone(), finding.file_path.clone());
                    if !existing_keys.contains(&key) {
                        report.add(finding);
                    }
                }
                report.sort_by_risk();
            }
            Err(e) => {
                eprintln!(
                    "\n  {} AI analysis failed: {} (continuing with pattern-based results)",
                    "[!]".yellow(),
                    e
                );
            }
        }
    }

    if let Some(path) = write_policy_baseline {
        let baseline = crate::policy::Policy::baseline_from(&report.findings);
        baseline.write(path)?;
        eprintln!(
            "  [POLICY] Accepted {} stable fingerprints in {}",
            baseline.baseline.fingerprints.len(),
            path.display()
        );
        return Ok(report);
    }

    let default_policy = canonical_path.join(".cipher-ai-policy.yml");
    let effective_policy = policy_path
        .map(std::path::PathBuf::from)
        .or_else(|| default_policy.is_file().then_some(default_policy));
    let policy_evaluation = if let Some(path) = effective_policy.as_deref() {
        let policy = crate::policy::Policy::load(path)?;
        let evaluation = policy.evaluate(&report.findings)?;
        eprintln!(
            "  [POLICY] {} new, {} baseline, {} suppressed, {} expired, {} below threshold",
            evaluation.new,
            evaluation.baseline,
            evaluation.suppressed,
            evaluation.expired,
            evaluation.below_threshold
        );
        for finding in &evaluation.findings {
            eprintln!(
                "    {:?} {}{}{}",
                finding.state,
                finding.fingerprint,
                finding
                    .reason
                    .as_ref()
                    .map(|r| format!(" — {r}"))
                    .unwrap_or_default(),
                finding
                    .expires
                    .map(|d| format!(" (expires {d})"))
                    .unwrap_or_default()
            );
        }
        Some(evaluation)
    } else {
        if fail_on_policy {
            anyhow::bail!("--fail-on-policy requires --policy or .cipher-ai-policy.yml");
        }
        None
    };

    // Apply display filters. Policy is evaluated against the complete finding set
    // before these presentation-only filters, so limits cannot weaken the gate.
    let max_show = max_findings.unwrap_or(30);
    let filtered = filter_findings(
        report.findings.clone(),
        min_severity,
        min_confidence,
        max_show,
    );

    // Handle format/output
    if format == "sarif" || format == "json" {
        let output_str = if format == "sarif" {
            generate_sarif(&report, &canonical_path)
        } else {
            generate_review_json(&report)
        };

        if let Some(out_path) = output {
            std::fs::write(out_path, &output_str)?;
            println!(
                "  {} {} output written to {}",
                "[FILE]".cyan(),
                format.to_uppercase().yellow().bold(),
                out_path.yellow()
            );
        } else {
            println!("{output_str}");
        }
        if fail_on_policy && policy_evaluation.as_ref().is_some_and(|p| p.gate_failed) {
            anyhow::bail!(
                "policy gate failed: new or expired findings meet the configured thresholds"
            );
        }
        return Ok(report);
    }

    // Display results
    println!();
    println!(
        "{} {}",
        "[LIST]".bright_blue(),
        "Security Review Results".bold()
    );
    println!("  {}", "-".repeat(50).dimmed());

    let filter_info = match (min_severity, min_confidence) {
        (Some(s), Some(c)) => format!(" (filtered: >={s} severity, >={c} confidence)"),
        (Some(s), None) => format!(" (filtered: >={s} severity)"),
        (None, Some(c)) => format!(" (filtered: >={c} confidence)"),
        (None, None) => String::new(),
    };

    let showing_info = if filtered.len() < total_raw {
        format!(
            "  {} Pattern-based scanner found {} potential issues, showing top {}{}",
            "[*]".cyan(),
            total_raw.to_string().bold(),
            filtered.len(),
            filter_info
        )
    } else {
        format!(
            "  {} Pattern-based scanner found {} potential issues{}",
            "[*]".cyan(),
            total_raw.to_string().bold(),
            filter_info
        )
    };
    println!("{showing_info}");

    // Build a mini report for display
    let mut display_report =
        FindingReport::new("security-review", canonical_path.to_string_lossy());
    for f in filtered {
        display_report.add(f);
    }

    display_report.print_summary();

    if display_report.is_empty() {
        println!();
        println!(
            "{} No vulnerabilities detected matching your filters.",
            "[OK]".green().bold()
        );
        println!(
            "  Note: Pattern-based scanners can miss business logic and context-dependent issues."
        );
        println!(
            "  Run {} for deeper analysis, or run without --min-severity to see all findings.",
            "cipher-ai review --ai".yellow()
        );
        return Ok(report);
    }

    // Print detailed findings (only top N)
    display_report.print_detailed();

    // Show count of filtered-out findings
    if total_raw > display_report.len() {
        let hidden = total_raw - display_report.len();
        println!();
        println!(
            "  {} {} additional findings not shown (use a lower --min-severity or --min-confidence to see more, or omit --max-findings)",
            "[…]".dimmed(),
            hidden.to_string().dimmed()
        );
    }

    // Recommendations
    println!();
    println!("{} {}", "[TARGET]".bold(), "Top Recommendations".bold());
    println!("  {}", "-".repeat(40).dimmed());

    let critical_high: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical || f.severity == Severity::High)
        .collect();

    if !critical_high.is_empty() {
        println!(
            "  [RED] Fix {} critical/high severity issues first:",
            critical_high.len()
        );
        for f in critical_high.iter().take(5) {
            let fp = f.file_path.as_deref().unwrap_or("<unknown>");
            println!(
                "      • {} in {} {}",
                f.title.bold(),
                fp.yellow(),
                f.line_number.map(|l| format!(":{l}")).unwrap_or_default()
            );
        }
        if critical_high.len() > 5 {
            println!(
                "      • ... and {} more",
                (critical_high.len() - 5).to_string().dimmed()
            );
        }
    }

    println!();
    println!(
        "  [IDEA] Run {} for interactive security Q&A about specific findings.",
        "cipher-ai ask \"Tell me more about [finding]\"".yellow()
    );
    println!(
        "  [IDEA] Use {} to see all raw findings without filters.",
        "cipher-ai review --max-findings 999 --min-severity low".yellow()
    );

    if fail_on_policy && policy_evaluation.as_ref().is_some_and(|p| p.gate_failed) {
        anyhow::bail!("policy gate failed: new or expired findings meet the configured thresholds");
    }
    Ok(report)
}

/// Check if a file extension is supported for scanning
fn is_supported_extension(ext: &str) -> bool {
    matches!(
        ext,
        "rs" | "js"
            | "jsx"
            | "ts"
            | "tsx"
            | "py"
            | "go"
            | "rb"
            | "java"
            | "kt"
            | "swift"
            | "c"
            | "cpp"
            | "h"
            | "hpp"
            | "cs"
            | "php"
            | "sh"
            | "bash"
            | "yaml"
            | "yml"
            | "json"
            | "toml"
            | "sql"
            | "vue"
            | "svelte"
            | "dart"
            | "scala"
            | "lua"
    )
}

/// Run AI-powered security review using the indexed codebase
async fn run_ai_review(project_path: &Path, model: Option<&str>) -> Result<Vec<Finding>> {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} Loading index for AI analysis...")
            .unwrap(),
    );
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));

    let index = match indexer::load_index(project_path)? {
        Some(idx) => idx,
        None => {
            spinner.finish_and_clear();
            return Ok(Vec::new());
        }
    };

    spinner.set_message("Connecting to AI...");
    let client = match GroqClient::from_env() {
        Ok(c) => c,
        Err(_) => {
            spinner.finish_and_clear();
            return Ok(Vec::new());
        }
    };

    // Select the most important code chunks for review
    // Focus on security-critical areas: auth, API endpoints, data handling, crypto
    let review_queries = [
        "authentication auth login password",
        "authorization permission role access",
        "api endpoint route handler request",
        "database sql query execute",
        "encryption crypto hash cipher",
        "input validation sanitize filter",
    ];

    let mut reviewed_chunks = std::collections::HashSet::new();
    let mut context = String::new();

    for query in &review_queries {
        let results = indexer::search_index(&index, query, 5);
        for chunk in results {
            if reviewed_chunks.insert(chunk.id.clone()) {
                let chunk_text = format!(
                    "--- {}:{}:{} ---\n{}\n\n",
                    chunk.relative_path, chunk.start_line, chunk.end_line, chunk.content
                );
                if context.len() + chunk_text.len() > 20_000 {
                    break;
                }
                context.push_str(&chunk_text);
            }
        }
    }

    if context.is_empty() {
        spinner.finish_and_clear();
        return Ok(Vec::new());
    }

    spinner.finish_and_clear();

    let system_prompt = r#"You are Cipher, an expert application security engineer.

Your task is to analyze the provided code and identify security vulnerabilities.

For each vulnerability you find, respond in this JSON format:
{
  "findings": [
    {
      "title": "Short title of the vulnerability",
      "description": "Detailed explanation of the issue and its impact",
      "type": "vulnerability|misconfiguration|authentication|authorization|injection|cryptography|business-logic",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "confidence": "HIGH|MEDIUM|LOW",
      "file_path": "relative/path/to/file.rs",
      "line_number": 42,
      "remediation": "How to fix this issue",
      "owasp_category": "A01:2021" (optional, e.g., A01:2021-A10:2021)
    }
  ]
}

Guidelines:
- Only report real issues — if unsure, set confidence to LOW
- Be specific about file paths and line numbers from the provided code
- Consider: OWASP Top 10, business logic flaws, auth bypasses, injection, crypto weaknesses
- If no vulnerabilities found, return {"findings": []}
- Respond with ONLY the JSON, no other text"#;

    let user_prompt = format!(
        r#"Analyze the following code for security vulnerabilities:

{context}

Return your findings as a JSON object with a "findings" array.
Each finding must have: title, description, type, severity, confidence, file_path, line_number, remediation.
If no vulnerabilities found, return {{"findings": []}}."#
    );

    let response = client
        .chat(system_prompt, &user_prompt, model)
        .await
        .map_err(|e| anyhow::anyhow!("AI analysis failed: {e}"))?;

    match parse_ai_findings(&response, project_path) {
        Ok(findings) => {
            if findings.is_empty() {
                eprintln!(
                    "  {} AI analysis completed but returned no parseable findings.\n    The model may not have identified issues, or the response format was unexpected.",
                    "(i)".blue()
                );
            }
            Ok(findings)
        }
        Err(e) => {
            eprintln!(
                "  {} Could not parse AI response: {}. Continuing with pattern-based results.",
                "[!]".yellow(),
                e
            );
            Ok(Vec::new())
        }
    }
}

/// Parse AI JSON response into Finding objects
fn parse_ai_findings(response: &str, project_path: &Path) -> Result<Vec<Finding>> {
    // Try to extract JSON from the response (handles markdown code blocks)
    let json_str = if let Some(start) = response.find("{\"findings\"") {
        let end = response[start..]
            .rfind('}')
            .map(|i| start + i + 1)
            .unwrap_or(response.len());
        &response[start..end]
    } else if let Some(start) = response.find('[') {
        let end = response[start..]
            .rfind(']')
            .map(|i| start + i + 1)
            .unwrap_or(response.len());
        &response[start..end]
    } else {
        return Ok(Vec::new());
    };

    // Parse JSON into AiFinding structs
    #[derive(serde::Deserialize)]
    struct AiFinding {
        title: Option<String>,
        description: Option<String>,
        #[serde(rename = "type")]
        finding_type: Option<String>,
        severity: Option<String>,
        confidence: Option<String>,
        file_path: Option<String>,
        line_number: Option<usize>,
        remediation: Option<String>,
        owasp_category: Option<String>,
        #[serde(rename = "cwe")]
        cwe_id: Option<String>,
        #[serde(rename = "cwe_id")]
        cwe_id_alt: Option<String>,
    }

    #[derive(serde::Deserialize)]
    struct AiResponse {
        findings: Vec<AiFinding>,
    }

    let ai_response: AiResponse = match serde_json::from_str(json_str) {
        Ok(r) => r,
        Err(_) => {
            // Try wrapping in an object
            #[derive(serde::Deserialize)]
            struct FindingsOnly {
                findings: Vec<AiFinding>,
            }
            match serde_json::from_str::<FindingsOnly>(&format!("{{\"findings\":{json_str}}}")) {
                Ok(r) => AiResponse {
                    findings: r.findings,
                },
                Err(e) => anyhow::bail!("JSON parse error: {e}"),
            }
        }
    };

    let mut findings = Vec::new();

    for af in ai_response.findings {
        let title = af
            .title
            .unwrap_or_else(|| "Unknown vulnerability".to_string());
        let description = af.description.unwrap_or_default();
        let severity = parse_severity(&af.severity.unwrap_or_default());
        let confidence = parse_confidence(&af.confidence.unwrap_or_default());
        let finding_type = parse_finding_type(&af.finding_type.unwrap_or_default());
        let owasp = parse_owasp(af.owasp_category.as_deref());
        let cwe = af
            .cwe_id
            .as_deref()
            .or(af.cwe_id_alt.as_deref())
            .and_then(parse_cwe);

        let mut finding = Finding::new(
            finding_type,
            &title,
            &description,
            severity,
            confidence,
            "ai-review",
        )
        .with_exploitability(match severity {
            Severity::Critical => 0.8,
            Severity::High => 0.6,
            Severity::Medium => 0.4,
            _ => 0.2,
        })
        .with_effort(match severity {
            Severity::Critical | Severity::High => RemediationEffort::Hours,
            _ => RemediationEffort::Minutes,
        });

        if let Some(fp) = af.file_path {
            let full_path = project_path.join(&fp);
            let fp_str = full_path.to_string_lossy().to_string();
            let ln = af.line_number.unwrap_or(0);
            finding = finding.at(fp_str, ln);
        }

        if let Some(rem) = af.remediation {
            if !rem.is_empty() {
                finding = finding.with_remediation(rem);
            }
        }

        if let Some(owasp) = owasp {
            finding = finding.with_owasp(owasp);
        }
        if let Some(cwe) = cwe {
            finding = finding.with_cwe(cwe);
        } else if let Some(cwe) = crate::finding::cwe_for_title(&title, finding_type) {
            finding = finding.with_cwe(cwe);
        }

        findings.push(finding);
    }

    Ok(findings)
}

// ── SARIF Output Generator ──────────────────────────────────────────

/// SARIF-compatible severity level mapping
fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "error",
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Info => "note",
    }
}

/// SARIF result-level entry
#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    #[serde(
        rename = "partialFingerprints",
        skip_serializing_if = "Option::is_none"
    )]
    partial_fingerprints: Option<SarifFingerprint>,
}

#[derive(Serialize)]
struct SarifFingerprint {
    #[serde(rename = "primaryLocationLineHash")]
    primary_location_line_hash: String,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    region: Option<SarifRegion>,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
    #[serde(rename = "uriBaseId", skip_serializing_if = "Option::is_none")]
    uri_base_id: Option<String>,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: usize,
    snippet: Option<SarifSnippet>,
}

#[derive(Serialize)]
struct SarifSnippet {
    text: String,
}

/// Generate a SARIF 2.1.0 JSON string from a FindingReport
pub(crate) fn generate_sarif(report: &FindingReport, project_path: &Path) -> String {
    // Keep the rule metadata in sync with the result rule IDs.
    let mut rule_ids: Vec<String> = Vec::new();
    let mut rules: Vec<SarifRule> = Vec::new();
    for f in &report.findings {
        let id = stable_rule_id(f);
        if rule_ids.iter().any(|existing| existing == &id) {
            continue;
        }
        rule_ids.push(id.clone());
        let name = match id.as_str() {
            "cipher/sql-injection" => "SQL Injection",
            "cipher/command-injection" => "Command Injection",
            "cipher/path-traversal" => "Path Traversal",
            "cipher/ssrf" => "Server-Side Request Forgery",
            "cipher/idor" => "Insecure Direct Object Reference",
            "cipher/secrets" => "Secret Exposure",
            "cipher/auth" => "Authentication & Session Hardening",
            "cipher/authz" => "Authorization / Access Control",
            "cipher/crypto" => "Cryptographic Weakness",
            "cipher/injection" => "Injection",
            "cipher/misconfig" => "Security Misconfiguration",
            "cipher/dependency" => "Dependency Vulnerability",
            "cipher/business-logic" => "Business Logic",
            _ => "Security Finding",
        };
        rules.push(SarifRule {
            id: id.clone(),
            short_description: SarifMessage {
                text: name.to_string(),
            },
            properties: None,
        });
    }

    let fingerprints = stable_fingerprints(&report.findings);
    let results: Vec<SarifResult> = report
        .findings
        .iter()
        .zip(fingerprints)
        .map(|(f, fingerprint)| {
            let file_uri = f
                .file_path
                .as_ref()
                .and_then(|fp| std::path::Path::new(fp).canonicalize().ok())
                .map(|p| format!("file:///{}", p.to_string_lossy().replace("\\", "/")))
                .unwrap_or_else(|| {
                    format!(
                        "file:///{}",
                        project_path.to_string_lossy().replace("\\", "/")
                    )
                });

            let snippet = f
                .code_snippet
                .as_ref()
                .map(|s| SarifSnippet { text: s.clone() });

            let region = f.line_number.map(|ln| SarifRegion {
                start_line: ln.max(1),
                snippet,
            });

            let rule_id = stable_rule_id(f);
            SarifResult {
                rule_id: rule_id.clone(),
                level: sarif_level(f.severity).to_string(),
                message: SarifMessage {
                    text: format!(
                        "{}\n\n**Remediation:** {}",
                        f.description,
                        f.remediation.as_deref().unwrap_or("Not specified")
                    ),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: file_uri,
                            uri_base_id: None,
                        },
                        region,
                    },
                }],
                partial_fingerprints: Some(SarifFingerprint {
                    primary_location_line_hash: fingerprint,
                }),
            }
        })
        .collect();

    #[derive(Serialize)]
    struct SarifRoot {
        #[serde(rename = "$schema")]
        schema: String,
        version: String,
        runs: Vec<SarifRun>,
    }

    #[derive(Serialize)]
    struct SarifRun {
        tool: SarifTool,
        results: Vec<SarifResult>,
        #[serde(skip_serializing_if = "Option::is_none")]
        artifacts: Option<Vec<SarifArtifact>>,
        #[serde(rename = "columnKind")]
        column_kind: String,
        properties: SarifProperties,
    }

    #[derive(Serialize)]
    struct SarifTool {
        driver: SarifDriver,
    }

    #[derive(Serialize)]
    struct SarifDriver {
        name: String,
        #[serde(rename = "informationUri")]
        information_uri: String,
        version: String,
        rules: Vec<SarifRule>,
    }

    #[derive(Serialize)]
    struct SarifRule {
        id: String,
        #[serde(rename = "shortDescription")]
        short_description: SarifMessage,
        #[serde(skip_serializing_if = "Option::is_none")]
        properties: Option<SarifRuleProps>,
    }

    #[derive(Serialize)]
    struct SarifRuleProps {
        tags: Vec<String>,
    }

    #[derive(Serialize)]
    struct SarifArtifact {
        location: SarifArtifactLocation,
    }

    #[derive(Serialize)]
    struct SarifProperties {
        #[serde(rename = "totalFindings")]
        total_findings: usize,
    }

    let root = SarifRoot {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "CipherAI".to_string(),
                    information_uri: "https://github.com/sandeepannandi/Cipher".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    rules,
                },
            },
            results,
            artifacts: None,
            column_kind: "utf16CodeUnits".to_string(),
            properties: SarifProperties {
                total_findings: report.len(),
            },
        }],
    };

    serde_json::to_string_pretty(&root).unwrap_or_else(|_| "{}".to_string())
}

// ── JSON Output Generator ────────────────────────────────────────────

/// Generate a plain JSON string from a FindingReport (machine-readable)
pub(crate) fn generate_review_json(report: &FindingReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
}

/// Parse severity string
fn parse_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Parse confidence string
fn parse_confidence(s: &str) -> Confidence {
    match s.to_uppercase().as_str() {
        "HIGH" => Confidence::High,
        "MEDIUM" => Confidence::Medium,
        _ => Confidence::Low,
    }
}

/// Parse finding type string
fn parse_finding_type(s: &str) -> FindingType {
    match s.to_lowercase().as_str() {
        "secret" => FindingType::Secret,
        "misconfiguration" => FindingType::Misconfiguration,
        "dependency" => FindingType::Dependency,
        "business-logic" | "business_logic" | "businesslogic" => FindingType::BusinessLogic,
        "authentication" => FindingType::Authentication,
        "authorization" => FindingType::Authorization,
        "injection" => FindingType::Injection,
        "cryptography" => FindingType::Cryptography,
        _ => FindingType::Vulnerability,
    }
}

/// Normalize a CWE identifier from model output.
/// Accepts "89", "CWE-89", "cwe-89", "CWE-89: Description".
fn parse_cwe(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let upper = s.to_uppercase();
    if upper.starts_with("CWE-") {
        let num: String = upper
            .chars()
            .skip(4)
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if num.is_empty() {
            return None;
        }
        Some(format!("CWE-{num}"))
    } else {
        let num: String = upper.chars().take_while(|c| c.is_ascii_digit()).collect();
        if num.is_empty() {
            return None;
        }
        Some(format!("CWE-{num}"))
    }
}

/// Parse OWASP category string
fn parse_owasp(s: Option<&str>) -> Option<OwaspCategory> {
    match s {
        Some(s) => {
            let s = s.trim().to_uppercase();
            if s.contains("A01")
                || s.contains("BROKEN ACCESS CONTROL")
                || s.contains("ACCESS CONTROL")
            {
                Some(OwaspCategory::A01BrokenAccessControl)
            } else if s.contains("A02")
                || s.contains("CRYPTOGRAPHIC FAILURES")
                || s.contains("CRYPTOGRAPHIC")
            {
                Some(OwaspCategory::A02CryptographicFailures)
            } else if s.contains("A03") || s.contains("INJECTION") {
                Some(OwaspCategory::A03Injection)
            } else if s.contains("A04") || s.contains("INSECURE DESIGN") {
                Some(OwaspCategory::A04InsecureDesign)
            } else if s.contains("A05")
                || s.contains("SECURITY MISCONFIGURATION")
                || s.contains("MISCONFIGURATION")
            {
                Some(OwaspCategory::A05SecurityMisconfiguration)
            } else if s.contains("A06")
                || s.contains("VULNERABLE COMPONENTS")
                || s.contains("OUTDATED COMPONENTS")
            {
                Some(OwaspCategory::A06VulnerableComponents)
            } else if s.contains("A07")
                || s.contains("AUTHENTICATION")
                || s.contains("AUTH FAILURES")
            {
                Some(OwaspCategory::A07AuthFailures)
            } else if s.contains("A08")
                || s.contains("INTEGRITY FAILURES")
                || s.contains("DATA INTEGRITY")
            {
                Some(OwaspCategory::A08IntegrityFailures)
            } else if s.contains("A09") || s.contains("LOGGING FAILURES") || s.contains("LOGGING") {
                Some(OwaspCategory::A09LoggingFailures)
            } else if s.contains("A10") || s.contains("SSRF") {
                Some(OwaspCategory::A10SSRF)
            } else {
                None
            }
        }
        None => None,
    }
}

#[cfg(test)]
mod scanner_regression_tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scan(source: &str, extension: &str) -> Vec<Finding> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("cipher-review-{nonce}.{extension}"));
        fs::write(&path, source).expect("write fixture");
        let findings = scan_file_for_vulns(&path, &build_vuln_patterns());
        fs::remove_file(path).expect("remove fixture");
        findings
    }

    fn titles(findings: &[Finding]) -> Vec<&str> {
        findings
            .iter()
            .map(|finding| finding.title.as_str())
            .collect()
    }

    #[test]
    fn github_workflow_yaml_gets_workflow_checks() {
        let findings = scan(
            "on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n",
            "yml",
        );
        assert!(titles(&findings).contains(&crate::workflow::SCRIPT_INJECTION_TITLE));
        let plain = scan(
            "name: app\nrun: echo ${{ github.event.issue.title }}\n",
            "yml",
        );
        assert!(!titles(&plain).contains(&crate::workflow::SCRIPT_INJECTION_TITLE));
    }

    #[test]
    fn jwt_specific_binding_is_not_reported_as_generic_secret() {
        let findings = scan(r#"const jwt_secret = "replace-this-secret";"#, "js");
        assert_eq!(titles(&findings), vec!["JWT Secret Hardcoded"]);
    }

    #[test]
    fn contextual_jwt_secret_binding_is_promoted_to_specific_rule() {
        let findings = scan(
            "const secret = \"dev-secret\";\nconst token = `jwt.${secret}.payload`;",
            "js",
        );
        assert_eq!(titles(&findings), vec!["JWT Secret Hardcoded"]);
    }

    #[test]
    fn unrelated_generic_secret_keeps_generic_detection() {
        let findings = scan(
            r#"const secret = "dev-secret";
connect(secret);"#,
            "js",
        );
        assert_eq!(titles(&findings), vec!["Hardcoded Credentials"]);
    }

    #[test]
    fn environment_jwt_secret_is_not_reported() {
        let findings = scan(
            "const secret = process.env.JWT_SECRET;\nconst token = `jwt.${secret}.payload`;",
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn rust_shell_c_with_untrusted_argument_is_reported() {
        let findings = scan(
            r#"Command::new("sh").arg("-c").arg(input).status()?;"#,
            "rs",
        );
        assert_eq!(titles(&findings), vec!["Command Injection"]);
    }

    #[test]
    fn rust_fixed_executable_with_argument_vector_is_clean() {
        let findings = scan(
            r#"let mut cmd = Command::new("/usr/bin/printf");
cmd.arg(input);"#,
            "rs",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_runtime_exec_with_composed_shell_command_is_reported() {
        let findings = scan(
            r#"Runtime.getRuntime().exec("sh -c '" + input + "'");"#,
            "java",
        );
        assert_eq!(titles(&findings), vec!["Command Injection"]);
    }

    #[test]
    fn java_process_builder_argument_vector_is_clean() {
        let findings = scan(
            r#"new ProcessBuilder("/usr/bin/printf", input).start();"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_message_digest_md5_is_reported() {
        let findings = scan(
            r#"MessageDigest md = MessageDigest.getInstance("MD5");"#,
            "java",
        );
        assert_eq!(titles(&findings), vec!["Weak Hash Algorithm — MD5"]);
    }

    #[test]
    fn java_message_digest_sha256_is_clean() {
        let findings = scan(
            r#"MessageDigest md = MessageDigest.getInstance("SHA-256");"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_request_path_reaching_open_is_reported() {
        let findings = scan(
            r#"from flask import request
import os
requested = request.args.get("file")
target = os.path.join("uploads", requested)
with open(target, "rb") as handle:
    return handle.read()"#,
            "py",
        );
        assert_eq!(titles(&findings), vec!["Path Traversal"]);
    }

    #[test]
    fn python_basename_sanitized_path_is_clean() {
        let findings = scan(
            r#"from flask import request
import os
requested = os.path.basename(request.args.get("file"))
target = os.path.join("uploads", requested)
with open(target, "rb") as handle:
    return handle.read()"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_request_path_reaching_file_stream_is_reported() {
        let findings = scan(
            r#"String requested = request.getParameter("file");
File target = new File("uploads", requested);
FileInputStream in = new FileInputStream(target);"#,
            "java",
        );
        assert_eq!(titles(&findings), vec!["Path Traversal"]);
    }

    #[test]
    fn java_file_name_sanitized_path_is_clean() {
        let findings = scan(
            r#"String requested = Paths.get(request.getParameter("file")).getFileName().toString();
File target = new File("uploads", requested);
FileInputStream in = new FileInputStream(target);"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_request_path_reaching_read_file_is_reported() {
        let findings = scan(
            r#"requested := r.URL.Query().Get("file")
target := filepath.Join("uploads", requested)
data, err := os.ReadFile(target)"#,
            "go",
        );
        assert_eq!(titles(&findings), vec!["Path Traversal"]);
    }

    #[test]
    fn go_base_sanitized_path_is_clean() {
        let findings = scan(
            r#"requested := filepath.Base(r.URL.Query().Get("file"))
target := filepath.Join("uploads", requested)
data, err := os.ReadFile(target)"#,
            "go",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn md5_function_call_is_still_reported() {
        let findings = scan(
            r#"return hashlib.md5(value.encode("utf-8")).hexdigest();"#,
            "py",
        );
        assert_eq!(titles(&findings), vec!["Weak Hash Algorithm — MD5"]);
    }

    #[test]
    fn python_md5_callable_alias_is_reported() {
        let findings = scan(
            r#"import hashlib
algorithm = hashlib.md5
return algorithm(payload).hexdigest()"#,
            "py",
        );
        assert_eq!(titles(&findings), vec!["Weak Hash Algorithm — MD5"]);
    }

    #[test]
    fn python_sha256_callable_alias_is_clean() {
        let findings = scan(
            r#"import hashlib
algorithm = hashlib.sha256
return algorithm(payload).hexdigest()"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    const SQLI: &str = "SQL Injection — String Concatenation";

    #[test]
    fn python_request_value_built_into_executed_query_is_reported() {
        let findings = scan(
            r#"user_id = request.args.get("id")
query = f"SELECT * FROM users WHERE id = '{user_id}'"
cursor.execute(query)"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn python_parameterized_query_with_request_value_is_clean() {
        let findings = scan(
            r#"user_id = request.args.get("id")
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_int_converted_request_value_is_clean() {
        let findings = scan(
            r#"user_id = request.args.get("id")
user_id = int(user_id)
query = "SELECT * FROM users WHERE id = " + str(user_id)
cursor.execute(query)"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_identifier_only_inside_plain_string_is_clean() {
        let findings = scan(
            r#"name = request.args.get("name")
query = "SELECT name FROM users"
cursor.execute(query)"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_destructured_request_value_in_template_query_is_reported() {
        let findings = scan(
            r#"const { name } = req.query;
const sql = `SELECT * FROM products WHERE name = '${name}'`;
const rows = db.query(sql);"#,
            "js",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn js_placeholder_query_with_request_value_is_clean() {
        let findings = scan(
            r#"const name = req.query.name;
const sql = "SELECT * FROM products WHERE name = ?";
const rows = db.query(sql, [name]);"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_request_value_concatenated_into_statement_is_reported() {
        let findings = scan(
            r#"String name = request.getParameter("name");
String sql = "SELECT * FROM users WHERE name = '" + name + "'";
ResultSet rs = stmt.executeQuery(sql);"#,
            "java",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn java_prepared_statement_bind_value_is_clean() {
        let findings = scan(
            r#"String name = request.getParameter("name");
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
ps.setString(1, name);
ResultSet rs = ps.executeQuery();"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_sprintf_request_value_in_query_is_reported() {
        let findings = scan(
            r#"name := r.URL.Query().Get("name")
query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
rows, err := db.QueryContext(ctx, query)"#,
            "go",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn go_placeholder_query_with_request_value_is_clean() {
        let findings = scan(
            r#"name := r.URL.Query().Get("name")
rows, err := db.QueryContext(ctx, "SELECT * FROM users WHERE name = $1", name)"#,
            "go",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_atoi_converted_request_value_is_clean() {
        let findings = scan(
            r#"raw := r.URL.Query().Get("id")
id, err := strconv.Atoi(raw)
query := fmt.Sprintf("SELECT * FROM users WHERE id = %d", id)
rows, err := db.Query(query)"#,
            "go",
        );
        assert!(findings.is_empty());
    }
}

/// Find calls through local Python aliases bound directly to `hashlib.md5`.
///
/// This intentionally stays narrow: it follows only direct callable bindings in
/// the same file and reports an invocation of that identifier. Secure hash
/// aliases and unrelated callables remain clean.
#[allow(clippy::items_after_test_module)]
fn python_md5_alias_call_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    if extension != "py" {
        return std::collections::HashSet::new();
    }

    let Ok(binding) =
        Regex::new(r#"(?i)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:hashlib\s*\.\s*md5|md5)\s*$"#)
    else {
        return std::collections::HashSet::new();
    };

    let mut aliases = std::collections::HashSet::new();
    let mut call_lines = std::collections::HashSet::new();
    for (line_index, line) in content.lines().enumerate() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.is_empty() {
            continue;
        }

        if let Some(alias) = binding
            .captures(code)
            .and_then(|captures| captures.get(1))
            .map(|capture| capture.as_str().to_string())
        {
            aliases.insert(alias);
            continue;
        }

        if aliases.iter().any(|alias| {
            Regex::new(&format!(r"\b{}\s*\(", regex::escape(alias)))
                .is_ok_and(|call| call.is_match(code))
        }) {
            call_lines.insert(line_index + 1);
        }
    }
    call_lines
}

/// Find Python filesystem sinks reached by a request-path value.
///
/// This intentionally models only straight-line local bindings. It follows Flask
/// and Django request path input through aliases and path construction, but stops
/// at basename-style sanitizers. The narrow model does not claim interprocedural
/// coverage.
#[allow(clippy::items_after_test_module)]
fn python_path_traversal_sink_lines(
    content: &str,
    extension: &str,
) -> std::collections::HashSet<usize> {
    if extension != "py" {
        return std::collections::HashSet::new();
    }

    let Ok(source) = Regex::new(
        r#"(?i)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:request\.(?:args|form|values|GET|POST)(?:\.get\s*\([^)]*\)|\s*\[[^\]]+\])|request\.path)"#,
    ) else {
        return std::collections::HashSet::new();
    };
    let Ok(binding) = Regex::new(r#"(?i)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$"#) else {
        return std::collections::HashSet::new();
    };
    let Ok(open_sink) = Regex::new(r#"(?i)\bopen\s*\("#) else {
        return std::collections::HashSet::new();
    };
    let Ok(method_sink) = Regex::new(
        r#"(?i)\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:read_text|read_bytes|write_text|write_bytes|open)\s*\("#,
    ) else {
        return std::collections::HashSet::new();
    };

    let mut tainted = std::collections::HashSet::new();
    let mut sink_lines = std::collections::HashSet::new();
    for (line_index, line) in content.lines().enumerate() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.is_empty() {
            continue;
        }

        if let Some(name) = source
            .captures(code)
            .and_then(|captures| captures.get(1))
            .map(|capture| capture.as_str().to_string())
        {
            if !contains_python_path_sanitizer(code) {
                tainted.insert(name);
            }
            continue;
        }

        if let Some(captures) = binding.captures(code) {
            let lhs = captures.get(1).map(|capture| capture.as_str());
            let rhs = captures
                .get(2)
                .map(|capture| capture.as_str())
                .unwrap_or("");
            let derives_from_taint = tainted.iter().any(|name| identifier_in(rhs, name));
            if derives_from_taint && !contains_python_path_sanitizer(rhs) {
                if let Some(lhs) = lhs {
                    tainted.insert(lhs.to_string());
                }
            }
        }

        let tainted_open =
            open_sink.is_match(code) && tainted.iter().any(|name| identifier_in(code, name));
        let tainted_method = method_sink.captures_iter(code).any(|captures| {
            captures
                .get(1)
                .is_some_and(|receiver| tainted.contains(receiver.as_str()))
        });
        if (tainted_open || tainted_method) && !contains_python_path_sanitizer(code) {
            sink_lines.insert(line_index + 1);
        }
    }
    sink_lines
}

/// Find Java filesystem sinks reached by a servlet request-path value.
///
/// This intentionally models only straight-line local bindings. It follows
/// `getParameter`/`getHeader`/`getPathInfo` input through aliases, string
/// construction, `new File`, `Paths.get`/`Path.of`, and `resolve`, but stops at
/// file-name sanitizers such as `getFileName()`. The narrow model does not claim
/// interprocedural coverage.
#[allow(clippy::items_after_test_module)]
fn java_path_traversal_sink_lines(
    content: &str,
    extension: &str,
) -> std::collections::HashSet<usize> {
    if extension != "java" {
        return std::collections::HashSet::new();
    }

    let Ok(source) = Regex::new(
        r#"(?i)^\s*(?:final\s+)?(?:[A-Za-z_][A-Za-z0-9_.<>\[\]]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:req|request)\s*\.\s*(?:getParameter|getHeader|getPathInfo)\s*\("#,
    ) else {
        return std::collections::HashSet::new();
    };
    let Ok(binding) = Regex::new(
        r#"(?i)^\s*(?:final\s+)?(?:[A-Za-z_][A-Za-z0-9_.<>\[\]]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^=].*?);?\s*$"#,
    ) else {
        return std::collections::HashSet::new();
    };
    let Ok(sink) = Regex::new(
        r#"(?i)\bnew\s+(?:FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)\s*\(|\bFiles\s*\.\s*(?:readAllBytes|readString|readAllLines|lines|newInputStream|newBufferedReader|newBufferedWriter|newOutputStream|write|writeString)\s*\("#,
    ) else {
        return std::collections::HashSet::new();
    };

    let mut tainted = std::collections::HashSet::new();
    let mut sink_lines = std::collections::HashSet::new();
    for (line_index, line) in content.lines().enumerate() {
        let code = line.trim();
        if code.is_empty()
            || code.starts_with("//")
            || code.starts_with("/*")
            || code.starts_with('*')
        {
            continue;
        }

        if let Some(name) = source
            .captures(code)
            .and_then(|captures| captures.get(1))
            .map(|capture| capture.as_str().to_string())
        {
            if !contains_java_path_sanitizer(code) {
                tainted.insert(name);
            }
            continue;
        }

        if let Some(captures) = binding.captures(code) {
            let lhs = captures.get(1).map(|capture| capture.as_str());
            let rhs = captures
                .get(2)
                .map(|capture| capture.as_str())
                .unwrap_or("");
            let derives_from_taint = tainted.iter().any(|name| identifier_in(rhs, name));
            if derives_from_taint && !contains_java_path_sanitizer(rhs) {
                if let Some(lhs) = lhs {
                    tainted.insert(lhs.to_string());
                }
            }
        }

        if sink.is_match(code)
            && tainted.iter().any(|name| identifier_in(code, name))
            && !contains_java_path_sanitizer(code)
        {
            sink_lines.insert(line_index + 1);
        }
    }
    sink_lines
}

#[allow(clippy::items_after_test_module)]
fn contains_java_path_sanitizer(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains(".getfilename(")
        || lower.contains("filenameutils.getname(")
        || lower.contains(".getname()")
}

/// Find Go filesystem sinks reached by a `net/http` request-path value.
///
/// This intentionally models only straight-line local bindings. It follows
/// query, form, and URL path input through aliases, string construction, and
/// `filepath.Join`/`path.Join`, but stops at `filepath.Base`/`path.Base`.
/// `filepath.Clean` is not treated as a sanitizer because it keeps leading
/// `../` segments. The narrow model does not claim interprocedural coverage.
#[allow(clippy::items_after_test_module)]
fn go_path_traversal_sink_lines(
    content: &str,
    extension: &str,
) -> std::collections::HashSet<usize> {
    if extension != "go" {
        return std::collections::HashSet::new();
    }

    let Ok(source) = Regex::new(
        r#"^\s*(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:\s+string)?\s*(?::=|=)\s*(?:r|req|request)\s*\.\s*(?:URL\s*\.\s*Query\s*\(\s*\)\s*\.\s*Get\s*\(|FormValue\s*\(|PostFormValue\s*\(|URL\s*\.\s*Path\b)"#,
    ) else {
        return std::collections::HashSet::new();
    };
    let Ok(binding) = Regex::new(
        r#"^\s*(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)?(?:\s+[A-Za-z_][A-Za-z0-9_.]*)?\s*(?::=|=)\s*([^=].*?)\s*$"#,
    ) else {
        return std::collections::HashSet::new();
    };
    let Ok(sink) = Regex::new(
        r#"\b(?:os\s*\.\s*(?:Open|OpenFile|ReadFile|WriteFile|Create)|ioutil\s*\.\s*(?:ReadFile|WriteFile)|http\s*\.\s*ServeFile)\s*\("#,
    ) else {
        return std::collections::HashSet::new();
    };

    let mut tainted = std::collections::HashSet::new();
    let mut sink_lines = std::collections::HashSet::new();
    for (line_index, line) in content.lines().enumerate() {
        let code = line.trim();
        if code.is_empty()
            || code.starts_with("//")
            || code.starts_with("/*")
            || code.starts_with('*')
        {
            continue;
        }

        if let Some(name) = source
            .captures(code)
            .and_then(|captures| captures.get(1))
            .map(|capture| capture.as_str().to_string())
        {
            if !contains_go_path_sanitizer(code) {
                tainted.insert(name);
            }
            continue;
        }

        if let Some(captures) = binding.captures(code) {
            let lhs = captures.get(1).map(|capture| capture.as_str());
            let rhs = captures
                .get(2)
                .map(|capture| capture.as_str())
                .unwrap_or("");
            let derives_from_taint = tainted.iter().any(|name| identifier_in(rhs, name));
            if derives_from_taint && !contains_go_path_sanitizer(rhs) {
                if let Some(lhs) = lhs {
                    tainted.insert(lhs.to_string());
                }
            }
        }

        if sink.is_match(code)
            && tainted.iter().any(|name| identifier_in(code, name))
            && !contains_go_path_sanitizer(code)
        {
            sink_lines.insert(line_index + 1);
        }
    }
    sink_lines
}

#[allow(clippy::items_after_test_module)]
fn contains_go_path_sanitizer(text: &str) -> bool {
    text.contains("filepath.Base(") || text.contains("path.Base(")
}

#[allow(clippy::items_after_test_module)]
fn contains_python_path_sanitizer(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("os.path.basename") || lower.contains("path.basename")
}

/// Find JavaScript/TypeScript filesystem sinks reached by a request-path value.
///
/// This intentionally models only straight-line local bindings. It follows a request
/// source through direct aliases, string construction, and `path.join`/`path.resolve`,
/// but stops at `path.basename`, which reduces a path to one component. The narrow
/// model adds useful multi-line coverage without pretending to be interprocedural.
#[allow(clippy::items_after_test_module)]
fn js_path_traversal_sink_lines(
    content: &str,
    extension: &str,
) -> std::collections::HashSet<usize> {
    if !matches!(extension, "js" | "ts") {
        return std::collections::HashSet::new();
    }

    let Ok(source) = Regex::new(
        r#"(?i)^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:req|request)\.(?:params|query|body)(?:\.[A-Za-z_$][A-Za-z0-9_$]*|\s*\[[^\]]+\])"#,
    ) else {
        return std::collections::HashSet::new();
    };
    let Ok(binding) =
        Regex::new(r#"(?i)^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(.+?);?\s*$"#)
    else {
        return std::collections::HashSet::new();
    };
    let Ok(sink) = Regex::new(
        r#"(?i)(?:\bfs\s*\.\s*)?(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)\s*\(|\.sendFile\s*\("#,
    ) else {
        return std::collections::HashSet::new();
    };

    let mut tainted = std::collections::HashSet::new();
    let mut sink_lines = std::collections::HashSet::new();
    for (line_index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
        {
            continue;
        }

        if let Some(name) = source
            .captures(line)
            .and_then(|captures| captures.get(1))
            .map(|capture| capture.as_str().to_string())
        {
            tainted.insert(name);
        }

        if let Some(captures) = binding.captures(line) {
            let lhs = captures.get(1).map(|capture| capture.as_str());
            let rhs = captures
                .get(2)
                .map(|capture| capture.as_str())
                .unwrap_or("");
            let derives_from_taint = tainted.iter().any(|name| identifier_in(rhs, name));
            if derives_from_taint && !rhs.to_ascii_lowercase().contains("path.basename") {
                if let Some(lhs) = lhs {
                    tainted.insert(lhs.to_string());
                }
            }
        }

        if sink.is_match(line)
            && tainted.iter().any(|name| identifier_in(line, name))
            && !line.to_ascii_lowercase().contains("path.basename")
        {
            sink_lines.insert(line_index + 1);
        }
    }
    sink_lines
}

#[allow(clippy::items_after_test_module)]
fn identifier_in(text: &str, identifier: &str) -> bool {
    Regex::new(&format!(r"\b{}\b", regex::escape(identifier)))
        .is_ok_and(|reference| reference.is_match(text))
}

/// Language family for the shared same-file request-flow engine.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FlowLanguage {
    JavaScript,
    Python,
    Java,
    Go,
}

#[allow(clippy::items_after_test_module)]
fn flow_language(extension: &str) -> Option<FlowLanguage> {
    match extension {
        "js" | "ts" => Some(FlowLanguage::JavaScript),
        "py" => Some(FlowLanguage::Python),
        "java" => Some(FlowLanguage::Java),
        "go" => Some(FlowLanguage::Go),
        _ => None,
    }
}

/// Blank out the contents of plain string literals so identifiers that only
/// appear inside quoted text are not mistaken for data flow. Interpolated
/// parts (`${...}` in JS template literals, `{...}` in Python f-strings) are
/// kept because they do carry values into the string.
#[allow(clippy::items_after_test_module)]
fn blank_plain_strings(text: &str, language: FlowLanguage) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let is_quote = c == '"'
            || c == '\''
            || (c == '`' && matches!(language, FlowLanguage::JavaScript | FlowLanguage::Go));
        if !is_quote {
            out.push(c);
            i += 1;
            continue;
        }
        let python_fstring = language == FlowLanguage::Python
            && i > 0
            && matches!(chars[i - 1], 'f' | 'F')
            && (i < 2
                || !(chars[i - 2].is_ascii_alphanumeric() || chars[i - 2] == '_')
                || matches!(chars[i - 2], 'r' | 'R'));
        let js_template = language == FlowLanguage::JavaScript && c == '`';
        out.push(c);
        i += 1;
        let mut depth = 0usize;
        while i < chars.len() {
            let ch = chars[i];
            if ch == '\\' && c != '`' {
                out.push(' ');
                i += 1;
                if i < chars.len() {
                    out.push(' ');
                    i += 1;
                }
                continue;
            }
            if depth == 0 && ch == c {
                break;
            }
            let opens = (python_fstring && ch == '{')
                || (js_template && ch == '$' && chars.get(i + 1) == Some(&'{'));
            if opens {
                if js_template {
                    out.push(' ');
                    i += 1;
                }
                depth += 1;
                out.push(' ');
                i += 1;
                continue;
            }
            if depth > 0 && ch == '}' {
                depth -= 1;
                out.push(' ');
                i += 1;
                continue;
            }
            out.push(if depth > 0 { ch } else { ' ' });
            i += 1;
        }
        if i < chars.len() {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Split the argument list of the call whose opening parenthesis is at
/// `open` (a byte index into `text`) into top-level arguments.
#[allow(clippy::items_after_test_module)]
fn call_arguments(text: &str, open: usize) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    for ch in text[open + 1..].chars() {
        match ch {
            '(' | '[' | '{' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' | '}' if depth == 0 => {
                args.push(current.trim().to_string());
                return args;
            }
            ')' | ']' | '}' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                args.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    args.push(current.trim().to_string());
    args
}

/// Request-input sources for each language, matching the ones proven in the
/// path-traversal flow models.
#[allow(clippy::items_after_test_module)]
fn flow_source_regex(language: FlowLanguage) -> Option<Regex> {
    let pattern = match language {
        FlowLanguage::JavaScript => {
            r#"(?i)^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:req|request)\.(?:params|query|body)(?:\.[A-Za-z_$][A-Za-z0-9_$]*|\s*\[[^\]]+\])"#
        }
        FlowLanguage::Python => {
            r#"(?i)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:request\.(?:args|form|values|GET|POST)(?:\.get\s*\([^)]*\)|\s*\[[^\]]+\])|request\.path)"#
        }
        FlowLanguage::Java => {
            r#"(?i)^\s*(?:final\s+)?(?:[A-Za-z_][A-Za-z0-9_.<>\[\]]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:req|request)\s*\.\s*(?:getParameter|getHeader|getPathInfo)\s*\("#
        }
        FlowLanguage::Go => {
            r#"^\s*(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:\s+string)?\s*(?::=|=)\s*(?:r|req|request)\s*\.\s*(?:URL\s*\.\s*Query\s*\(\s*\)\s*\.\s*Get\s*\(|FormValue\s*\(|PostFormValue\s*\(|URL\s*\.\s*Path\b)"#
        }
    };
    Regex::new(pattern).ok()
}

/// Plain local bindings (`lhs = rhs`) for each language.
#[allow(clippy::items_after_test_module)]
fn flow_binding_regex(language: FlowLanguage) -> Option<Regex> {
    let pattern = match language {
        FlowLanguage::JavaScript => {
            r#"^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([^=].*?);?\s*$"#
        }
        FlowLanguage::Python => r#"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^=].*?)\s*$"#,
        FlowLanguage::Java => {
            r#"^\s*(?:final\s+)?(?:[A-Za-z_][A-Za-z0-9_.<>\[\]]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^=].*?);?\s*$"#
        }
        FlowLanguage::Go => {
            r#"^\s*(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)?(?:\s+[A-Za-z_][A-Za-z0-9_.]*)?\s*(?::=|=)\s*([^=].*?)\s*$"#
        }
    };
    Regex::new(pattern).ok()
}

/// A sink for the shared flow engine: a call pattern whose match ends at the
/// call's opening parenthesis, and which argument positions carry the
/// dangerous value.
struct FlowSink {
    call: Regex,
    arguments: FlowArguments,
}

/// Maps a matched sink name to the argument positions that carry the
/// dangerous value.
type FlowArguments = fn(&str) -> Vec<usize>;

/// Straight-line, same-file request flow shared by the SQL injection model.
///
/// Tracks request-input variables through direct aliases and string
/// construction, drops taint when a variable is rebound to a sanitized or
/// untainted value, and reports a sink line only when a tainted identifier
/// appears in one of the sink's dangerous argument positions. Plain string
/// literal contents are ignored so text that merely looks like a variable
/// name does not count. This does not follow function calls, returns,
/// branches, or other files.
#[allow(clippy::items_after_test_module)]
fn request_flow_sink_lines(
    content: &str,
    language: FlowLanguage,
    sinks: &[FlowSink],
    sanitized: fn(&str) -> bool,
) -> std::collections::HashSet<usize> {
    let mut sink_lines = std::collections::HashSet::new();
    let (Some(source), Some(binding)) = (flow_source_regex(language), flow_binding_regex(language))
    else {
        return sink_lines;
    };
    let destructure = Regex::new(
        r#"^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:req|request)\s*\.\s*(?:params|query|body)\s*;?\s*$"#,
    )
    .ok();

    let mut tainted: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (line_index, line) in content.lines().enumerate() {
        let raw = if language == FlowLanguage::Python {
            line.split('#').next().unwrap_or("")
        } else {
            line
        };
        let code = raw.trim();
        if code.is_empty()
            || code.starts_with("//")
            || code.starts_with("/*")
            || code.starts_with('*')
        {
            continue;
        }

        if language == FlowLanguage::JavaScript {
            if let Some(names) = destructure
                .as_ref()
                .and_then(|re| re.captures(code))
                .and_then(|captures| captures.get(1))
            {
                for part in names.as_str().split(',') {
                    let local = part.split('=').next().unwrap_or("");
                    let local = local.rsplit(':').next().unwrap_or("").trim();
                    if !local.is_empty()
                        && local
                            .chars()
                            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
                    {
                        tainted.insert(local.to_string());
                    }
                }
                continue;
            }
        }

        if let Some(name) = source
            .captures(code)
            .and_then(|captures| captures.get(1))
            .map(|capture| capture.as_str().to_string())
        {
            if sanitized(code) {
                tainted.remove(&name);
            } else {
                tainted.insert(name);
            }
            continue;
        }

        let visible = blank_plain_strings(code, language);
        if let Some(captures) = binding.captures(&visible) {
            if let (Some(lhs), Some(rhs)) = (captures.get(1), captures.get(2)) {
                let rhs = rhs.as_str();
                let derives = tainted.iter().any(|name| identifier_in(rhs, name));
                if derives && !sanitized(rhs) {
                    tainted.insert(lhs.as_str().to_string());
                } else {
                    tainted.remove(lhs.as_str());
                }
            }
        }
        if tainted.is_empty() {
            continue;
        }

        let reaches_sink = sinks.iter().any(|sink| {
            sink.call.captures_iter(&visible).any(|captures| {
                let Some(whole) = captures.get(0) else {
                    return false;
                };
                let name = captures.get(1).map(|m| m.as_str()).unwrap_or("");
                let args = call_arguments(&visible, whole.end() - 1);
                (sink.arguments)(name).into_iter().any(|position| {
                    args.get(position).is_some_and(|arg| {
                        !sanitized(arg) && tainted.iter().any(|name| identifier_in(arg, name))
                    })
                })
            })
        });
        if reaches_sink {
            sink_lines.insert(line_index + 1);
        }
    }
    sink_lines
}

#[allow(clippy::items_after_test_module)]
fn first_argument(_name: &str) -> Vec<usize> {
    vec![0]
}

#[allow(clippy::items_after_test_module)]
fn go_sql_query_argument(name: &str) -> Vec<usize> {
    if name.ends_with("Context") {
        vec![1]
    } else {
        vec![0]
    }
}

#[allow(clippy::items_after_test_module)]
fn contains_numeric_conversion(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "int(",
        "float(",
        "number(",
        "parseint(",
        "parsefloat(",
        "integer.parseint(",
        "integer.valueof(",
        "long.parselong(",
        "long.valueof(",
        "uuid.fromstring(",
        "strconv.atoi(",
        "strconv.parseint(",
        "strconv.parseuint(",
        "strconv.parsefloat(",
    ]
    .iter()
    .any(|marker| {
        lower.match_indices(marker).any(|(index, _)| {
            index == 0 || {
                let before = lower.as_bytes()[index - 1];
                !(before.is_ascii_alphanumeric() || before == b'_')
            }
        })
    })
}

/// Find SQL query sinks whose query argument is built from request input in
/// the same file.
///
/// Sources are the request inputs used by the path-traversal models (plus JS
/// destructuring from `req.query`/`req.body`/`req.params`). Taint follows
/// aliases and string construction (concatenation, template literals,
/// f-strings, `format`/`String.format`/`fmt.Sprintf`) and is stopped by
/// numeric conversions. A tainted value passed only as a bind parameter of a
/// parameterized query is not reported. The model is same-file and
/// straight-line only; it makes no interprocedural claim.
#[allow(clippy::items_after_test_module)]
fn sql_injection_sink_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    let Some(language) = flow_language(extension) else {
        return std::collections::HashSet::new();
    };
    let patterns: &[(&str, FlowArguments)] = match language {
        FlowLanguage::Python => &[
            (
                r#"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(execute|executemany|executescript)\s*\("#,
                first_argument,
            ),
            (r#"\.\s*objects\s*\.\s*(raw)\s*\("#, first_argument),
        ],
        FlowLanguage::JavaScript => &[(
            r#"\b(?:db|conn|connection|pool|client|knex|sequelize|database|sql|tx|trx)\s*\.\s*(query|execute|prepare|exec|raw)\s*\("#,
            first_argument,
        )],
        FlowLanguage::Java => &[
            (
                r#"\.\s*(executeQuery|executeUpdate|executeLargeUpdate|execute|addBatch|prepareStatement|prepareCall|create(?:Native|SQL)?Query)\s*\("#,
                first_argument,
            ),
            (
                r#"\b[A-Za-z_]*[Jj]dbc[Tt]emplate\s*\.\s*(query[A-Za-z]*|update|execute)\s*\("#,
                first_argument,
            ),
        ],
        FlowLanguage::Go => &[(
            r#"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Prepare|PrepareContext)\s*\("#,
            go_sql_query_argument,
        )],
    };
    let sinks: Vec<FlowSink> = patterns
        .iter()
        .filter_map(|(pattern, arguments)| {
            Regex::new(pattern).ok().map(|call| FlowSink {
                call,
                arguments: *arguments,
            })
        })
        .collect();
    request_flow_sink_lines(content, language, &sinks, contains_numeric_conversion)
}
