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

    add_vuln!(
        "Server-Side Request Forgery (SSRF)",
        "An outbound HTTP request uses a URL taken from user input, letting an attacker reach internal services or cloud metadata endpoints.",
        Severity::High, Confidence::Medium, Some(OwaspCategory::A10SSRF),
        // Same-line shape only: request input passed straight into an HTTP
        // client call. Multi-line flows are found by `ssrf_sink_lines`.
        r#"(?i)\b(?:requests\s*\.\s*(?:get|post|put|delete|head|patch)|urlopen|fetch|axios\s*\.\s*(?:get|post|put|delete)|http\s*\.\s*Get)\s*\(\s*(?:request\s*\.\s*(?:args|form|values|GET|POST|getParameter)|req\s*\.\s*(?:query|body|params)|r\s*\.\s*URL\s*\.\s*Query)"#,
        &["py", "js", "ts", "java", "go", "rs"],
        "Validate outbound URLs against an allowlist of hosts and schemes, block private and metadata addresses, and never pass user input directly as the request URL."
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
#[cfg(test)]
fn scan_file_for_vulns(path: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    scan_file_for_vulns_with(path, patterns, None)
}

/// Scan one file, also reporting sink lines that other project files reach
/// through cross-file calls (see [`cross_file_flow_sinks`]).
fn scan_file_for_vulns_with(
    path: &Path,
    patterns: &[VulnPattern],
    cross_file: Option<&CrossFileSinkLines>,
) -> Vec<Finding> {
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
    let mut sql_injection_sinks = sql_injection_sink_lines(&content, &ext);
    let mut command_injection_sinks = command_injection_sink_lines(&content, &ext);
    let mut ssrf_sinks = ssrf_sink_lines(&content, &ext);
    if let Some(cross_file) = cross_file {
        sql_injection_sinks.extend(cross_file.sql.iter().copied());
        command_injection_sinks.extend(cross_file.command.iter().copied());
        ssrf_sinks.extend(cross_file.ssrf.iter().copied());
    }

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
                    && sql_injection_sinks.contains(&line_number))
                || (pattern.name == "Command Injection"
                    && command_injection_sinks.contains(&line_number))
                || (pattern.name == "Server-Side Request Forgery (SSRF)"
                    && ssrf_sinks.contains(&line_number));
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

    let mut files = Vec::new();
    for result in walker {
        if files.len() >= scan::MAX_SCAN_FILES {
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
                    files.push(path.to_path_buf());
                }
            }
        }
    }

    let cross_file = cross_file_flow_sinks(&files, &canonical_path);
    for path in &files {
        let findings = scan_file_for_vulns_with(path, &patterns, cross_file.get(path));
        report.extend(findings);
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

    const CMDI: &str = "Command Injection";

    #[test]
    fn python_request_value_reaching_popen_is_reported() {
        let findings = scan(
            r#"host = request.args.get("host")
cmd = "ping -c 1 " + host
return os.popen(cmd).read()"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![CMDI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn python_subprocess_shell_true_is_reported() {
        let findings = scan(
            r#"host = request.args.get("host")
cmd = f"ping -c 1 {host}"
subprocess.run(cmd, shell=True, check=True)"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![CMDI]);
    }

    #[test]
    fn python_argument_vector_without_shell_is_clean() {
        let findings = scan(
            r#"host = request.args.get("host")
subprocess.run(["ping", "-c", "1", host], check=True)"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_shlex_quoted_value_is_clean() {
        let findings = scan(
            r#"host = shlex.quote(request.args.get("host"))
cmd = "ping -c 1 " + host
os.system(cmd)"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_request_value_reaching_exec_is_reported() {
        let findings = scan(
            r#"const target = req.query.host;
const cmd = "ping -c 1 " + target;
exec(cmd, (err, out) => res.send(out));"#,
            "js",
        );
        assert_eq!(titles(&findings), vec![CMDI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn js_exec_file_argument_vector_is_clean() {
        let findings = scan(
            r#"const target = req.query.host;
execFile("ping", ["-c", "1", target], (err, out) => res.send(out));"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_regex_exec_method_is_not_a_command_sink() {
        let findings = scan(
            r#"const target = req.query.host;
const match = pattern.exec(target);"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_request_value_in_shell_process_builder_is_reported() {
        let findings = scan(
            r#"String host = request.getParameter("host");
String cmd = "ping -c 1 " + host;
Process p = new ProcessBuilder("sh", "-c", cmd).start();"#,
            "java",
        );
        assert_eq!(titles(&findings), vec![CMDI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn java_request_value_in_process_builder_argument_vector_is_clean() {
        let findings = scan(
            r#"String host = request.getParameter("host");
Process p = new ProcessBuilder("ping", "-c", "1", host).start();"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_request_value_in_shell_command_is_reported() {
        let findings = scan(
            r#"host := r.URL.Query().Get("host")
cmd := "ping -c 1 " + host
out, err := exec.Command("sh", "-c", cmd).Output()"#,
            "go",
        );
        assert_eq!(titles(&findings), vec![CMDI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn go_argument_vector_command_is_clean() {
        let findings = scan(
            r#"host := r.URL.Query().Get("host")
out, err := exec.Command("ping", "-c", "1", host).Output()"#,
            "go",
        );
        assert!(findings.is_empty());
    }

    const SSRF: &str = "Server-Side Request Forgery (SSRF)";

    #[test]
    fn python_request_url_reaching_requests_get_is_reported() {
        let findings = scan(
            r#"target = request.args.get("url")
endpoint = target + "/status"
resp = requests.get(endpoint, timeout=5)"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![SSRF]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn python_request_value_as_query_param_of_fixed_url_is_clean() {
        let findings = scan(
            r#"term = request.args.get("q")
resp = requests.get("https://api.example.com/search", params={"q": term})"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_request_url_reaching_fetch_is_reported() {
        let findings = scan(
            r#"const target = req.query.url;
const endpoint = `${target}/status`;
const resp = await fetch(endpoint);"#,
            "js",
        );
        assert_eq!(titles(&findings), vec![SSRF]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn js_request_value_in_body_of_fixed_url_is_clean() {
        let findings = scan(
            r#"const term = req.query.q;
const resp = await fetch("https://api.example.com/search", { method: "POST", body: term });"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_request_url_reaching_new_url_is_reported() {
        let findings = scan(
            r#"String target = request.getParameter("url");
URL endpoint = new URL(target);
HttpURLConnection conn = (HttpURLConnection) endpoint.openConnection();"#,
            "java",
        );
        assert_eq!(titles(&findings), vec![SSRF]);
        assert_eq!(findings[0].line_number, Some(2));
    }

    #[test]
    fn java_request_value_posted_to_fixed_url_is_clean() {
        let findings = scan(
            r#"String term = request.getParameter("q");
String body = restTemplate.postForObject("https://api.example.com/search", term, String.class);"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_request_url_reaching_new_request_is_reported() {
        let findings = scan(
            r#"target := r.URL.Query().Get("url")
req, err := http.NewRequestWithContext(ctx, "GET", target, nil)"#,
            "go",
        );
        assert_eq!(titles(&findings), vec![SSRF]);
    }

    #[test]
    fn go_request_value_in_body_of_fixed_url_is_clean() {
        let findings = scan(
            r#"term := r.URL.Query().Get("q")
req, err := http.NewRequest("POST", "https://api.example.com/search", strings.NewReader(term))"#,
            "go",
        );
        assert!(findings.is_empty());
    }

    const SQLI_FLOW: &str = "SQL Injection — String Concatenation";

    #[test]
    fn js_request_value_through_helper_chain_reaches_sql_sink() {
        let findings = scan(
            r#"function findUserByName(username) {
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    return db.prepare(query).get();
}

function lookup(name) {
    return findUserByName(name);
}

exports.getUser = (req, res) => {
    const { username } = req.query;
    return res.json(lookup(username));
};"#,
            "js",
        );
        assert_eq!(titles(&findings), vec![SQLI_FLOW]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn js_helper_using_bind_parameter_is_clean() {
        let findings = scan(
            r#"function findUserByName(username) {
    return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

exports.getUser = (req, res) => {
    const { username } = req.query;
    return res.json(findUserByName(username));
};"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_helper_called_only_with_constants_is_clean() {
        let findings = scan(
            r#"function findUserByName(username) {
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    return db.prepare(query).get();
}

exports.getAdmin = (req, res) => {
    const { id } = req.query;
    return res.json(findUserByName('admin'));
};"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_function_defined_twice_is_not_resolved() {
        let findings = scan(
            r#"function findUser(name) {
    return db.prepare(`SELECT * FROM users WHERE name = '${name}'`).get();
}

function findUser(name) {
    return db.prepare('SELECT * FROM users WHERE name = ?').get(name);
}

exports.getUser = (req, res) => {
    const { name } = req.query;
    return res.json(findUser(name));
};"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_call_on_other_receiver_is_not_resolved_to_local_function() {
        let findings = scan(
            r#"function findUser(name) {
    return db.prepare(`SELECT * FROM users WHERE name = '${name}'`).get();
}

exports.getUser = (req, res) => {
    const { name } = req.query;
    return res.json(repository.findUser(name));
};"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_caller_rebinding_to_constant_before_call_is_clean() {
        let findings = scan(
            r#"function findUser(name) {
    return db.prepare(`SELECT * FROM users WHERE name = '${name}'`).get();
}

exports.getUser = (req, res) => {
    let name = req.query.name;
    name = 'guest';
    return res.json(findUser(name));
};"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_only_the_tainted_parameter_position_counts() {
        let findings = scan(
            r#"function findProduct(owner, term) {
    const sql = `SELECT * FROM products WHERE name = '${term}'`;
    return db.prepare(sql).all();
}

exports.search = (req, res) => {
    const owner = req.query.owner;
    return res.json(findProduct(owner, 'widgets'));
};"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_request_value_passed_to_query_helper_is_reported() {
        let findings = scan(
            r#"def find_user(conn, name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return conn.execute(query).fetchall()


@app.route("/user")
def user():
    name = request.args.get("name")
    return str(find_user(conn, name))"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![SQLI_FLOW]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn python_numeric_conversion_at_call_site_is_clean() {
        let findings = scan(
            r#"def find_user(conn, user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query).fetchall()


@app.route("/user")
def user():
    user_id = request.args.get("id")
    return str(find_user(conn, int(user_id)))"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_self_method_shell_helper_is_reported_and_quote_stops_it() {
        let vulnerable = scan(
            r#"class Diagnostics:
    def run_ping(self, host):
        command = "ping -c 1 " + host
        return subprocess.check_output(command, shell=True)

    def ping(self):
        host = request.args.get("host")
        return self.run_ping(host)"#,
            "py",
        );
        assert_eq!(titles(&vulnerable), vec![CMDI]);
        assert_eq!(vulnerable[0].line_number, Some(4));

        let quoted = scan(
            r#"class Diagnostics:
    def run_ping(self, host):
        command = "ping -c 1 " + host
        return subprocess.check_output(command, shell=True)

    def ping(self):
        host = request.args.get("host")
        return self.run_ping(shlex.quote(host))"#,
            "py",
        );
        assert!(quoted.is_empty());
    }

    #[test]
    fn python_keyword_argument_call_is_not_mapped_by_position() {
        let findings = scan(
            r#"def find_user(conn, name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return conn.execute(query).fetchall()


def user():
    name = request.args.get("name")
    return find_user(conn=name, name="guest")"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_request_value_passed_to_private_query_method_is_reported() {
        let vulnerable = scan(
            r#"public class UserController extends HttpServlet {
    private ResultSet findUser(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return conn.createStatement().executeQuery(sql);
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findUser(name);
    }
}"#,
            "java",
        );
        assert_eq!(titles(&vulnerable), vec![SQLI_FLOW]);
        assert_eq!(vulnerable[0].line_number, Some(4));

        let prepared = scan(
            r#"public class UserController extends HttpServlet {
    private ResultSet findUser(String name) throws SQLException {
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        stmt.setString(1, name);
        return stmt.executeQuery();
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findUser(name);
    }
}"#,
            "java",
        );
        assert!(prepared.is_empty());
    }

    #[test]
    fn java_overloaded_methods_are_not_resolved() {
        let findings = scan(
            r#"public class UserController {
    private ResultSet findUser(String name) throws SQLException {
        return conn.createStatement().executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    private ResultSet findUser(String name, int limit) throws SQLException {
        return null;
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findUser(name, 10);
    }
}"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_request_value_passed_to_query_function_is_reported() {
        let vulnerable = scan(
            r#"func findUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	findUser(name)
}"#,
            "go",
        );
        assert_eq!(titles(&vulnerable), vec![SQLI_FLOW]);
        assert_eq!(vulnerable[0].line_number, Some(3));

        let parameterized = scan(
            r#"func findUser(name string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE name = $1", name)
}

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	findUser(name)
}"#,
            "go",
        );
        assert!(parameterized.is_empty());
    }

    #[test]
    fn go_method_with_receiver_is_not_resolved_from_bare_call() {
        let findings = scan(
            r#"func (s *Store) findUser(name string) (*sql.Rows, error) {
	return s.db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	store.findUser(name)
}"#,
            "go",
        );
        assert!(findings.is_empty());
    }

    /// Write a small project and return `(relative path, title, line)` for
    /// every flow-family finding the review path produces across its files.
    fn scan_project(files: &[(&str, &str)]) -> Vec<(String, String, usize)> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-xfile-{nonce}"));
        let mut paths = Vec::new();
        for (relative, source) in files {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            fs::write(&path, source).expect("write fixture");
            paths.push(path);
        }
        let cross_file = cross_file_flow_sinks(&paths, &root);
        let patterns = build_vuln_patterns();
        let mut found = Vec::new();
        for path in &paths {
            for finding in scan_file_for_vulns_with(path, &patterns, cross_file.get(path)) {
                // Only the flow families; unrelated pattern rules (IDOR on
                // `id` lookups, etc.) are covered by their own tests.
                if ![SQLI_FLOW, CMDI, SSRF].contains(&finding.title.as_str()) {
                    continue;
                }
                let relative = path
                    .strip_prefix(&root)
                    .expect("relative")
                    .to_string_lossy()
                    .replace('\\', "/");
                found.push((
                    relative,
                    finding.title.clone(),
                    finding.line_number.unwrap_or(0),
                ));
            }
        }
        fs::remove_dir_all(&root).expect("cleanup");
        found.sort();
        found
    }

    const JS_USERS_SERVICE: &str = r#"const db = require('../db');

function findByName(name) {
    const sql = `SELECT id FROM users WHERE name = '${name}'`;
    return db.prepare(sql).all();
}

function findById(id) {
    return db.prepare('SELECT id FROM users WHERE id = ?').get(id);
}

module.exports = { findByName, findById };"#;

    #[test]
    fn js_controller_to_service_module_call_is_reported_in_service() {
        let found = scan_project(&[
            (
                "src/routes/users.js",
                r#"const users = require('../services/users');

exports.search = (req, res) => {
    const { name } = req.query;
    return res.json(users.findByName(name));
};"#,
            ),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_named_import_and_destructured_require_resolve() {
        for import in [
            "import { findByName as lookup } from '../services/users';",
            "const { findByName: lookup } = require('../services/users');",
        ] {
            let route = format!(
                "{import}\n\nexports.search = (req, res) => {{\n    const name = req.query.name;\n    return res.json(lookup(name));\n}};"
            );
            let found = scan_project(&[
                ("src/routes/users.js", route.as_str()),
                ("src/services/users.js", JS_USERS_SERVICE),
            ]);
            assert_eq!(found.len(), 1, "{import}");
            assert_eq!(found[0].2, 5, "{import}");
        }
    }

    #[test]
    fn js_multiline_import_and_require_resolve() {
        for import in [
            "import {\n    findByName as lookup\n} from '../services/users';",
            "const {\n    findByName: lookup\n} = require('../services/users');",
        ] {
            let route = format!(
                "{import}\n\nexports.search = (req, res) => {{\n    const name = req.query.name;\n    return res.json(lookup(name));\n}};"
            );
            let found = scan_project(&[
                ("src/routes/users.js", route.as_str()),
                ("src/services/users.js", JS_USERS_SERVICE),
            ]);
            assert_eq!(found.len(), 1, "{import}");
            assert_eq!(found[0].2, 5, "{import}");
        }
    }

    #[test]
    fn js_multiline_reexport_resolves() {
        let barrel = "export {\n    findByName\n} from './users';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", barrel),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_instance_variable_mixed_import_call_is_reported_in_service() {
        let route = r#"import Repo, { helper } from '../services/repo';

class Handler {
    constructor() {
        this.repo = new Repo();
    }

    async search(req, res) {
        const { name } = req.query;
        return res.json(await this.repo.findByName(name));
    }
}

module.exports = new Handler();
"#;
        let repo = r#"const db = require('../db');

class Repo {
    async findByName(name) {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    }
}

module.exports = Repo;
"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/repo.js", repo),
        ]);
        assert_eq!(
            found,
            vec![("src/services/repo.js".to_string(), SQLI_FLOW.to_string(), 6)]
        );
    }

    #[test]
    fn js_instance_variable_call_is_reported_in_service() {
        let route = r#"const Repo = require('../services/repo');

class Handler {
    constructor() {
        this.repo = new Repo();
    }

    async search(req, res) {
        const { name } = req.query;
        return res.json(await this.repo.findByName(name));
    }
}

module.exports = new Handler();
"#;
        let repo = r#"const db = require('../db');

class Repo {
    async findByName(name) {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    }
}

module.exports = Repo;
"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/repo.js", repo),
        ]);
        assert_eq!(
            found,
            vec![("src/services/repo.js".to_string(), SQLI_FLOW.to_string(), 6)]
        );
    }

    #[test]
    fn js_instance_variable_other_name_call_is_reported_in_service() {
        let route = r#"const Repo = require('../services/repo');

class Handler {
    constructor() {
        this.store = new Repo();
    }

    async search(req, res) {
        const { name } = req.query;
        return res.json(await this.store.findByName(name));
    }
}

module.exports = new Handler();
"#;
        let repo = r#"const db = require('../db');

class Repo {
    async findByName(name) {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    }
}

module.exports = Repo;
"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/repo.js", repo),
        ]);
        assert_eq!(
            found,
            vec![("src/services/repo.js".to_string(), SQLI_FLOW.to_string(), 6)]
        );
    }

    #[test]
    fn js_instance_variable_default_import_call_is_reported_in_service() {
        let route = r#"import Repo from '../services/repo';

class Handler {
    constructor() {
        this.repo = new Repo();
    }

    async search(req, res) {
        const { name } = req.query;
        return res.json(await this.repo.findByName(name));
    }
}

export default new Handler();
"#;
        let repo = r#"import db from '../db';

export default class Repo {
    async findByName(name) {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    }
}
"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/repo.js", repo),
        ]);
        assert_eq!(
            found,
            vec![("src/services/repo.js".to_string(), SQLI_FLOW.to_string(), 6)]
        );
    }

    #[test]
    fn js_instance_variable_named_import_call_is_reported_in_service() {
        let route = r#"import { Repo } from '../services/repo';

class Handler {
    constructor() {
        this.repo = new Repo();
    }

    async search(req, res) {
        const { name } = req.query;
        return res.json(await this.repo.findByName(name));
    }
}

export default new Handler();
"#;
        let repo = r#"import db from '../db';

export class Repo {
    async findByName(name) {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    }
}
"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/repo.js", repo),
        ]);
        assert_eq!(
            found,
            vec![("src/services/repo.js".to_string(), SQLI_FLOW.to_string(), 6)]
        );
    }

    #[test]
    fn js_instance_variable_aliased_import_call_is_reported_in_service() {
        let route = r#"import { Repo as Store } from '../services/repo';

class Handler {
    constructor() {
        this.repo = new Store();
    }

    async search(req, res) {
        const { name } = req.query;
        return res.json(await this.repo.findByName(name));
    }
}

export default new Handler();
"#;
        let repo = r#"import db from '../db';

export class Repo {
    async findByName(name) {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    }
}
"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/repo.js", repo),
        ]);
        assert_eq!(
            found,
            vec![("src/services/repo.js".to_string(), SQLI_FLOW.to_string(), 6)]
        );
    }

    #[test]
    fn js_unassigned_instance_variable_call_is_not_resolved() {
        let route = r#"const Repo = require('../services/repo');

class Handler {
    async search(req, res) {
        const { name } = req.query;
        return res.json(await this.repo.findByName(name));
    }
}

module.exports = new Handler();
"#;
        let repo = r#"const db = require('../db');

class Repo {
    async findByName(name) {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    }
}

module.exports = Repo;
"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/repo.js", repo),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_instance_variable_without_import_is_not_resolved() {
        let route = r#"class Handler {
    constructor() {
        this.repo = new Repo();
    }

    async search(req, res) {
        const { name } = req.query;
        return res.json(await this.repo.findByName(name));
    }
}

module.exports = new Handler();
"#;
        let repo = r#"const db = require('../db');

class Repo {
    async findByName(name) {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    }
}

module.exports = Repo;
"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/repo.js", repo),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn python_instance_variable_call_is_reported_in_store() {
        let views = r#"from .repository import Store


class Views:
    def __init__(self):
        self.store = Store()

    @app.route("/orders")
    def orders(self):
        customer = request.args.get("customer")
        return {"orders": self.store.find_orders(customer)}
"#;
        let repository = r#"import sqlite3


class Store:
    def find_orders(self, customer):
        conn = sqlite3.connect("shop.db")
        query = "SELECT id FROM orders WHERE customer = '%s'" % customer
        return conn.execute(query).fetchall()
"#;
        let found = scan_project(&[("app/views.py", views), ("app/repository.py", repository)]);
        assert_eq!(
            found,
            vec![("app/repository.py".to_string(), SQLI_FLOW.to_string(), 8)]
        );
    }

    #[test]
    fn python_instance_variable_module_call_is_reported_in_store() {
        let views = r#"from . import repository


class Views:
    def __init__(self):
        self.store = repository.Store()

    @app.route("/orders")
    def orders(self):
        customer = request.args.get("customer")
        return {"orders": self.store.find_orders(customer)}
"#;
        let repository = r#"import sqlite3


class Store:
    def find_orders(self, customer):
        conn = sqlite3.connect("shop.db")
        query = "SELECT id FROM orders WHERE customer = '%s'" % customer
        return conn.execute(query).fetchall()
"#;
        let found = scan_project(&[("app/views.py", views), ("app/repository.py", repository)]);
        assert_eq!(
            found,
            vec![("app/repository.py".to_string(), SQLI_FLOW.to_string(), 8)]
        );
    }

    #[test]
    fn python_unassigned_instance_variable_call_is_not_resolved() {
        let views = r#"from .repository import Store


class Views:
    @app.route("/orders")
    def orders(self):
        customer = request.args.get("customer")
        return {"orders": self.store.find_orders(customer)}
"#;
        let repository = r#"import sqlite3


class Store:
    def find_orders(self, customer):
        conn = sqlite3.connect("shop.db")
        query = "SELECT id FROM orders WHERE customer = '%s'" % customer
        return conn.execute(query).fetchall()
"#;
        let found = scan_project(&[("app/views.py", views), ("app/repository.py", repository)]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn python_instance_variable_without_import_is_not_resolved() {
        let views = r#"class Views:
    def __init__(self):
        self.store = Store()

    @app.route("/orders")
    def orders(self):
        customer = request.args.get("customer")
        return {"orders": self.store.find_orders(customer)}
"#;
        let repository = r#"import sqlite3


class Store:
    def find_orders(self, customer):
        conn = sqlite3.connect("shop.db")
        query = "SELECT id FROM orders WHERE customer = '%s'" % customer
        return conn.execute(query).fetchall()
"#;
        let found = scan_project(&[("app/views.py", views), ("app/repository.py", repository)]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_default_export_call_is_reported_in_service() {
        let service = r#"const db = require('../db');

export default function findByName(name) {
    const sql = `SELECT id FROM users WHERE name = '${name}'`;
    return db.prepare(sql).all();
}
"#;
        for import in [
            "import findByName from '../services/users';",
            "import lookup from '../services/users';",
        ] {
            let callee = if import.contains("lookup") {
                "lookup"
            } else {
                "findByName"
            };
            let route = format!(
                "{import}\n\nexports.search = (req, res) => {{\n    const name = req.query.name;\n    return res.json({callee}(name));\n}};"
            );
            let found = scan_project(&[
                ("src/routes/users.js", route.as_str()),
                ("src/services/users.js", service),
            ]);
            assert_eq!(
                found,
                vec![(
                    "src/services/users.js".to_string(),
                    SQLI_FLOW.to_string(),
                    5
                )],
                "{import}"
            );
        }
    }

    #[test]
    fn js_default_export_reference_form_is_reported_in_service() {
        let service = r#"const db = require('../db');

function findByName(name) {
    const sql = `SELECT id FROM users WHERE name = '${name}'`;
    return db.prepare(sql).all();
}

export default findByName;
"#;
        let route = r#"import findByName from '../services/users';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/users.js", service),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_mixed_default_and_named_import_resolve() {
        let service = r#"const db = require('../db');

export default function findByName(name) {
    const sql = `SELECT id FROM users WHERE name = '${name}'`;
    return db.prepare(sql).all();
}

export function findById(id) {
    return db.prepare('SELECT id FROM users WHERE id = ?').get(id);
}
"#;
        let route = r#"import findByName, { findById } from '../services/users';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/users.js", service),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_default_export_parameterized_stays_clean() {
        let service = r#"const db = require('../db');

export default function findByName(name) {
    return db.prepare('SELECT id FROM users WHERE name = ?').all(name);
}
"#;
        let route = r#"import findByName from '../services/users';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/users.js", service),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_default_import_without_default_export_is_not_resolved() {
        let route = r#"import findByName from '../services/users';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_named_reexport_through_barrel_is_reported_in_service() {
        let barrel = "export { findByName } from './users';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", barrel),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_glob_reexport_through_barrel_is_reported_in_service() {
        let barrel = "export * from './users';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", barrel),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_chained_barrel_reexport_is_reported_in_service() {
        let outer_barrel = "export { findByName } from './v2';";
        let inner_barrel = "export { findByName } from './users';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", outer_barrel),
            ("src/services/v2.js", inner_barrel),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_glob_chained_through_named_barrel_is_reported_in_service() {
        let outer_barrel = "export * from './v2';";
        let inner_barrel = "export { findByName } from './users';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", outer_barrel),
            ("src/services/v2.js", inner_barrel),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_deep_barrel_chain_converges_in_service() {
        // Seven re-export hops: beyond the old fixed pass bound.
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            (
                "src/services/index.js",
                "export { findByName } from './v2';",
            ),
            ("src/services/v2.js", "export { findByName } from './v3';"),
            ("src/services/v3.js", "export { findByName } from './v4';"),
            ("src/services/v4.js", "export { findByName } from './v5';"),
            ("src/services/v5.js", "export { findByName } from './v6';"),
            ("src/services/v6.js", "export { findByName } from './v7';"),
            (
                "src/services/v7.js",
                "export { findByName } from './users';",
            ),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_long_same_file_helper_chain_converges() {
        // Nine functions deep: beyond the old fixed summary rounds.
        let route = r#"const store = require('../services/users');

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(store.findByName(name));
};"#;
        let service = r#"const db = require('../db');

function h8(name) {
    const sql = `SELECT id, name FROM users WHERE name = '${name}'`;
    return db.prepare(sql).all();
}

function h7(name) {
    return h8(name);
}

function h6(name) {
    return h7(name);
}

function h5(name) {
    return h6(name);
}

function h4(name) {
    return h5(name);
}

function h3(name) {
    return h4(name);
}

function h2(name) {
    return h3(name);
}

function findByName(name) {
    return h2(name);
}

module.exports = { findByName };"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/users.js", service),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_barrel_reexport_cycle_is_not_resolved() {
        let outer_barrel = "export { findByName } from './v2';";
        let inner_barrel = "export { findByName } from './index';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", outer_barrel),
            ("src/services/v2.js", inner_barrel),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_chained_barrel_ambiguous_source_is_not_resolved() {
        let barrel = "export { findByName } from './a';\nexport { findByName } from './b';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", barrel),
            ("src/services/a.js", JS_USERS_SERVICE),
            ("src/services/b.js", JS_USERS_SERVICE),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_two_import_hop_is_reported_in_final_service() {
        let route = r#"const search = require('../services/search');

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(search.byName(name));
};"#;
        let middle = r#"const store = require('./db-users');

function byName(name) {
    return store.findByName(name);
}

module.exports = { byName };"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/search.js", middle),
            ("src/services/db-users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/db-users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_two_import_hop_parameterized_service_is_clean() {
        let route = r#"const search = require('../services/search');

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(search.byName(name));
};"#;
        let middle = r#"const store = require('./db-users');

function byName(name) {
    return store.findByName(name);
}

module.exports = { byName };"#;
        let service = r#"const db = require('../db');

function findByName(name) {
    return db.prepare('SELECT id, name FROM users WHERE name = ?').get(name);
}

module.exports = { findByName };"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/search.js", middle),
            ("src/services/db-users.js", service),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_two_import_hop_ambiguous_middle_import_is_not_resolved() {
        let route = r#"const search = require('../services/search');

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(search.byName(name));
};"#;
        let middle = r#"const { findByName } = require('./a');
const { findByName } = require('./b');

function byName(name) {
    return findByName(name);
}

module.exports = { byName };"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/search.js", middle),
            ("src/services/a.js", JS_USERS_SERVICE),
            ("src/services/b.js", JS_USERS_SERVICE),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_three_import_hops_converge_in_final_service() {
        let route = r#"const gateway = require('../services/gateway');

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(gateway.byName(name));
};"#;
        let gateway = r#"const search = require('./search');

function byName(name) {
    return search.byName(name);
}

module.exports = { byName };"#;
        let middle = r#"const store = require('./db-users');

function byName(name) {
    return store.findByName(name);
}

module.exports = { byName };"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/gateway.js", gateway),
            ("src/services/search.js", middle),
            ("src/services/db-users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/db-users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_three_import_hops_parameterized_service_is_clean() {
        let route = r#"const gateway = require('../services/gateway');

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(gateway.byName(name));
};"#;
        let gateway = r#"const search = require('./search');

function byName(name) {
    return search.byName(name);
}

module.exports = { byName };"#;
        let middle = r#"const store = require('./db-users');

function byName(name) {
    return store.findByName(name);
}

module.exports = { byName };"#;
        let service = r#"const db = require('../db');

function findByName(name) {
    return db.prepare('SELECT id, name FROM users WHERE name = ?').get(name);
}

module.exports = { findByName };"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/gateway.js", gateway),
            ("src/services/search.js", middle),
            ("src/services/db-users.js", service),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_ambiguous_glob_reexport_is_not_resolved() {
        let other = r#"const db = require('../db');

function findByName(name) {
    const sql = `SELECT id FROM users WHERE name = '${name}'`;
    return db.prepare(sql).all();
}

module.exports = { findByName };"#;
        let barrel = "export * from './users';
export * from './other';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", barrel),
            ("src/services/users.js", JS_USERS_SERVICE),
            ("src/services/other.js", other),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_aliased_reexport_through_barrel_is_reported_in_service() {
        let barrel = "export { findByName as lookup } from './users';";
        let route = r#"import { lookup } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(lookup(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", barrel),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_namespace_reexport_through_barrel_is_reported_in_service() {
        let barrel = "export * as users from './users';";
        let route = r#"import { users } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(users.findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", barrel),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn java_import_resolving_outside_the_project_does_not_panic() {
        // `import java.io.File` names no class in the project; with a second
        // Java file present the class resolver used to index its empty match
        // list eagerly and panic the whole review.
        let reader = r#"package com.example;
import java.io.File;
public class A {
    public String read(String path) { return new File(path).getName(); }
}
"#;
        let other = r#"package com.example;
public class B {
    public String go(String p) { return p; }
}
"#;
        let found = scan_project(&[("src/A.java", reader), ("src/B.java", other)]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn python_star_import_name_offered_by_two_modules_resolves_to_neither() {
        let repository = r#"import sqlite3


def find_orders(customer):
    conn = sqlite3.connect("shop.db")
    query = "SELECT id FROM orders WHERE customer = '%s'" % customer
    return conn.execute(query).fetchall()"#;
        let views = r#"from .repository_a import *
from .repository_b import *


@app.route("/orders")
def orders():
    customer = request.args.get("customer")
    return {"orders": find_orders(customer)}
"#;
        let found = scan_project(&[
            ("app/views.py", views),
            ("app/repository_a.py", repository),
            ("app/repository_b.py", repository),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn python_star_import_into_repository_is_reported() {
        let repository = r#"import sqlite3


def find_orders(customer):
    conn = sqlite3.connect("shop.db")
    query = "SELECT id FROM orders WHERE customer = '%s'" % customer
    return conn.execute(query).fetchall()"#;
        let views = r#"from .repository import *


@app.route("/orders")
def orders():
    customer = request.args.get("customer")
    return {"orders": find_orders(customer)}
"#;
        let found = scan_project(&[("app/views.py", views), ("app/repository.py", repository)]);
        assert_eq!(
            found,
            vec![("app/repository.py".to_string(), SQLI_FLOW.to_string(), 7)],
            "star import"
        );
    }

    #[test]
    fn js_default_reexport_through_barrel_is_reported_in_service() {
        let service = r#"const db = require('../db');

export default function findByName(name) {
    const sql = `SELECT id FROM users WHERE name = '${name}'`;
    return db.prepare(sql).all();
}
"#;
        let barrel = "export { default as findByName } from './users';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", barrel),
            ("src/services/users.js", service),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )],
            "default-as reexport"
        );
    }

    #[test]
    fn js_reexport_of_parameterized_service_stays_clean() {
        let barrel = "export { findById } from './users';";
        let route = r#"import { findById } from '../services';

exports.get = (req, res) => {
    const id = req.params.id;
    return res.json(findById(id));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", barrel),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_parameterized_service_function_stays_clean() {
        let found = scan_project(&[
            (
                "src/routes/users.js",
                r#"const users = require('../services/users');

exports.get = (req, res) => {
    const id = req.params.id;
    return res.json(users.findById(id));
};"#,
            ),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_unexported_or_package_functions_are_not_resolved() {
        let found = scan_project(&[
            (
                "src/routes/users.js",
                r#"const users = require('../services/users');
const pkg = require('users');

exports.search = (req, res) => {
    const { name } = req.query;
    pkg.findByName(name);
    return res.json(users.findHidden(name));
};"#,
            ),
            (
                "src/services/users.js",
                r#"const db = require('../db');

function findHidden(name) {
    return db.prepare(`SELECT id FROM users WHERE name = '${name}'`).all();
}

module.exports = {};"#,
            ),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_service_called_only_with_constants_stays_clean() {
        let found = scan_project(&[
            (
                "src/routes/users.js",
                r#"const users = require('../services/users');

exports.admins = (req, res) => {
    const { page } = req.query;
    return res.json(users.findByName('admin'));
};"#,
            ),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn python_relative_import_into_repository_is_reported() {
        let repository = r#"import sqlite3


def find_orders(customer):
    conn = sqlite3.connect("shop.db")
    query = "SELECT id FROM orders WHERE customer = '%s'" % customer
    return conn.execute(query).fetchall()"#;
        for (import, call) in [
            (
                "from .repository import find_orders",
                "find_orders(customer)",
            ),
            (
                "from . import repository",
                "repository.find_orders(customer)",
            ),
        ] {
            let views = format!(
                "{import}\n\n\n@app.route(\"/orders\")\ndef orders():\n    customer = request.args.get(\"customer\")\n    return {{\"orders\": {call}}}\n"
            );
            let found = scan_project(&[
                ("app/views.py", views.as_str()),
                ("app/repository.py", repository),
            ]);
            assert_eq!(
                found,
                vec![("app/repository.py".to_string(), SQLI_FLOW.to_string(), 7)],
                "{import}"
            );
        }
    }

    #[test]
    fn python_parenthesized_import_into_repository_is_reported() {
        let repository = r#"import sqlite3


def find_orders(customer):
    conn = sqlite3.connect("shop.db")
    query = "SELECT id FROM orders WHERE customer = '%s'" % customer
    return conn.execute(query).fetchall()"#;
        for import in [
            "from .repository import (find_orders)",
            "from .repository import (\n    find_orders,\n)",
            "from . import (repository)",
        ] {
            let (import, call) = if import.contains("repository)") {
                (import, "repository.find_orders(customer)")
            } else {
                (import, "find_orders(customer)")
            };
            let views = format!(
                "{import}\n\n\n@app.route(\"/orders\")\ndef orders():\n    customer = request.args.get(\"customer\")\n    return {{\"orders\": {call}}}\n"
            );
            let found = scan_project(&[
                ("app/views.py", views.as_str()),
                ("app/repository.py", repository),
            ]);
            assert_eq!(
                found,
                vec![("app/repository.py".to_string(), SQLI_FLOW.to_string(), 7)],
                "{import}"
            );
        }
    }

    #[test]
    fn python_numeric_conversion_before_cross_file_call_is_clean() {
        let found = scan_project(&[
            (
                "app/views.py",
                r#"from .repository import find_orders


@app.route("/orders")
def orders():
    customer_id = int(request.args.get("customer_id", "0"))
    return {"orders": find_orders(customer_id)}"#,
            ),
            (
                "app/repository.py",
                r#"def find_orders(customer_id):
    query = "SELECT id FROM orders WHERE customer_id = %d" % customer_id
    return conn.execute(query).fetchall()"#,
            ),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    const JAVA_USER_SERVICE: &str = r#"package com.example.demo;

import java.sql.*;

public class UserService {
    private static Connection conn;

    public static ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
"#;

    const JAVA_USER_CONTROLLER: &str = r#"package com.example.demo;

import java.sql.*;
import javax.servlet.http.*;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        UserService.findByName(name);
    }
}
"#;

    const GO_STORE: &str = r#"package main

import (
	"database/sql"
	"fmt"
)

var db *sql.DB

func findUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}
"#;

    #[test]
    fn java_same_package_static_call_is_reported_in_service() {
        let found = scan_project(&[
            ("src/UserController.java", JAVA_USER_CONTROLLER),
            ("src/UserService.java", JAVA_USER_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/UserService.java".to_string(),
                SQLI_FLOW.to_string(),
                11
            )]
        );
    }

    #[test]
    fn java_import_resolved_static_call_is_reported_in_service() {
        let controller = r#"package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import com.example.service.UserService;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        UserService.findByName(name);
    }
}
"#;
        let service = r#"package com.example.service;

import java.sql.*;

public class UserService {
    private static Connection conn;

    public static ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
"#;
        let found = scan_project(&[
            ("src/com/example/web/UserController.java", controller),
            ("src/com/example/service/UserService.java", service),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/com/example/service/UserService.java".to_string(),
                SQLI_FLOW.to_string(),
                11
            )]
        );
    }

    #[test]
    fn java_parameterized_cross_file_call_is_clean() {
        let service = r#"package com.example.demo;

import java.sql.*;

public class UserService {
    private static Connection conn;

    public static ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = ?";
        PreparedStatement stmt = conn.prepareStatement(sql);
        stmt.setString(1, name);
        return stmt.executeQuery();
    }
}
"#;
        let found = scan_project(&[
            ("src/UserController.java", JAVA_USER_CONTROLLER),
            ("src/UserService.java", service),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    const JAVA_SERVICE_PACKAGE: &str = r#"package com.example.service;

import java.sql.*;

public class UserService {
    private static Connection conn;

    public static ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
"#;

    #[test]
    fn java_import_static_call_is_reported_in_service() {
        let controller = r#"package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import static com.example.service.UserService.findByName;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findByName(name);
    }
}
"#;
        let found = scan_project(&[
            ("src/com/example/web/UserController.java", controller),
            (
                "src/com/example/service/UserService.java",
                JAVA_SERVICE_PACKAGE,
            ),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/com/example/service/UserService.java".to_string(),
                SQLI_FLOW.to_string(),
                11
            )]
        );
    }

    #[test]
    fn java_import_static_wildcard_call_is_reported_in_service() {
        let controller = r#"package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import static com.example.service.UserService.*;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findByName(name);
    }
}
"#;
        let found = scan_project(&[
            ("src/com/example/web/UserController.java", controller),
            (
                "src/com/example/service/UserService.java",
                JAVA_SERVICE_PACKAGE,
            ),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/com/example/service/UserService.java".to_string(),
                SQLI_FLOW.to_string(),
                11
            )]
        );
    }

    #[test]
    fn java_package_wildcard_call_is_reported_in_service() {
        let controller = r#"package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import com.example.service.*;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        UserService.findByName(name);
    }
}
"#;
        let found = scan_project(&[
            ("src/com/example/web/UserController.java", controller),
            (
                "src/com/example/service/UserService.java",
                JAVA_SERVICE_PACKAGE,
            ),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/com/example/service/UserService.java".to_string(),
                SQLI_FLOW.to_string(),
                11
            )]
        );
    }

    #[test]
    fn java_import_static_shadowed_by_own_method_is_not_resolved() {
        let controller = r#"package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import static com.example.service.UserService.findByName;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findByName(name);
    }

    private void findByName(String name) {
        System.out.println(name);
    }
}
"#;
        let found = scan_project(&[
            ("src/com/example/web/UserController.java", controller),
            (
                "src/com/example/service/UserService.java",
                JAVA_SERVICE_PACKAGE,
            ),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn java_import_static_private_method_is_not_resolved() {
        let controller = r#"package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import static com.example.service.UserService.findByName;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findByName(name);
    }
}
"#;
        let service = r#"package com.example.service;

import java.sql.*;

public class UserService {
    private static Connection conn;

    private static ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
"#;
        let found = scan_project(&[
            ("src/com/example/web/UserController.java", controller),
            ("src/com/example/service/UserService.java", service),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn java_import_static_ambiguous_members_are_not_resolved() {
        let controller = r#"package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import static com.example.service.UserService.findByName;
import static com.example.other.UserService.findByName;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findByName(name);
    }
}
"#;
        let other = r#"package com.example.other;

import java.sql.*;

public class UserService {
    private static Connection conn;

    public static ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
"#;
        let found = scan_project(&[
            ("src/com/example/web/UserController.java", controller),
            (
                "src/com/example/service/UserService.java",
                JAVA_SERVICE_PACKAGE,
            ),
            ("src/com/example/other/UserService.java", other),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn java_instance_method_call_is_not_resolved() {
        let controller = r#"package com.example.demo;

import java.sql.*;
import javax.servlet.http.*;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        UserService service = new UserService();
        service.findByName(name);
    }
}
"#;
        let service = r#"package com.example.demo;

import java.sql.*;

public class UserService {
    private Connection conn;

    public ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
"#;
        let found = scan_project(&[
            ("src/UserController.java", controller),
            ("src/UserService.java", service),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn go_same_package_call_is_reported_in_store() {
        let handler = r#"package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	findUser(name)
}
"#;
        let found = scan_project(&[("handler.go", handler), ("store.go", GO_STORE)]);
        assert_eq!(
            found,
            vec![("store.go".to_string(), SQLI_FLOW.to_string(), 12)]
        );
    }

    #[test]
    fn go_numeric_conversion_before_cross_file_call_is_clean() {
        let handler = r#"package main

import (
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	id, _ := strconv.Atoi(name)
	findUser(id)
}
"#;
        let found = scan_project(&[("handler.go", handler), ("store.go", GO_STORE)]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn go_cross_package_call_is_reported_in_store() {
        let store = r#"package store

import (
	"database/sql"
	"fmt"
)

var db *sql.DB

func FindUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}
"#;
        for (import, call) in [
            ("\"example.com/shop/store\"", "store.FindUser(name)"),
            ("st \"example.com/shop/store\"", "st.FindUser(name)"),
        ] {
            let main = format!(
                "package main\n\nimport (\n\t\"net/http\"\n\n\t{import}\n)\n\nfunc handler(w http.ResponseWriter, r *http.Request) {{\n\tname := r.URL.Query().Get(\"name\")\n\t{call}\n}}\n"
            );
            let found = scan_project(&[
                ("go.mod", "module example.com/shop\n"),
                ("main.go", main.as_str()),
                ("store/store.go", store),
            ]);
            assert_eq!(
                found,
                vec![("store/store.go".to_string(), SQLI_FLOW.to_string(), 12)],
                "{import}"
            );
        }
    }

    #[test]
    fn go_dot_import_name_offered_by_two_packages_resolves_to_neither() {
        let store = r#"package store

import (
	"database/sql"
	"fmt"
)

var db *sql.DB

func FindUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}
"#;
        let main = r#"package main

import (
	"net/http"

	. "example.com/shop/store"
	. "example.com/shop/store2"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	FindUser(name)
}
"#;
        let found = scan_project(&[
            (
                "go.mod",
                "module example.com/shop
",
            ),
            ("main.go", main),
            ("store/store.go", store),
            ("store2/store2.go", store),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn go_dot_import_call_is_reported_in_store() {
        let store = r#"package store

import (
	"database/sql"
	"fmt"
)

var db *sql.DB

func FindUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}
"#;
        let main = r#"package main

import (
	"net/http"

	. "example.com/shop/store"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	FindUser(name)
}
"#;
        let found = scan_project(&[
            (
                "go.mod",
                "module example.com/shop
",
            ),
            ("main.go", main),
            ("store/store.go", store),
        ]);
        assert_eq!(
            found,
            vec![("store/store.go".to_string(), SQLI_FLOW.to_string(), 12)],
            "dot import"
        );
    }

    #[test]
    fn go_replace_module_call_is_reported_in_store() {
        let main = r#"package main

import (
	"net/http"

	"example.com/inventory/store"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	store.FindUser(name)
}
"#;
        let store = r#"package store

import (
	"database/sql"
	"fmt"
)

var db *sql.DB

func FindUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}
"#;
        for go_mod in [
            "module example.com/shop\n\nrequire example.com/inventory v0.0.0\n\nreplace example.com/inventory => ./inventory\n",
            "module example.com/shop\n\nreplace (\n\texample.com/inventory => ./inventory\n)\n",
        ] {
            let found = scan_project(&[
                ("go.mod", go_mod),
                ("main.go", main),
                ("inventory/store/store.go", store),
            ]);
            assert_eq!(
                found,
                vec![(
                    "inventory/store/store.go".to_string(),
                    SQLI_FLOW.to_string(),
                    12
                )],
                "{go_mod}"
            );
        }
    }

    #[test]
    fn go_nested_module_call_is_reported_in_store() {
        let main = r#"package main

import (
	"net/http"

	"example.com/inventory/store"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	store.FindUser(name)
}
"#;
        let store = r#"package store

import (
	"database/sql"
	"fmt"
)

var db *sql.DB

func FindUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}
"#;
        let found = scan_project(&[
            ("go.mod", "module example.com/shop\n"),
            ("main.go", main),
            ("inventory/go.mod", "module example.com/inventory\n"),
            ("inventory/store/store.go", store),
        ]);
        assert_eq!(
            found,
            vec![(
                "inventory/store/store.go".to_string(),
                SQLI_FLOW.to_string(),
                12
            )]
        );
    }

    #[test]
    fn go_replace_module_parameterized_is_clean() {
        let main = r#"package main

import (
	"net/http"

	"example.com/inventory/store"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	store.FindUser(name)
}
"#;
        let store = r#"package store

import "database/sql"

var db *sql.DB

func FindUser(name string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE name = ?", name)
}
"#;
        let found = scan_project(&[
            (
                "go.mod",
                "module example.com/shop\n\nreplace example.com/inventory => ./inventory\n",
            ),
            ("main.go", main),
            ("inventory/store/store.go", store),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn go_unexported_cross_package_call_is_not_resolved() {
        let main = r#"package main

import (
	"net/http"

	"example.com/shop/store"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	store.findUser(name)
}
"#;
        let store = r#"package store

import (
	"database/sql"
	"fmt"
)

var db *sql.DB

func findUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}
"#;
        let found = scan_project(&[
            ("go.mod", "module example.com/shop\n"),
            ("main.go", main),
            ("store/store.go", store),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    const RUST_STORE: &str = r#"use sqlx::PgPool;

pub async fn find_user(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    let query = format!("SELECT * FROM users WHERE name = '{name}'");
    sqlx::query(&query).execute(pool).await?;
    Ok(())
}
"#;

    #[test]
    fn rust_mod_path_call_is_reported_in_store() {
        let main = r#"mod store;

use actix_web::{get, HttpRequest, HttpResponse};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    store::find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main), ("src/store.rs", RUST_STORE)]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_use_crate_function_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::find_user;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        for main_file in ["src/main.rs", "src/lib.rs"] {
            let found = scan_project(&[(main_file, main), ("src/store.rs", RUST_STORE)]);
            assert_eq!(
                found,
                vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)],
                "{main_file}"
            );
        }
    }

    #[test]
    fn rust_use_glob_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::*;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main), ("src/store.rs", RUST_STORE)]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_grouped_use_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{find_user, list_users};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main), ("src/store.rs", RUST_STORE)]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_grouped_use_alias_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{find_user as fetch_user};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    fetch_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main), ("src/store.rs", RUST_STORE)]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_grouped_use_glob_item_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{POOL_ALIAS, *};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main), ("src/store.rs", RUST_STORE)]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    const RUST_HANDLER: &str = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::find_user;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;

    #[test]
    fn rust_pub_use_named_reexport_is_reported_in_store() {
        let lib = "mod store;\n\npub use store::find_user;";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", RUST_HANDLER),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_pub_use_crate_path_reexport_is_reported_in_store() {
        let lib = "mod store;\n\npub use crate::store::find_user;";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", RUST_HANDLER),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_pub_use_grouped_reexport_is_reported_in_store() {
        let lib = "mod store;\n\npub use store::{find_user};";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", RUST_HANDLER),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_pub_use_glob_reexport_is_reported_in_store() {
        let lib = "mod store;\n\npub use store::*;";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", RUST_HANDLER),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_pub_use_alias_reexport_is_reported_in_store() {
        let lib = "mod store;\n\npub use store::find_user as locate_user;";
        let handler = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::locate_user;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    locate_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", handler),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_pub_use_ambiguous_glob_is_not_resolved() {
        let lib = "mod a;\nmod b;\n\npub use a::*;\npub use b::*;";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", RUST_HANDLER),
            ("src/a.rs", RUST_STORE),
            ("src/b.rs", RUST_STORE),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rust_pub_use_parameterized_store_is_clean() {
        let lib = "mod store;\n\npub use store::find_user;";
        let store = r#"use sqlx::{Pool, Postgres};

pub async fn find_user(pool: &Pool<Postgres>, name: &str) -> Option<String> {
    sqlx::query("SELECT name FROM users WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}
"#;
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", RUST_HANDLER),
            ("src/store.rs", store),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rust_pub_use_chained_reexport_is_reported_in_store() {
        let lib = "mod intermediate;\nmod store;\n\npub use intermediate::find_user;";
        let intermediate = "pub use crate::store::find_user;";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/intermediate.rs", intermediate),
            ("src/handler.rs", RUST_HANDLER),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_pub_use_chained_glob_reexport_is_reported_in_store() {
        let lib = "mod intermediate;\nmod store;\n\npub use intermediate::*;";
        let intermediate = "pub use crate::store::*;";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/intermediate.rs", intermediate),
            ("src/handler.rs", RUST_HANDLER),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_deep_pub_use_chain_converges_in_store() {
        // Six re-export hops: beyond the old fixed pass bound.
        let lib =
            "mod m1;\nmod m2;\nmod m3;\nmod m4;\nmod m5;\nmod store;\n\npub use m1::find_user;";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/m1.rs", "pub use crate::m2::find_user;"),
            ("src/m2.rs", "pub use crate::m3::find_user;"),
            ("src/m3.rs", "pub use crate::m4::find_user;"),
            ("src/m4.rs", "pub use crate::m5::find_user;"),
            ("src/m5.rs", "pub use crate::store::find_user;"),
            ("src/handler.rs", RUST_HANDLER),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_pub_use_reexport_cycle_is_not_resolved() {
        let lib = "mod intermediate;\n\npub use intermediate::find_user;";
        let intermediate = "pub use crate::find_user;";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/intermediate.rs", intermediate),
            ("src/handler.rs", RUST_HANDLER),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rust_two_import_hop_is_reported_in_store() {
        let lib = "mod intermediate;\nmod store;";
        let handler = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::intermediate::find_user;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let intermediate = r#"use sqlx::PgPool;

use crate::store::query_user;

pub async fn find_user(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    query_user(pool, name).await
}
"#;
        // Built from RUST_STORE so the fixture adds no extra copy of the
        // sink string to this file (the policy baseline counts duplicates).
        let store = RUST_STORE.replace("find_user", "query_user");
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", handler),
            ("src/intermediate.rs", intermediate),
            ("src/store.rs", store.as_str()),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_three_import_hops_converge_in_store() {
        let lib = "mod intermediate;\nmod relay;\nmod store;";
        let handler = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::intermediate::find_user;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let intermediate = r#"use sqlx::PgPool;

use crate::relay::find_user as relay_user;

pub async fn find_user(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    relay_user(pool, name).await
}
"#;
        let relay = r#"use sqlx::PgPool;

use crate::store::find_user as query_user;

pub async fn find_user(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    query_user(pool, name).await
}
"#;
        // Reuses RUST_STORE directly so the fixture adds no extra copy of
        // the sink string (the policy baseline counts duplicates).
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", handler),
            ("src/intermediate.rs", intermediate),
            ("src/relay.rs", relay),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_two_import_hop_cycle_without_sink_is_clean() {
        let lib = "mod intermediate;\nmod store;";
        let handler = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::intermediate::find_user;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let intermediate = r#"use sqlx::PgPool;

use crate::store::query_user;

pub async fn find_user(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    query_user(pool, name).await
}
"#;
        let store = r#"use sqlx::PgPool;

use crate::intermediate::find_user;

pub async fn query_user(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    find_user(pool, name).await
}
"#;
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", handler),
            ("src/intermediate.rs", intermediate),
            ("src/store.rs", store),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rust_grouped_use_parameterized_store_is_clean() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{find_user, list_users};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let store = r#"use sqlx::{Pool, Postgres};

pub async fn find_user(pool: &Pool<Postgres>, name: &str) -> Option<String> {
    sqlx::query("SELECT name FROM users WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}

pub async fn list_users(pool: &Pool<Postgres>) -> Vec<String> {
    Vec::new()
}
"#;
        let found = scan_project(&[("src/main.rs", main), ("src/store.rs", store)]);
        assert!(found.is_empty());
    }

    #[test]
    fn rust_deep_nested_mod_path_converges_in_leaf() {
        let main = r#"mod api;

use actix_web::{get, HttpRequest, HttpResponse};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    api::v1::users::lookup(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        // `api::v1::users::lookup(...)` walks three module bindings: api,
        // v1 inside api, users inside v1. Built from RUST_STORE so the
        // fixture adds no extra copy of the sink string to this file (the
        // policy baseline counts duplicates).
        let users = RUST_STORE.replace("find_user", "lookup");
        let found = scan_project(&[
            ("src/main.rs", main),
            (
                "src/api.rs",
                "pub mod v1;
",
            ),
            (
                "src/api/v1.rs",
                "pub mod users;
",
            ),
            ("src/api/v1/users.rs", users.as_str()),
        ]);
        assert_eq!(
            found,
            vec![("src/api/v1/users.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );

        // Without `pub mod users;` in v1.rs the chain stays unresolved.
        let found = scan_project(&[
            ("src/main.rs", main),
            (
                "src/api.rs",
                "pub mod v1;
",
            ),
            ("src/api/v1.rs", ""),
            ("src/api/v1/users.rs", users.as_str()),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rust_pubuse_barrel_call_is_reported_in_store() {
        let barrel = "pub use crate::store::find_user;";
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::barrel::find_user;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/barrel.rs", barrel),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)],
            "pub use barrel"
        );
    }

    #[test]
    fn rust_multiline_grouped_use_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{
    find_user,
    list_users,
};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main), ("src/store.rs", RUST_STORE)]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_multiline_nested_group_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{
    inner::{
        find_user
    }
};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let store = "pub mod inner;
";
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/store.rs", store),
            ("src/store/inner.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store/inner.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_multiline_grouped_use_with_comment_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{
    find_user, // the lookup
    list_users,
};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main), ("src/store.rs", RUST_STORE)]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_nested_group_missing_module_is_clean() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{inner::{find_user}};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main), ("src/store.rs", RUST_STORE)]);
        assert!(found.is_empty());
    }

    #[test]
    fn rust_nested_group_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{inner::{find_user}};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let store = "pub mod inner;
";
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/store.rs", store),
            ("src/store/inner.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store/inner.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_nested_group_alias_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{inner::{find_user as fetch_user}};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    fetch_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let store = "pub mod inner;
";
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/store.rs", store),
            ("src/store/inner.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store/inner.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_nested_group_glob_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{inner::{*}};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let store = "pub mod inner;
";
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/store.rs", store),
            ("src/store/inner.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store/inner.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_nested_path_item_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{inner::find_user};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let store = "pub mod inner;
";
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/store.rs", store),
            ("src/store/inner.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store/inner.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_nested_mod_path_call_is_reported_in_store() {
        let main = r#"mod api;

use actix_web::{get, HttpRequest, HttpResponse};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    api::users::lookup(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let api = r#"pub mod users;
"#;
        let users = r#"use sqlx::PgPool;

pub async fn lookup(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    let query = format!("SELECT * FROM users WHERE name = '{name}'");
    sqlx::query(&query).execute(pool).await?;
    Ok(())
}
"#;
        // `api::users::lookup(...)` resolves through one nested hop: each
        // module declares the next (`mod api;` + `pub mod users;`).
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/api.rs", api),
            ("src/api/users.rs", users),
        ]);
        assert_eq!(
            found,
            vec![("src/api/users.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );

        // Without `pub mod users;` in api.rs the chain stays unresolved.
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/api.rs", ""),
            ("src/api/users.rs", users),
        ]);
        assert!(found.is_empty(), "{found:?}");

        let main_use = main.replace("mod api;", "use crate::api::users::lookup;");
        let main_use = main_use.replace(
            "api::users::lookup(&POOL, name).await.ok();",
            "lookup(&POOL, name).await.ok();",
        );
        let found = scan_project(&[
            ("src/main.rs", main_use.as_str()),
            ("src/api.rs", api),
            ("src/api/users.rs", users),
        ]);
        assert_eq!(
            found,
            vec![("src/api/users.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_triple_mod_path_call_is_reported_in_leaf() {
        let main = r#"mod api;

use actix_web::{get, HttpRequest, HttpResponse};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    api::inner::users::lookup(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let api = "pub mod inner;\n";
        let inner = "pub mod users;\n";
        let users = r#"use sqlx::PgPool;

pub async fn lookup(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    let query = format!("SELECT * FROM users WHERE name = '{name}'");
    sqlx::query(&query).execute(pool).await?;
    Ok(())
}
"#;
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/api.rs", api),
            ("src/api/inner.rs", inner),
            ("src/api/inner/users.rs", users),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/api/inner/users.rs".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn rust_non_pub_function_is_not_exported() {
        let store = r#"use sqlx::PgPool;

async fn find_user(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    let query = format!("SELECT * FROM users WHERE name = '{name}'");
    sqlx::query(&query).execute(pool).await?;
    Ok(())
}
"#;
        let main = r#"mod store;

use actix_web::{get, HttpRequest, HttpResponse};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    store::find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main), ("src/store.rs", store)]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rust_parse_conversion_before_call_is_clean() {
        let main = r#"mod store;

use actix_web::{get, HttpRequest, HttpResponse};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    let id: i64 = name.parse::<i64>().unwrap_or(0);
    store::find_user_by_id(id).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let store = r#"use sqlx::PgPool;

pub async fn find_user_by_id(id: i64) -> Result<(), sqlx::Error> {
    let query = format!("SELECT * FROM users WHERE id = {id}");
    sqlx::query(&query).execute(&POOL).await?;
    Ok(())
}
"#;
        let found = scan_project(&[("src/main.rs", main), ("src/store.rs", store)]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rust_same_file_helper_call_is_reported() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use sqlx::PgPool;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    run(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}

async fn run(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    let query = format!("SELECT * FROM users WHERE name = '{name}'");
    sqlx::query(&query).execute(pool).await?;
    Ok(())
}
"#;
        let found = scan_project(&[("src/main.rs", main)]);
        assert_eq!(
            found,
            vec![("src/main.rs".to_string(), SQLI_FLOW.to_string(), 13)]
        );
    }

    #[test]
    fn rust_command_chain_from_request_is_reported() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use std::process::Command;

#[get("/ping")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let host = req.match_info().get("host").unwrap_or("");
    Command::new("sh").arg("-c").arg(format!("ping {host}")).output().ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main)]);
        assert_eq!(
            found,
            vec![("src/main.rs".to_string(), CMDI.to_string(), 7)]
        );
    }

    #[test]
    fn rust_command_without_shell_is_clean() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use std::process::Command;

#[get("/ping")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let host = req.match_info().get("host").unwrap_or("");
    Command::new("ping").arg(host).output().ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main)]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rust_reqwest_url_from_request_is_reported() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};

#[get("/fetch")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let url = req.match_info().get("url").unwrap_or("");
    reqwest::get(url).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main)]);
        assert_eq!(
            found,
            vec![("src/main.rs".to_string(), SSRF.to_string(), 6)]
        );
    }

    #[test]
    fn go_gin_query_param_reaching_query_is_reported() {
        let findings = scan(
            r#"name := c.Query("name")
query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
rows, err := db.QueryContext(ctx, query)"#,
            "go",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn go_echo_path_param_reaching_query_is_reported() {
        let findings = scan(
            r#"name := c.Param("name")
query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
rows, err := db.QueryContext(ctx, query)"#,
            "go",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn go_gin_bind_struct_field_reaching_query_is_reported() {
        let findings = scan(
            r#"var input UserInput
if err := c.ShouldBindJSON(&input); err != nil {
	return
}
query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", input.Name)
rows, err := db.QueryContext(ctx, query)"#,
            "go",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(6));
    }

    #[test]
    fn go_gin_parameterized_query_is_clean() {
        let findings = scan(
            r#"name := c.Query("name")
rows, err := db.QueryContext(ctx, "SELECT * FROM users WHERE name = $1", name)"#,
            "go",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_gin_param_sanitized_by_atoi_is_clean() {
        let findings = scan(
            r#"id, _ := strconv.Atoi(c.Param("id"))
query := fmt.Sprintf("SELECT * FROM users WHERE id = %d", id)
rows, err := db.QueryContext(ctx, query)"#,
            "go",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_gin_handler_to_store_cross_file_is_reported() {
        let handler = r#"package main

import "github.com/gin-gonic/gin"

func handler(c *gin.Context) {
	name := c.Query("name")
	findUser(name)
}
"#;
        let found = scan_project(&[("handler.go", handler), ("store.go", GO_STORE)]);
        assert_eq!(
            found,
            vec![("store.go".to_string(), SQLI_FLOW.to_string(), 12)]
        );
    }

    #[test]
    fn java_spring_request_param_reaching_statement_is_reported() {
        let findings = scan(
            r#"@GetMapping("/user")
public String getUser(@RequestParam String name) throws SQLException {
	String sql = "SELECT * FROM users WHERE name = '" + name + "'";
	Statement stmt = conn.createStatement();
	ResultSet rs = stmt.executeQuery(sql);
	return "ok";
}"#,
            "java",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(5));
    }

    #[test]
    fn java_spring_prepared_statement_is_clean() {
        let findings = scan(
            r#"@GetMapping("/user")
public String getUser(@RequestParam String name) throws SQLException {
	PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
	ps.setString(1, name);
	ResultSet rs = ps.executeQuery();
	return "ok";
}"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_spring_unannotated_param_is_not_seeded() {
        let findings = scan(
            r#"public String getUser(String name) throws SQLException {
	String sql = "SELECT * FROM users WHERE name = '" + name + "'";
	Statement stmt = conn.createStatement();
	ResultSet rs = stmt.executeQuery(sql);
	return "ok";
}"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_spring_controller_to_static_service_cross_file_is_reported() {
        let controller = r#"package com.example.demo;

import java.sql.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    @GetMapping("/user/{name}")
    public ResultSet getUser(@PathVariable String name) throws SQLException {
        return UserService.findByName(name);
    }
}
"#;
        let service = r#"package com.example.demo;

import java.sql.*;

public class UserService {
    private static Connection conn;

    public static ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
"#;
        let found = scan_project(&[
            ("src/UserController.java", controller),
            ("src/UserService.java", service),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/UserService.java".to_string(),
                SQLI_FLOW.to_string(),
                11
            )]
        );
    }

    #[test]
    fn java_spring_multiline_annotated_params_reaching_statement_is_reported() {
        let findings = scan(
            r#"@GetMapping("/user")
public String getUser(
        @RequestParam String name,
        @RequestParam String city) throws SQLException {
	String sql = "SELECT * FROM users WHERE city = '" + city + "'";
	Statement stmt = conn.createStatement();
	ResultSet rs = stmt.executeQuery(sql);
	return "ok";
}"#,
            "java",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(7));
    }

    #[test]
    fn java_spring_multiline_param_with_value_is_reported() {
        let findings = scan(
            r#"@GetMapping("/user")
public String getUser(
        @RequestParam("name") String name) throws SQLException {
	String sql = "SELECT * FROM users WHERE name = '" + name + "'";
	Statement stmt = conn.createStatement();
	ResultSet rs = stmt.executeQuery(sql);
	return "ok";
}"#,
            "java",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(6));
    }

    #[test]
    fn java_spring_multiline_unannotated_param_is_not_seeded() {
        let findings = scan(
            r#"@GetMapping("/user")
public String getUser(
        @RequestParam String name,
        String safe) throws SQLException {
	String sql = "SELECT * FROM users WHERE name = '" + safe + "'";
	Statement stmt = conn.createStatement();
	ResultSet rs = stmt.executeQuery(sql);
	return "ok";
}"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_spring_inline_unannotated_param_is_not_seeded() {
        let findings = scan(
            r#"public String getUser(@RequestParam String name, String safe) throws SQLException {
	String sql = "SELECT * FROM users WHERE name = '" + safe + "'";
	Statement stmt = conn.createStatement();
	ResultSet rs = stmt.executeQuery(sql);
	return "ok";
}"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_spring_multiline_prepared_statement_is_clean() {
        let findings = scan(
            r#"@GetMapping("/user")
public String getUser(
        @RequestParam String name) throws SQLException {
	PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
	ps.setString(1, name);
	ResultSet rs = ps.executeQuery();
	return "ok";
}"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_spring_multiline_controller_to_static_service_cross_file_is_reported() {
        let controller = r#"package com.example.demo;

import java.sql.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    @GetMapping("/user/{name}")
    public ResultSet getUser(
            @PathVariable String name) throws SQLException {
        return UserService.findByName(name);
    }
}
"#;
        let service = r#"package com.example.demo;

import java.sql.*;

public class UserService {
    private static Connection conn;

    public static ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
"#;
        let found = scan_project(&[
            ("src/UserController.java", controller),
            ("src/UserService.java", service),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/UserService.java".to_string(),
                SQLI_FLOW.to_string(),
                11
            )]
        );
    }

    #[test]
    fn go_external_import_is_not_resolved() {
        let main = r#"package main

import (
	"net/http"

	"github.com/other/store"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	store.FindUser(name)
}
"#;
        let found = scan_project(&[
            ("go.mod", "module example.com/shop\n"),
            ("main.go", main),
            ("store/store.go", GO_STORE),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn go_duplicate_function_names_across_siblings_are_not_resolved() {
        let handler = r#"package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	findUser(name)
}
"#;
        let found = scan_project(&[
            ("handler.go", handler),
            ("store.go", GO_STORE),
            ("extra.go", GO_STORE),
        ]);
        assert!(found.is_empty(), "{found:?}");
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
    Rust,
}

#[allow(clippy::items_after_test_module)]
fn flow_language(extension: &str) -> Option<FlowLanguage> {
    match extension {
        "js" | "ts" => Some(FlowLanguage::JavaScript),
        "py" => Some(FlowLanguage::Python),
        "java" => Some(FlowLanguage::Java),
        "go" => Some(FlowLanguage::Go),
        "rs" => Some(FlowLanguage::Rust),
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
        // Rust has no single-quoted strings (`'a` is a lifetime, `'x'` a
        // rare char literal); blanking on them would eat code.
        let is_quote = c == '"'
            || (c == '\'' && language != FlowLanguage::Rust)
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
        // Rust `format!("{name}")`-family macro strings interpolate inline
        // `{ident}` arguments; keep those visible like f-string contents.
        let rust_format = language == FlowLanguage::Rust
            && c == '"'
            && i > 1
            && chars[i - 1] == '('
            && chars[i - 2] == '!'
            && i > 2
            && (chars[i - 3].is_ascii_alphanumeric() || chars[i - 3] == '_');
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
            let opens = ((python_fstring || rust_format) && ch == '{')
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
            r#"^\s*(?:(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:\s+string)?\s*(?::=|=)\s*(?:(?:r|req|request)\s*\.\s*(?:URL\s*\.\s*Query\s*\(\s*\)\s*\.\s*Get\s*\(|FormValue\s*\(|PostFormValue\s*\(|URL\s*\.\s*Path\b)|(?:c|ctx)\s*\.\s*(?:Param|Query|DefaultQuery|QueryArray|PostForm|DefaultPostForm|PostFormArray|FormValue|QueryParam|GetHeader|Cookie)\s*\()|(?:if\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\s*:?=\s*)?(?:c|ctx)\s*\.\s*(?:Bind|BindJSON|BindQuery|BindUri|ShouldBind|ShouldBindJSON|ShouldBindQuery|ShouldBindUri|ShouldBindWith)\s*\(\s*&\s*([A-Za-z_][A-Za-z0-9_]*))"#
        }
        FlowLanguage::Rust => {
            r#"^\s*let\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^=]+)?=\s*(?:(?:req|request)\s*\.\s*(?:match_info|query_params|query_string|param|params)\s*\(|(?:params|query|form)\s*(?:\.\s*get\s*\(|\[))"#
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
        FlowLanguage::Rust => {
            r#"^\s*(?:let\s+(?:mut\s+)?)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^=]+)?=\s*([^=].*?);?\s*$"#
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
    /// Optional whole-line condition checked against the raw code (string
    /// literals included), e.g. `shell=True` or a `"sh", "-c"` prefix.
    line_requires: Option<Regex>,
}

/// Maps a matched sink name to the argument positions that carry the
/// dangerous value.
type FlowArguments = fn(&str) -> Vec<usize>;

/// Straight-line, same-file request flow shared by the SQL injection,
/// command injection, and SSRF models.
///
/// Tracks request-input variables through direct aliases and string
/// construction, drops taint when a variable is rebound to a sanitized or
/// untainted value, and reports a sink line only when a tainted identifier
/// appears in one of the sink's dangerous argument positions. Plain string
/// literal contents are ignored so text that merely looks like a variable
/// name does not count.
///
/// On top of that straight-line pass, calls to functions defined in the same
/// file are followed: when a tainted argument is passed in a parameter
/// position whose value reaches a sink inside the callee (directly or through
/// further same-file calls), the callee's sink line is reported as well. See
/// [`flow_functions`] for which definitions and calls are recognized. This
/// does not follow branches, dynamic dispatch, or other files.
#[allow(clippy::items_after_test_module)]
fn request_flow_sink_lines(
    content: &str,
    language: FlowLanguage,
    sinks: &[FlowSink],
    sanitized: fn(&str) -> bool,
) -> std::collections::HashSet<usize> {
    let lines: Vec<&str> = content.lines().collect();
    let functions = flow_functions(&lines, language);
    let summaries = flow_summaries(&lines, language, sinks, sanitized, &functions);
    let calls = FlowCalls {
        functions: &functions,
        summaries: &summaries,
        imports: &[],
    };
    let (mut sink_lines, callee_sink_lines, _) = flow_pass(
        &lines,
        0..lines.len(),
        language,
        sinks,
        sanitized,
        &[],
        true,
        Some(&calls),
    );
    sink_lines.extend(callee_sink_lines);
    for (body, seeds) in spring_annotated_seeds(&lines, language, &functions) {
        let (seeded, seeded_callee, _) = flow_pass(
            &lines,
            body,
            language,
            sinks,
            sanitized,
            &seeds,
            true,
            Some(&calls),
        );
        sink_lines.extend(seeded);
        sink_lines.extend(seeded_callee);
    }
    sink_lines
}

/// A function defined in the file, as seen by the interprocedural pass.
struct FlowFunction {
    name: String,
    params: Vec<String>,
    /// Line index of the definition header.
    header: usize,
    /// First line index after the signature: `header + 1` for a single-line
    /// header, or the line after a multi-line signature's opening brace.
    signature_end: usize,
    /// Line indices of the function body.
    body: std::ops::Range<usize>,
    /// Methods are only resolved through `this.` / `self.` (JS, Python).
    method: bool,
}

/// For each function (by index) and parameter position, the sink lines a
/// value passed in that position reaches.
type FlowSummaries = Vec<Vec<std::collections::HashSet<usize>>>;

struct FlowCalls<'a> {
    functions: &'a [FlowFunction],
    summaries: &'a FlowSummaries,
    /// Functions in other project files reachable through this file's imports.
    imports: &'a [ImportedCallee],
}

/// A function in another project file that a call in this file can resolve
/// to through an import.
struct ImportedCallee {
    /// Module binding for `binding.name(...)` calls; `None` for a function
    /// imported by name and called bare.
    receiver: Option<String>,
    /// Name used at the call site.
    name: String,
    /// Index of the file that defines the function.
    target: usize,
    /// Parameter count of the target function.
    params: usize,
    /// Per parameter, the `(file index, sink line)` pairs a value passed in
    /// that position reaches. Pairs point at the defining file of each
    /// sink, so a callee whose own imports forward the value onward
    /// contributes sink lines in those files as well.
    summaries: Vec<std::collections::HashSet<(usize, usize)>>,
}

/// Compute parameter-to-sink summaries for every recognized function. Each
/// parameter is seeded as the only tainted value and the function body is
/// run through the same flow pass; calls to other same-file functions use the
/// summaries from the previous round, so helper chains resolve over a
/// bounded number of rounds.
#[allow(clippy::items_after_test_module)]
fn flow_summaries(
    lines: &[&str],
    language: FlowLanguage,
    sinks: &[FlowSink],
    sanitized: fn(&str) -> bool,
    functions: &[FlowFunction],
) -> FlowSummaries {
    let mut summaries: FlowSummaries = functions
        .iter()
        .map(|function| vec![std::collections::HashSet::new(); function.params.len()])
        .collect();
    for _ in 0..functions.len().max(6) {
        let calls = FlowCalls {
            functions,
            summaries: &summaries,
            imports: &[],
        };
        let next: FlowSummaries = functions
            .iter()
            .map(|function| {
                function
                    .params
                    .iter()
                    .map(|param| {
                        let (mut reached, via_calls, _) = flow_pass(
                            lines,
                            function.body.clone(),
                            language,
                            sinks,
                            sanitized,
                            std::slice::from_ref(param),
                            false,
                            Some(&calls),
                        );
                        reached.extend(via_calls);
                        reached
                    })
                    .collect()
            })
            .collect();
        if next == summaries {
            break;
        }
        summaries = next;
    }
    summaries
}

/// Spring-style handler parameters (`@RequestParam`, `@PathVariable`,
/// `@RequestBody`, and friends) enter the controller already
/// attacker-controlled at the framework boundary. Returns each annotated
/// Java function's body range with its parameter names, so callers can run
/// an extra seeded pass. Only single-line headers are considered (the same
/// headers `flow_functions` parses); parameter annotations on their own
/// line are a documented gap.
#[allow(clippy::items_after_test_module)]
fn spring_annotated_seeds(
    lines: &[&str],
    language: FlowLanguage,
    functions: &[FlowFunction],
) -> Vec<(std::ops::Range<usize>, Vec<String>)> {
    if language != FlowLanguage::Java {
        return Vec::new();
    }
    // Extract only the parameter names an annotation directly marks, from the
    // whole signature window (the header line through the line before the
    // body), so annotated parameters on their own lines are seeded and an
    // unannotated parameter on the same line is not tainted by association.
    let Ok(annotated_param) = Regex::new(
        r"@(?:RequestParam|PathVariable|RequestBody|RequestHeader|ModelAttribute|CookieValue)\b\s*(?:\([^()]*\))?\s*(?:final\s+)?[A-Za-z_][A-Za-z0-9_.<>\[\], ?]*?\s+([A-Za-z_$][A-Za-z0-9_$]*)",
    ) else {
        return Vec::new();
    };
    functions
        .iter()
        .filter(|function| !function.params.is_empty())
        .filter_map(|function| {
            let seeds: Vec<String> = lines[function.header..function.signature_end]
                .iter()
                .flat_map(|line| {
                    annotated_param
                        .captures_iter(line)
                        .filter_map(|captures| {
                            captures.get(1).map(|name| name.as_str().to_string())
                        })
                        .collect::<Vec<_>>()
                })
                .collect();
            (!seeds.is_empty()).then(|| (function.body.clone(), seeds))
        })
        .collect()
}

/// One flow pass over `range`. Returns the sink lines reached directly, the
/// callee sink lines reached through same-file calls, and `(file index, sink
/// line)` pairs reached through calls into imported functions.
#[allow(clippy::items_after_test_module, clippy::too_many_arguments)]
fn flow_pass(
    lines: &[&str],
    range: std::ops::Range<usize>,
    language: FlowLanguage,
    sinks: &[FlowSink],
    sanitized: fn(&str) -> bool,
    seeds: &[String],
    track_sources: bool,
    calls: Option<&FlowCalls>,
) -> (
    std::collections::HashSet<usize>,
    std::collections::HashSet<usize>,
    Vec<(usize, usize)>,
) {
    let mut sink_lines = std::collections::HashSet::new();
    let mut callee_sink_lines = std::collections::HashSet::new();
    let mut imported_sink_lines = Vec::new();
    let (Some(source), Some(binding)) = (flow_source_regex(language), flow_binding_regex(language))
    else {
        return (sink_lines, callee_sink_lines, imported_sink_lines);
    };
    let destructure = Regex::new(
        r#"^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:req|request)\s*\.\s*(?:params|query|body)\s*;?\s*$"#,
    )
    .ok();

    let mut tainted: std::collections::HashSet<String> = seeds.iter().cloned().collect();
    for line_index in range {
        let Some(line) = lines.get(line_index) else {
            break;
        };
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

        if track_sources && language == FlowLanguage::JavaScript {
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

        if track_sources {
            if let Some(name) = source
                .captures(code)
                .and_then(|captures| captures.get(1).or_else(|| captures.get(2)))
                .map(|capture| capture.as_str().to_string())
            {
                if sanitized(code) {
                    tainted.remove(&name);
                } else {
                    tainted.insert(name);
                }
                continue;
            }
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
            if sink
                .line_requires
                .as_ref()
                .is_some_and(|required| !required.is_match(code))
            {
                return false;
            }
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

        if let Some(calls) = calls {
            for (function_index, args) in same_file_calls(&visible, line_index, language, calls) {
                let Some(params) = calls.summaries.get(function_index) else {
                    continue;
                };
                for (position, arg) in args.iter().enumerate() {
                    let carries_taint =
                        !sanitized(arg) && tainted.iter().any(|name| identifier_in(arg, name));
                    if carries_taint {
                        if let Some(reached) = params.get(position) {
                            callee_sink_lines.extend(reached.iter().copied());
                        }
                    }
                }
            }
            for (import_index, args) in imported_calls(&visible, language, calls) {
                let callee = &calls.imports[import_index];
                for (position, arg) in args.iter().enumerate() {
                    let carries_taint =
                        !sanitized(arg) && tainted.iter().any(|name| identifier_in(arg, name));
                    if carries_taint {
                        if let Some(reached) = callee.summaries.get(position) {
                            imported_sink_lines.extend(reached.iter().copied());
                        }
                    }
                }
            }
        }
    }
    (sink_lines, callee_sink_lines, imported_sink_lines)
}

/// Calls on one line that resolve to an imported function: `binding.name(...)`
/// for a module binding, or a bare `name(...)` for a function imported by
/// name. A same-file definition with the same name shadows the import.
/// `this.repo.name(...)` / `self.repo.name(...)` resolve when the
/// instance variable was assigned an imported class (`new Repo(...)` for
/// JS, `Repo(...)` or `repo.Repo(...)` for Python). Longer receiver
/// chains, keyword or spread arguments, and extra arguments are
/// skipped.
#[allow(clippy::items_after_test_module)]
fn imported_calls(
    visible: &str,
    language: FlowLanguage,
    calls: &FlowCalls,
) -> Vec<(usize, Vec<String>)> {
    let mut found = Vec::new();
    if calls.imports.is_empty() {
        return found;
    }
    let Ok(call) = Regex::new(r#"([A-Za-z_$][A-Za-z0-9_$]*)\s*\("#) else {
        return found;
    };
    let keyword_argument = Regex::new(r#"^[A-Za-z_][A-Za-z0-9_]*\s*=[^=]"#).ok();
    let is_word = |ch: char| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$';
    for captures in call.captures_iter(visible) {
        let (Some(whole), Some(name)) = (captures.get(0), captures.get(1)) else {
            continue;
        };
        let before = visible[..name.start()].trim_end();
        let receiver = if language == FlowLanguage::Rust && before.ends_with("::") {
            let rest = before[..before.len() - 2].trim_end();
            let segments: Vec<&str> = rest.split("::").map(str::trim).collect();
            // `a::f(...)` resolves through a module binding; `a::b::f(...)`
            // and longer chains resolve through nested hops when each
            // module declares the next.
            if segments.is_empty()
                || segments
                    .iter()
                    .any(|word| word.is_empty() || !word.chars().all(&is_word))
            {
                continue;
            }
            Some(segments.join("::"))
        } else {
            match before.strip_suffix('.') {
                Some(rest) => {
                    let rest = rest.trim_end();
                    let word: String = rest
                        .rsplit(|ch: char| !is_word(ch))
                        .next()
                        .unwrap_or("")
                        .to_string();
                    if word.is_empty() {
                        continue;
                    }
                    let ahead = rest[..rest.len() - word.len()].trim_end();
                    if let Some(stripped) = ahead.strip_suffix('.') {
                        // One instance-variable hop: `this.repo.find(...)`
                        // / `self.repo.find(...)`. Longer chains stay
                        // unresolved.
                        if language != FlowLanguage::JavaScript && language != FlowLanguage::Python
                        {
                            continue;
                        }
                        let owner = stripped
                            .trim_end()
                            .rsplit(|ch: char| !is_word(ch))
                            .next()
                            .unwrap_or("");
                        if owner != "this" && owner != "self" {
                            continue;
                        }
                        Some(format!("{owner}.{word}"))
                    } else {
                        Some(word)
                    }
                }
                None => {
                    if before.chars().last().is_some_and(is_word) {
                        let keyword: String = before
                            .rsplit(|ch: char| !is_word(ch))
                            .next()
                            .unwrap_or("")
                            .to_string();
                        if keyword != "return" && keyword != "await" {
                            continue;
                        }
                    }
                    if calls
                        .functions
                        .iter()
                        .any(|function| function.name == name.as_str())
                    {
                        continue;
                    }
                    None
                }
            }
        };
        let Some(import_index) = calls
            .imports
            .iter()
            .position(|callee| callee.receiver == receiver && callee.name == name.as_str())
        else {
            continue;
        };
        let args = call_arguments(visible, whole.end() - 1);
        let args: Vec<String> = if args.len() == 1 && args[0].is_empty() {
            Vec::new()
        } else {
            args
        };
        let unsupported = args.len() > calls.imports[import_index].params
            || args.iter().any(|arg| {
                arg.starts_with('*')
                    || arg.starts_with("...")
                    || keyword_argument
                        .as_ref()
                        .is_some_and(|re| language == FlowLanguage::Python && re.is_match(arg))
            });
        if unsupported {
            continue;
        }
        found.push((import_index, args));
    }
    found
}

/// Calls on one line that resolve to a recognized same-file function,
/// with their positional arguments. A bare `name(...)` resolves to a
/// function (in Java, also to a method of the file); `this.name(...)` /
/// `self.name(...)` resolves to a method. Calls on any other receiver, calls
/// with keyword, spread, or extra arguments, and the definition header
/// itself are skipped.
#[allow(clippy::items_after_test_module)]
fn same_file_calls(
    visible: &str,
    line_index: usize,
    language: FlowLanguage,
    calls: &FlowCalls,
) -> Vec<(usize, Vec<String>)> {
    let mut found = Vec::new();
    let Ok(call) = Regex::new(r#"([A-Za-z_$][A-Za-z0-9_$]*)\s*\("#) else {
        return found;
    };
    let keyword_argument = Regex::new(r#"^[A-Za-z_][A-Za-z0-9_]*\s*=[^=]"#).ok();
    for captures in call.captures_iter(visible) {
        let (Some(whole), Some(name)) = (captures.get(0), captures.get(1)) else {
            continue;
        };
        let Some(function_index) = calls
            .functions
            .iter()
            .position(|function| function.name == name.as_str())
        else {
            continue;
        };
        let function = &calls.functions[function_index];
        if function.header == line_index {
            continue;
        }
        let before = visible[..name.start()].trim_end();
        let is_word = |ch: char| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$';
        let last_word = |text: &str| -> String {
            text.rsplit(|ch: char| !is_word(ch))
                .next()
                .unwrap_or("")
                .to_string()
        };
        if before.chars().last().is_some_and(is_word) {
            // `function name(`, `def name(`, `new name(` and similar are not
            // calls; `return name(` and `await name(` are.
            let keyword = last_word(before);
            if keyword != "return" && keyword != "await" {
                continue;
            }
        }
        // For `recv.name(`: the receiver word, and whether the receiver is
        // itself reached through another `.` (e.g. `other.this.name(`).
        let receiver = before.strip_suffix('.').map(|rest| {
            let rest = rest.trim_end();
            let word = last_word(rest);
            let chained = rest[..rest.len() - word.len()].trim_end().ends_with('.');
            (word, chained)
        });
        let resolves = match (&receiver, language) {
            (None, FlowLanguage::Java) => true,
            (None, _) => !function.method,
            (Some((word, chained)), FlowLanguage::JavaScript) => {
                word == "this" && !chained && function.method
            }
            (Some((word, chained)), FlowLanguage::Java) => word == "this" && !chained,
            (Some((word, chained)), FlowLanguage::Python) => {
                word == "self" && !chained && function.method
            }
            (Some((word, chained)), FlowLanguage::Rust) if word == "self" && !chained => {
                function.method
            }
            (Some(_), FlowLanguage::Go | FlowLanguage::Rust) => false,
        };
        if !resolves {
            continue;
        }
        let args = call_arguments(visible, whole.end() - 1);
        let args: Vec<String> = if args.len() == 1 && args[0].is_empty() {
            Vec::new()
        } else {
            args
        };
        let unsupported = args.len() > function.params.len()
            || args.iter().any(|arg| {
                arg.starts_with('*')
                    || arg.starts_with("...")
                    || keyword_argument
                        .as_ref()
                        .is_some_and(|re| language == FlowLanguage::Python && re.is_match(arg))
            });
        if unsupported {
            continue;
        }
        found.push((function_index, args));
    }
    found
}

/// Function definitions the interprocedural pass can summarize.
///
/// Recognized: JS/TS `function name(...) {`, `const name = function (...) {`,
/// `const name = (...) => {`, and class methods `name(...) {`; Python
/// `def name(...):` (methods when the first parameter is `self`/`cls`); Java
/// methods and constructors whose header ends with `{`; Go `func name(...)
/// ... {` (methods with receivers are skipped); Rust `fn name(...) ->
/// ... {` (methods when the first parameter is `self`). Only simple
/// positional
/// parameters are accepted: destructuring, rest/variadic-star parameters,
/// and headers split across lines make a definition unsupported. A name
/// defined more than once in the file (overloads, redefinitions, the same
/// method name on two classes) is dropped so a call never resolves to the
/// wrong body.
#[allow(clippy::items_after_test_module)]
fn flow_functions(lines: &[&str], language: FlowLanguage) -> Vec<FlowFunction> {
    let mut functions: Vec<FlowFunction> = Vec::new();
    let mut unsupported_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    let keywords = [
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "function",
        "return",
        "with",
        "else",
        "new",
        "synchronized",
        "try",
        "do",
        "super",
        "this",
    ];
    let headers: Vec<(Regex, bool)> = match language {
        FlowLanguage::JavaScript => vec![
            (
                r#"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^()]*)\)\s*(?::\s*[^{]+)?\{\s*$"#,
                false,
            ),
            (
                r#"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::\s*[^=]+)?=\s*(?:async\s+)?(?:function\s*[A-Za-z0-9_$]*\s*\(([^()]*)\)|\(([^()]*)\)\s*(?::\s*[^=]+)?=>)\s*\{\s*$"#,
                false,
            ),
            (
                r#"^\s*(?:(?:public|private|protected|static|async|readonly)\s+)*([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^()]*)\)\s*(?::\s*[^{]+)?\{\s*$"#,
                true,
            ),
        ],
        FlowLanguage::Python => vec![(
            r#"^(\s*)(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]*)\)\s*(?:->\s*[^:]+)?:\s*$"#,
            false,
        )],
        FlowLanguage::Java => vec![(
            r#"^\s*(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)*(?:<[^>]+>\s+)?(?:[A-Za-z_][A-Za-z0-9_.<>\[\], ?]*?\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]*)\)\s*(?:throws\s+[A-Za-z0-9_.,\s]+?)?\s*\{\s*$"#,
            false,
        )],
        FlowLanguage::Go => vec![(
            r#"^\s*func\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]*)\)[^{]*\{\s*$"#,
            false,
        )],
        FlowLanguage::Rust => vec![(
            r#"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\(([^()]*)\)\s*(?:->\s*[^{]+?)?\{\s*$"#,
            false,
        )],
    }
    .into_iter()
    .filter_map(|(pattern, method)| Regex::new(pattern).ok().map(|re| (re, method)))
    .collect();
    let annotation = Regex::new(r#"@[A-Za-z_][A-Za-z0-9_.]*(?:\([^()]*\))?\s*"#).ok();
    let header_start = Regex::new(
        r#"^\s*(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)*(?:[A-Za-z_][A-Za-z0-9_.<>\[\], ?]*?\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\([^()]*$"#,
    )
    .ok();
    let definition_like = Regex::new(
        r#"^\s*(?:(?:export\s+)?(?:async\s+)?function\s*\*?\s*|(?:async\s+)?def\s+|func\s+|(?:pub\s+)?(?:async\s+)?fn\s+)([A-Za-z_$][A-Za-z0-9_$]*)\s*\("#,
    )
    .ok();

    for (index, line) in lines.iter().enumerate() {
        let code = if language == FlowLanguage::Python {
            line.split('#').next().unwrap_or("")
        } else {
            line
        };
        let visible = blank_plain_strings(code, language);
        let header_text = match (language, annotation.as_ref()) {
            (FlowLanguage::Java, Some(annotation)) => {
                annotation.replace_all(&visible, "").to_string()
            }
            _ => visible.clone(),
        };
        // Java method signatures may span several lines (annotations on their
        // own parameter lines). Assemble a bounded join of the following lines
        // when the stripped line opens a parameter list it does not close, and
        // match the header against the joined text. Line indexes are kept:
        // `header` stays the first line and the brace scan below still finds
        // the body.
        let mut joined: Option<String> = None;
        let mut joined_end: Option<usize> = None;
        if language == FlowLanguage::Java {
            if let (Some(start), Some(annotation)) = (header_start.as_ref(), annotation.as_ref()) {
                if start.is_match(&header_text) {
                    let mut text = header_text.clone();
                    let mut depth = header_text.matches('(').count() as i64
                        - header_text.matches(')').count() as i64;
                    let mut next_index = index;
                    while depth > 0 && next_index + 1 < lines.len() && next_index - index < 8 {
                        next_index += 1;
                        let following = blank_plain_strings(lines[next_index], language);
                        let following = annotation.replace_all(&following, "");
                        depth += following.matches('(').count() as i64
                            - following.matches(')').count() as i64;
                        text.push(' ');
                        text.push_str(&following);
                    }
                    if depth == 0 {
                        joined = Some(text);
                        joined_end = Some(next_index + 1);
                    }
                }
            }
        }
        let matched = headers.iter().find_map(|(re, method)| {
            re.captures(joined.as_deref().unwrap_or(&header_text))
                .map(|captures| {
                    if language == FlowLanguage::Python {
                        let indent = captures.get(1).map_or(0, |m| m.as_str().len());
                        (
                            captures.get(2).map(|m| m.as_str().to_string()),
                            captures.get(3).map(|m| m.as_str().to_string()),
                            *method,
                            indent,
                        )
                    } else {
                        let params = captures.get(2).or_else(|| captures.get(3));
                        (
                            captures.get(1).map(|m| m.as_str().to_string()),
                            params.map(|m| m.as_str().to_string()),
                            *method,
                            0,
                        )
                    }
                })
        });
        let Some((Some(name), Some(params), mut method, indent)) = matched else {
            // A definition this pass cannot parse still shadows the name.
            if let Some(name) = definition_like
                .as_ref()
                .and_then(|re| re.captures(&visible))
                .and_then(|captures| captures.get(1))
            {
                unsupported_names.insert(name.as_str().to_string());
            }
            continue;
        };
        if keywords.contains(&name.as_str()) {
            continue;
        }
        let Some(mut params) = flow_parameters(&params, language) else {
            unsupported_names.insert(name);
            continue;
        };
        if language == FlowLanguage::Python
            && params
                .first()
                .is_some_and(|first| first == "self" || first == "cls")
        {
            params.remove(0);
            method = true;
        }
        if language == FlowLanguage::Rust && params.first().is_some_and(|first| first == "self") {
            params.remove(0);
            method = true;
        }
        let body = match language {
            FlowLanguage::Python => {
                let mut end = index + 1;
                for (offset, next) in lines.iter().enumerate().skip(index + 1) {
                    let trimmed = next.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let next_indent = next.len() - next.trim_start().len();
                    if next_indent <= indent {
                        break;
                    }
                    end = offset + 1;
                }
                index + 1..end
            }
            _ => {
                let mut depth = 0i64;
                let mut opened = false;
                let mut end = None;
                for (offset, next) in lines.iter().enumerate().skip(index) {
                    let text = blank_plain_strings(next, language);
                    let text = text.split("//").next().unwrap_or("");
                    for ch in text.chars() {
                        match ch {
                            '{' => depth += 1,
                            '}' => depth -= 1,
                            _ => {}
                        }
                    }
                    // Multi-line signatures contribute no brace on the header
                    // line, so only close once the opening brace was seen.
                    if depth > 0 {
                        opened = true;
                    }
                    if opened && depth <= 0 {
                        end = Some(offset);
                        break;
                    }
                }
                match end {
                    Some(end) if end > index => index + 1..end,
                    _ => {
                        unsupported_names.insert(name);
                        continue;
                    }
                }
            }
        };
        functions.push(FlowFunction {
            name,
            params,
            header: index,
            signature_end: joined_end.unwrap_or(index + 1),
            body,
            method,
        });
    }

    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for function in &functions {
        *counts.entry(function.name.clone()).or_default() += 1;
    }
    functions.retain(|function| {
        counts.get(&function.name) == Some(&1) && !unsupported_names.contains(&function.name)
    });
    functions
}

/// Parse a parameter list into plain names, or `None` when any parameter is
/// not a simple positional identifier.
#[allow(clippy::items_after_test_module)]
fn flow_parameters(list: &str, language: FlowLanguage) -> Option<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    for ch in list.chars() {
        match ch {
            '<' | '[' | '{' | '(' => {
                depth += 1;
                current.push(ch);
            }
            '>' | ']' | '}' | ')' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                parts.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    parts.push(current);
    let parts: Vec<String> = parts
        .into_iter()
        .map(|part| part.trim().to_string())
        .collect();
    if parts.len() == 1 && parts[0].is_empty() {
        return Some(Vec::new());
    }
    let is_identifier = |name: &str| {
        !name.is_empty()
            && !name.starts_with(|ch: char| ch.is_ascii_digit())
            && name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
    };
    let mut names = Vec::new();
    for part in parts {
        if part.is_empty() || part.starts_with('*') || part.starts_with("...") {
            return None;
        }
        let name = match language {
            FlowLanguage::JavaScript | FlowLanguage::Python => {
                let name = part.split('=').next().unwrap_or("");
                let name = name.split(':').next().unwrap_or("").trim();
                let name = name.trim_end_matches('?');
                name.to_string()
            }
            FlowLanguage::Java => {
                let part = part.trim_start_matches("final ").trim();
                if part.contains("...") {
                    return None;
                }
                part.rsplit(char::is_whitespace)
                    .next()
                    .unwrap_or("")
                    .to_string()
            }
            FlowLanguage::Go => {
                if part.contains("...") {
                    return None;
                }
                part.split_whitespace().next().unwrap_or("").to_string()
            }
            FlowLanguage::Rust => {
                let part = part.trim();
                if matches!(part, "self" | "&self" | "&mut self" | "mut self") {
                    "self".to_string()
                } else {
                    part.trim_start_matches("mut ")
                        .split(':')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string()
                }
            }
        };
        if !is_identifier(&name) {
            return None;
        }
        names.push(name);
    }
    Some(names)
}

/// Sink lines found in one file through calls from other project files, per
/// flow family.
#[derive(Default)]
struct CrossFileSinkLines {
    sql: std::collections::HashSet<usize>,
    command: std::collections::HashSet<usize>,
    ssrf: std::collections::HashSet<usize>,
}

/// How a caller file binds an imported file.
enum ImportBinding {
    /// `const service = require('../service')`, `import * as s from`,
    /// `import service` / `from . import service`: calls look like
    /// `binding.name(...)`. `exported_only` restricts the visible names to
    /// capitalized ones (Go cross-package calls).
    Module {
        binding: String,
        target: usize,
        exported_only: bool,
    },
    /// `const { f } = require(...)`, `import { f as g } from`,
    /// `from .service import f as g`: calls look like `local(...)`.
    Function {
        local: String,
        exported: String,
        target: usize,
    },
    /// `from .service import *`, Go `import . "pkg"`: every exported
    /// name of `target` is callable bare. Expanded into Function bindings
    /// once exports are known, so later passes never see this variant.
    Star { target: usize },
}

/// Cross-file request flow for JS/TS, Python, Java, Go, and Rust projects.
///
/// Each file's functions are summarized with the same per-parameter pass as
/// the same-file engine. JS/TS and Python imports are resolved to project
/// files (`require`/`import` of `./x`, `../x`, `x/index`; Python `from .x
/// import f`, `from .x import *`, `from x import f`, `import x as m` resolved next to the
/// importing file or at the project root; multi-line JS import, require,
/// and re-export declarations are joined before matching, as are
/// parenthesized Python from-imports). Go files in one directory share a
/// package namespace, so a bare call resolves to a function defined in a
/// sibling file; `import "mod/pkg"` (optionally aliased, single or grouped
/// form) resolves through the module path of the nearest `go.mod`, and only
/// exported (capitalized) names are visible across packages. Imports outside
/// the file's own module resolve through `replace` directives that map the
/// module path to a local directory, or through another `go.mod` under the
/// project root whose module path prefixes the import; the module cache and
/// `vendor/` (excluded from scans) are not followed. Java classes in one
/// package refer to each other by class name (`Service.find(...)`), and
/// `import a.b.C;` resolves to the one project file whose package and class
/// name match; `import a.b.*;` resolves every uniquely named class in that
/// package, `import static a.b.C.f;` resolves the bare call `f(...)`, and
/// `import static a.b.C.*;` resolves every static method of `C` the same
/// way. Only static, non-private methods resolve. Rust `mod store;`
/// resolves to the sibling `store.rs`/`store/mod.rs` for `store::f(...)`
/// path calls, `a::b::f(...)` and longer chains resolve through nested
/// hops when each module declares the next, and
/// `use crate::`/`self::`/`super::` paths (with `as`
/// aliases or a trailing `::*` glob) resolve from the nearest ancestor
/// holding `main.rs`/`lib.rs`; only `pub` free functions are visible. A
/// request-tainted
/// argument passed to an exported function of another file in a position
/// that reaches a sink reports the sink line in that file. Import hops are
/// followed through a converging fixpoint: a callee whose own imports
/// forward the value onward contributes the sinks those imports reach, so a
/// call chain across any number of import hops resolves (one propagation
/// round per module bounds the loop); the callee's same-file helpers are
/// included through its summaries, and import cycles simply stop changing.
/// JS/TS re-exports and Rust `pub use` re-exports (named,
/// `as` alias, grouped, or `*` glob, with `crate::`/`self::`/`super::` or
/// bare relative paths) resolve through a bounded fixpoint, so chained
/// re-exports (a barrel re-exporting from another barrel) collapse toward
/// the defining module pass by pass, iterated to convergence; in both
/// languages a name offered by two sources at any pass resolves to neither,
/// and a re-export cycle offers nothing. Calls through instance
/// variables resolve for JS (`this.repo.m(...)` when the variable is
/// assigned `new Repo(...)` and `Repo` is a whole-module or class
/// import) and for Python (`self.repo.m(...)` when the variable is
/// assigned `Repo(...)` from `from .repo import Repo`, or
/// `repo.Repo(...)` with `import repo`); methods match by name within
/// the imported file.
/// Package imports (JS), dynamic `require`,
/// `_test.go` files, and other instance receivers are not
/// resolved, and a callable name offered by two different files resolves
/// to neither.
#[allow(clippy::items_after_test_module)]
fn cross_file_flow_sinks(
    files: &[std::path::PathBuf],
    project_root: &Path,
) -> std::collections::HashMap<std::path::PathBuf, CrossFileSinkLines> {
    let mut result: std::collections::HashMap<std::path::PathBuf, CrossFileSinkLines> =
        std::collections::HashMap::new();
    struct Module {
        path: std::path::PathBuf,
        language: FlowLanguage,
        content: String,
    }
    let modules: Vec<Module> = files
        .iter()
        .filter_map(|path| {
            let language = flow_language(&file_extension(path))?;
            let content = std::fs::read_to_string(path).ok()?;
            Some(Module {
                path: path.clone(),
                language,
                content,
            })
        })
        .collect();
    if modules.len() < 2 {
        return result;
    }
    let index_of: std::collections::HashMap<std::path::PathBuf, usize> = modules
        .iter()
        .enumerate()
        .filter_map(|(index, module)| {
            std::fs::canonicalize(&module.path)
                .ok()
                .map(|canonical| (canonical, index))
        })
        .collect();
    let root = std::fs::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());

    let lines: Vec<Vec<&str>> = modules
        .iter()
        .map(|module| module.content.lines().collect())
        .collect();
    let functions: Vec<Vec<FlowFunction>> = modules
        .iter()
        .zip(&lines)
        .map(|(module, lines)| flow_functions(lines, module.language))
        .collect();
    let exports: Vec<std::collections::HashMap<String, usize>> = modules
        .iter()
        .zip(&lines)
        .zip(&functions)
        .map(|((module, lines), functions)| flow_exports(lines, module.language, functions))
        .collect();
    let mut bindings: Vec<Vec<ImportBinding>> = modules
        .iter()
        .zip(&lines)
        .map(|(module, lines)| flow_imports(lines, module.language, &module.path, &root, &index_of))
        .collect();
    // Re-exporting ("barrel") modules: named (`export { f } from './x'`) and
    // glob (`export * from './x'`) re-exports make the source function
    // visible under the barrel's path. Chained barrels (a barrel
    // re-exporting from another barrel) resolve through a bounded fixpoint:
    // each pass collapses one hop toward the defining module. A name
    // offered by two different sources at any pass resolves to neither, a
    // re-export cycle offers nothing, and chains longer than the pass
    // bound stay unresolved.
    let js_reexports_pass = |old: &[std::collections::HashMap<String, (usize, String)>]| {
        modules
            .iter()
            .enumerate()
            .zip(&lines)
            .map(|((index, module), lines)| {
                let mut map = std::collections::HashMap::new();
                if module.language != FlowLanguage::JavaScript {
                    return map;
                }
                let Some(dir) = module.path.parent() else {
                    return map;
                };
                let mut candidates: std::collections::HashMap<String, Vec<(usize, String)>> =
                    std::collections::HashMap::new();
                for declaration in js_reexports(lines) {
                    match declaration {
                        JsReexport::Named { spec, source, name } => {
                            if let Some(target) = resolve_js_specifier(dir, &spec, &index_of) {
                                // A barrel-of-barrel link collapses to the
                                // defining module found in the previous pass.
                                if let Some((definer, original)) = old[target].get(&source) {
                                    candidates
                                        .entry(name)
                                        .or_default()
                                        .push((*definer, original.clone()));
                                } else {
                                    candidates.entry(name).or_default().push((target, source));
                                }
                            }
                        }
                        JsReexport::Namespace { .. } => {
                            // Handled by the namespace map below, which
                            // binds the name as a module, not a function.
                        }
                        JsReexport::Glob { spec } => {
                            if let Some(target) = resolve_js_specifier(dir, &spec, &index_of) {
                                for name in exports[target].keys() {
                                    candidates
                                        .entry(name.clone())
                                        .or_default()
                                        .push((target, name.clone()));
                                }
                                for (name, (definer, original)) in &old[target] {
                                    candidates
                                        .entry(name.clone())
                                        .or_default()
                                        .push((*definer, original.clone()));
                                }
                            }
                        }
                    }
                }
                for (name, mut offers) in candidates {
                    offers.sort();
                    offers.dedup();
                    // A link pointing back at this module is a re-export
                    // cycle: it offers nothing.
                    if offers.len() == 1 && offers[0].0 != index {
                        map.insert(name, offers[0].clone());
                    }
                }
                map
            })
            .collect::<Vec<_>>()
    };
    let empty_maps: Vec<std::collections::HashMap<String, (usize, String)>> = (0..modules.len())
        .map(|_| std::collections::HashMap::new())
        .collect();
    // Iterate until the maps stop changing: each pass collapses one hop
    // toward the defining module, so chains of any depth converge within
    // one pass per module and re-export cycles simply stop changing.
    let mut reexport_maps = js_reexports_pass(&empty_maps);
    for _ in 0..modules.len().max(4) {
        let next = js_reexports_pass(&reexport_maps);
        if next == reexport_maps {
            reexport_maps = next;
            break;
        }
        reexport_maps = next;
    }
    // Namespace re-exports (`export * as ns from './x'`): the barrel
    // offers `ns` as a module bound to the re-exported file, so
    // `import { ns } from './barrel'` followed by `ns.f(...)` resolves
    // like a whole-module import of that file. Single pass: a name
    // offered by two sources, or pointing at the barrel itself,
    // resolves to neither.
    let namespace_maps: Vec<std::collections::HashMap<String, usize>> = modules
        .iter()
        .enumerate()
        .zip(&lines)
        .map(|((index, module), lines)| {
            let mut map = std::collections::HashMap::new();
            if module.language != FlowLanguage::JavaScript {
                return map;
            }
            let Some(dir) = module.path.parent() else {
                return map;
            };
            let mut offers: std::collections::HashMap<String, Vec<usize>> =
                std::collections::HashMap::new();
            for declaration in js_reexports(lines) {
                if let JsReexport::Namespace { spec, name } = declaration {
                    if let Some(target) = resolve_js_specifier(dir, &spec, &index_of) {
                        offers.entry(name).or_default().push(target);
                    }
                }
            }
            for (name, mut targets) in offers {
                targets.sort();
                targets.dedup();
                if targets.len() == 1 && targets[0] != index {
                    map.insert(name, targets[0]);
                }
            }
            map
        })
        .collect();
    for (index, module) in modules.iter().enumerate() {
        if module.language != FlowLanguage::JavaScript {
            continue;
        }
        for binding in &mut bindings[index] {
            let replacement = if let ImportBinding::Function {
                local,
                exported,
                target,
            } = binding
            {
                if modules[*target].language == FlowLanguage::JavaScript
                    && !exports[*target].contains_key(exported)
                {
                    if let Some((new_target, source)) = reexport_maps[*target].get(exported) {
                        *target = *new_target;
                        *exported = source.clone();
                        None
                    } else {
                        namespace_maps[*target].get(exported).map(|ns_target| {
                            ImportBinding::Module {
                                binding: local.clone(),
                                target: *ns_target,
                                exported_only: false,
                            }
                        })
                    }
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(new_binding) = replacement {
                *binding = new_binding;
            }
        }
    }
    let mut by_dir: std::collections::HashMap<std::path::PathBuf, Vec<usize>> =
        std::collections::HashMap::new();
    for (canonical, index) in &index_of {
        if let Some(parent) = canonical.parent() {
            by_dir.entry(parent.to_path_buf()).or_default().push(*index);
        }
    }
    // Rust re-exporting modules: `pub use a::f;` (named, `as` alias,
    // grouped, or a `*` glob) makes the source function visible under the
    // re-exporting module's path. Chained re-exports (a module re-exporting
    // a name it only re-exports) resolve through a bounded fixpoint: each
    // pass collapses one hop toward the defining module. A name offered by
    // two different sources at any pass resolves to neither, and a
    // re-export cycle offers nothing.
    let rust_reexports_pass = |old: &[std::collections::HashMap<String, (usize, String)>]| {
        modules
            .iter()
            .enumerate()
            .zip(&lines)
            .map(|((index, module), lines)| {
                let mut offers: std::collections::HashMap<String, Vec<(usize, String)>> =
                    std::collections::HashMap::new();
                if module.language != FlowLanguage::Rust {
                    return std::collections::HashMap::new();
                }
                let Some(own_dir) = module
                    .path
                    .parent()
                    .and_then(|parent| std::fs::canonicalize(parent).ok())
                else {
                    return std::collections::HashMap::new();
                };
                let Some(module_dir) = rust_module_dir(&module.path) else {
                    return std::collections::HashMap::new();
                };
                let is_mod_rs = module.path.file_stem().is_some_and(|stem| stem == "mod");
                let super_base = if is_mod_rs {
                    own_dir.parent().map(|parent| parent.to_path_buf())
                } else {
                    Some(own_dir.clone())
                };
                let crate_base = rust_crate_root(&own_dir, &root);
                let resolve_module = |base: &Path, segments: &[&str]| -> Option<usize> {
                    let mut target = base.to_path_buf();
                    for segment in segments {
                        target.push(segment);
                    }
                    let candidates: Vec<std::path::PathBuf> = if segments.is_empty() {
                        vec![base.join("lib.rs"), base.join("main.rs")]
                    } else {
                        vec![target.with_extension("rs"), target.join("mod.rs")]
                    };
                    candidates.into_iter().find_map(|candidate| {
                        std::fs::canonicalize(candidate)
                            .ok()
                            .and_then(|canonical| index_of.get(&canonical).copied())
                            .filter(|&found| modules[found].language == FlowLanguage::Rust)
                    })
                };
                for declaration in rust_declarations(lines) {
                    let RustDeclaration::Use {
                        segments,
                        alias,
                        reexport,
                    } = declaration
                    else {
                        continue;
                    };
                    if !reexport {
                        continue;
                    }
                    let skip = usize::from(matches!(
                        segments.first().map(String::as_str),
                        Some("crate" | "self" | "super")
                    ));
                    let Some(base) = (match segments.first().map(String::as_str) {
                        Some("crate") => crate_base.clone(),
                        Some("self") => Some(module_dir.clone()),
                        Some("super") => super_base.clone(),
                        // A bare path is relative to the current module; an
                        // external crate name simply resolves to nothing.
                        _ => Some(module_dir.clone()),
                    }) else {
                        continue;
                    };
                    let rest: Vec<&str> = segments[skip..].iter().map(String::as_str).collect();
                    if rest.last() == Some(&"*") {
                        let module_path = &rest[..rest.len() - 1];
                        if let Some(source) = resolve_module(&base, module_path) {
                            for name in exports[source].keys() {
                                offers
                                    .entry(name.clone())
                                    .or_default()
                                    .push((source, name.clone()));
                            }
                            for (name, (definer, original)) in &old[source] {
                                offers
                                    .entry(name.clone())
                                    .or_default()
                                    .push((*definer, original.clone()));
                            }
                        }
                        continue;
                    }
                    let Some(last) = rest.last().copied() else {
                        continue;
                    };
                    if let Some(source) = resolve_module(&base, &rest[..rest.len() - 1]) {
                        if exports[source].contains_key(last) {
                            offers
                                .entry(alias.clone().unwrap_or_else(|| last.to_string()))
                                .or_default()
                                .push((source, last.to_string()));
                        } else if let Some((definer, original)) = old[source].get(last) {
                            // A chained re-export collapses to the defining
                            // module found in the previous pass.
                            offers
                                .entry(alias.clone().unwrap_or_else(|| last.to_string()))
                                .or_default()
                                .push((*definer, original.clone()));
                        }
                    }
                }
                offers
                    .into_iter()
                    // A link pointing back at this module is a re-export
                    // cycle: it offers nothing.
                    .filter(|(_, found)| found.len() == 1 && found[0].0 != index)
                    .map(|(name, found)| (name, found[0].clone()))
                    .collect()
            })
            .collect::<Vec<_>>()
    };
    let empty_rust_maps: Vec<std::collections::HashMap<String, (usize, String)>> = (0..modules
        .len())
        .map(|_| std::collections::HashMap::new())
        .collect();
    let mut rust_reexport_maps = rust_reexports_pass(&empty_rust_maps);
    for _ in 0..modules.len().max(4) {
        let next = rust_reexports_pass(&rust_reexport_maps);
        if next == rust_reexport_maps {
            rust_reexport_maps = next;
            break;
        }
        rust_reexport_maps = next;
    }
    // Multi-module Go repositories: an import outside a file's own module
    // resolves through a `replace` directive to a local directory or through
    // another go.mod under the project root whose module path prefixes it.
    let go_modules: Vec<(std::path::PathBuf, String)> = if modules
        .iter()
        .any(|module| module.language == FlowLanguage::Go)
    {
        go_nested_modules(&root)
    } else {
        Vec::new()
    };
    // Same-package siblings need no import statement: Go files in one
    // directory share a namespace, and Java classes in one package refer to
    // each other by class name. Go cross-package imports resolve through the
    // module path of the nearest go.mod; a Java `import a.b.C;` matches the
    // one file whose package and class name line up.
    for (index, module) in modules.iter().enumerate() {
        let is_test = module
            .path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().ends_with("_test.go"));
        let Some(own_dir) = module
            .path
            .parent()
            .and_then(|parent| std::fs::canonicalize(parent).ok())
        else {
            continue;
        };
        match module.language {
            FlowLanguage::Go => {
                if is_test {
                    continue;
                }
                if let Some(package) = go_package_clause(&lines[index]) {
                    if let Some(siblings) = by_dir.get(&own_dir) {
                        for &sibling in siblings {
                            if sibling == index
                                || modules[sibling].language != FlowLanguage::Go
                                || modules[sibling].path.file_name().is_some_and(|name| {
                                    name.to_string_lossy().ends_with("_test.go")
                                })
                                || go_package_clause(&lines[sibling]).as_deref()
                                    != Some(package.as_str())
                            {
                                continue;
                            }
                            for name in exports[sibling].keys() {
                                bindings[index].push(ImportBinding::Function {
                                    local: name.clone(),
                                    exported: name.clone(),
                                    target: sibling,
                                });
                            }
                        }
                    }
                }
                let Some((module_root, module_path)) = go_module_root_and_path(&own_dir, &root)
                else {
                    continue;
                };
                let replaces = go_replace_dirs(&module_root.join("go.mod"));
                for (alias, spec) in go_import_specs(&lines[index]) {
                    let relative = match spec.strip_prefix(module_path.as_str()) {
                        Some("") => std::path::PathBuf::new(),
                        Some(rest) if rest.starts_with('/') => std::path::PathBuf::from(&rest[1..]),
                        // Outside the file's own module: a `replace` to a
                        // local directory or another go.mod under the project
                        // root can still map the import into the tree.
                        _ => {
                            match go_external_import_dir(
                                &spec,
                                &module_root,
                                &replaces,
                                &go_modules,
                            ) {
                                Some(dir) => dir,
                                None => continue,
                            }
                        }
                    };
                    let Ok(target_dir) = std::fs::canonicalize(module_root.join(&relative)) else {
                        continue;
                    };
                    let Some(targets) = by_dir.get(&target_dir) else {
                        continue;
                    };
                    let targets: Vec<usize> = targets
                        .iter()
                        .copied()
                        .filter(|&target| {
                            modules[target].language == FlowLanguage::Go
                                && !modules[target].path.file_name().is_some_and(|name| {
                                    name.to_string_lossy().ends_with("_test.go")
                                })
                        })
                        .collect();
                    if targets.is_empty() {
                        continue;
                    }
                    let binding = match alias {
                        Some(alias) => alias,
                        None => {
                            let mut clauses = targets
                                .iter()
                                .filter_map(|&target| go_package_clause(&lines[target]));
                            let Some(first) = clauses.next() else {
                                continue;
                            };
                            if clauses.any(|clause| clause != first) {
                                continue;
                            }
                            first
                        }
                    };
                    if binding == "." {
                        // Dot import: the package's exported names are
                        // callable bare. Expanded once exports are known.
                        for target in targets {
                            bindings[index].push(ImportBinding::Star { target });
                        }
                        continue;
                    }
                    for target in targets {
                        bindings[index].push(ImportBinding::Module {
                            binding: binding.clone(),
                            target,
                            exported_only: true,
                        });
                    }
                }
            }
            FlowLanguage::Java => {
                let package = java_package_clause(&lines[index]);
                let mut class_counts: std::collections::HashMap<String, usize> =
                    std::collections::HashMap::new();
                let mut siblings = Vec::new();
                if let Some(same_dir) = by_dir.get(&own_dir) {
                    for &sibling in same_dir {
                        if sibling == index
                            || modules[sibling].language != FlowLanguage::Java
                            || java_package_clause(&lines[sibling]) != package
                        {
                            continue;
                        }
                        if let Some(class) =
                            java_class_name(&lines[sibling], &modules[sibling].path)
                        {
                            *class_counts.entry(class.clone()).or_default() += 1;
                            siblings.push((class, sibling));
                        }
                    }
                }
                for (class, sibling) in siblings {
                    if class_counts.get(&class) == Some(&1) {
                        bindings[index].push(ImportBinding::Module {
                            binding: class,
                            target: sibling,
                            exported_only: false,
                        });
                    }
                }
                // The one other file declaring `class` in `package`; two
                // files offering the same class resolve to neither.
                let class_file = |package: &str, class: &str| -> Option<usize> {
                    let matches: Vec<usize> = modules
                        .iter()
                        .enumerate()
                        .filter(|(other, other_module)| {
                            *other != index
                                && other_module.language == FlowLanguage::Java
                                && java_package_clause(&lines[*other]).as_deref() == Some(package)
                                && java_class_name(&lines[*other], &other_module.path).as_deref()
                                    == Some(class)
                        })
                        .map(|(other, _)| other)
                        .collect();
                    // `then`, not `then_some`: the match list is empty for
                    // imports that resolve outside the project (jdk, libraries),
                    // and `then_some` would index it eagerly and panic.
                    if matches.len() == 1 {
                        matches.first().copied()
                    } else {
                        None
                    }
                };
                for import in java_imports(&lines[index]) {
                    match import {
                        JavaImport::Class { package, class } => {
                            if let Some(target) = class_file(&package, &class) {
                                bindings[index].push(ImportBinding::Module {
                                    binding: class,
                                    target,
                                    exported_only: false,
                                });
                            }
                        }
                        JavaImport::PackageWildcard { package } => {
                            // `import a.b.*;` names every class of the
                            // package; a class offered by two files resolves
                            // to neither.
                            let mut by_class: std::collections::HashMap<String, Vec<usize>> =
                                std::collections::HashMap::new();
                            for (other, other_module) in modules.iter().enumerate() {
                                if other == index
                                    || other_module.language != FlowLanguage::Java
                                    || java_package_clause(&lines[other]).as_deref()
                                        != Some(package.as_str())
                                {
                                    continue;
                                }
                                if let Some(class) =
                                    java_class_name(&lines[other], &other_module.path)
                                {
                                    by_class.entry(class).or_default().push(other);
                                }
                            }
                            for (class, files) in by_class {
                                if files.len() == 1 {
                                    bindings[index].push(ImportBinding::Module {
                                        binding: class,
                                        target: files[0],
                                        exported_only: false,
                                    });
                                }
                            }
                        }
                        JavaImport::StaticMember {
                            package,
                            class,
                            member,
                        } => {
                            // `import static a.b.C.f;` makes the bare call
                            // `f(...)` resolve to the static method; only
                            // static, non-private methods are exported.
                            if let Some(target) = class_file(&package, &class) {
                                if exports[target].contains_key(member.as_str()) {
                                    bindings[index].push(ImportBinding::Function {
                                        local: member.clone(),
                                        exported: member,
                                        target,
                                    });
                                }
                            }
                        }
                        JavaImport::StaticWildcard { package, class } => {
                            if let Some(target) = class_file(&package, &class) {
                                for name in exports[target].keys() {
                                    bindings[index].push(ImportBinding::Function {
                                        local: name.clone(),
                                        exported: name.clone(),
                                        target,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            FlowLanguage::Rust => {
                // `mod store;` names a sibling file (`store.rs` or
                // `store/mod.rs`); calls look like `store::find_user(...)`,
                // or `api::users::lookup(...)` through one nested hop.
                // `use crate::a::b::f;` (also `self::`/`super::`, an `as`
                // alias, or a trailing `::*` glob) resolves from the crate
                // root and makes the bare call `f(...)` resolve; a path
                // whose last segment names a module binds the module
                // instead. Only `pub` free functions are visible.
                let Some(module_dir) = rust_module_dir(&module.path) else {
                    continue;
                };
                let is_mod_rs = module.path.file_stem().is_some_and(|stem| stem == "mod");
                let super_base = if is_mod_rs {
                    own_dir.parent().map(|parent| parent.to_path_buf())
                } else {
                    Some(own_dir.clone())
                };
                let crate_base = rust_crate_root(&own_dir, &root);
                let resolve_module = |base: &Path, segments: &[&str]| -> Option<usize> {
                    let mut target = base.to_path_buf();
                    for segment in segments {
                        target.push(segment);
                    }
                    let candidates: Vec<std::path::PathBuf> = if segments.is_empty() {
                        vec![base.join("lib.rs"), base.join("main.rs")]
                    } else {
                        vec![target.with_extension("rs"), target.join("mod.rs")]
                    };
                    candidates.into_iter().find_map(|candidate| {
                        std::fs::canonicalize(candidate)
                            .ok()
                            .and_then(|canonical| index_of.get(&canonical).copied())
                            .filter(|&found| modules[found].language == FlowLanguage::Rust)
                    })
                };
                for declaration in rust_declarations(&lines[index]) {
                    let (mut segments, alias) = match declaration {
                        RustDeclaration::Mod(name) => {
                            if let Some(target) = resolve_module(&module_dir, &[name.as_str()]) {
                                bindings[index].push(ImportBinding::Module {
                                    binding: name,
                                    target,
                                    exported_only: false,
                                });
                            }
                            continue;
                        }
                        RustDeclaration::Use {
                            segments, alias, ..
                        } => (segments, alias),
                    };
                    let Some(prefix) = segments.first().map(String::as_str) else {
                        continue;
                    };
                    let Some(base) = (match prefix {
                        "crate" => crate_base.clone(),
                        "self" => Some(module_dir.clone()),
                        "super" => super_base.clone(),
                        _ => None,
                    }) else {
                        continue;
                    };
                    segments.remove(0);
                    let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
                    if segments.last() == Some(&"*") {
                        // `use crate::store::*;` imports every `pub fn`.
                        let module_path = &segments[..segments.len() - 1];
                        if let Some(target) = resolve_module(&base, module_path) {
                            for name in exports[target].keys() {
                                bindings[index].push(ImportBinding::Function {
                                    local: name.clone(),
                                    exported: name.clone(),
                                    target,
                                });
                            }
                        }
                        continue;
                    }
                    let Some(last) = segments.last().copied() else {
                        continue;
                    };
                    // A path ending in a module binds the module; otherwise
                    // the last segment is the function and the rest is the
                    // module path.
                    if let Some(target) = resolve_module(&base, &segments) {
                        bindings[index].push(ImportBinding::Module {
                            binding: alias.clone().unwrap_or_else(|| last.to_string()),
                            target,
                            exported_only: false,
                        });
                        continue;
                    }
                    if let Some(target) = resolve_module(&base, &segments[..segments.len() - 1]) {
                        if exports[target].contains_key(last) {
                            bindings[index].push(ImportBinding::Function {
                                local: alias.clone().unwrap_or_else(|| last.to_string()),
                                exported: last.to_string(),
                                target,
                            });
                        } else if let Some((source, original)) =
                            rust_reexport_maps[target].get(last)
                        {
                            bindings[index].push(ImportBinding::Function {
                                local: alias.clone().unwrap_or_else(|| last.to_string()),
                                exported: original.clone(),
                                target: *source,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }
    // Python `from .x import *` and Go `import . "pkg"`: every name the
    // target exports is callable bare in the importing module. Expand
    // eagerly into Function bindings. A name the module defines or binds
    // explicitly stays local; a name offered by two star imports resolves
    // to neither; names that are not visible through a star (private in
    // Python, unexported in Go) are skipped.
    for index in 0..modules.len() {
        if !matches!(
            modules[index].language,
            FlowLanguage::Python | FlowLanguage::Go
        ) {
            continue;
        }
        let star_targets: Vec<usize> = bindings[index]
            .iter()
            .filter_map(|binding| match binding {
                ImportBinding::Star { target } => Some(*target),
                _ => None,
            })
            .collect();
        if star_targets.is_empty() {
            continue;
        }
        bindings[index].retain(|binding| !matches!(binding, ImportBinding::Star { .. }));
        let mut offers: std::collections::HashMap<String, Vec<usize>> =
            std::collections::HashMap::new();
        for target in star_targets {
            for name in exports[target].keys() {
                let visible = match modules[index].language {
                    FlowLanguage::Go => name.chars().next().is_some_and(|ch| ch.is_uppercase()),
                    _ => !name.starts_with('_'),
                };
                if !visible {
                    continue;
                }
                offers.entry(name.clone()).or_default().push(target);
            }
        }
        for (name, mut targets) in offers {
            targets.sort();
            targets.dedup();
            if targets.len() != 1 || exports[index].contains_key(&name) {
                continue;
            }
            let shadowed = bindings[index].iter().any(|binding| match binding {
                ImportBinding::Function { local, .. } => local == &name,
                ImportBinding::Module { binding, .. } => binding == &name,
                ImportBinding::Star { .. } => false,
            });
            if shadowed {
                continue;
            }
            bindings[index].push(ImportBinding::Function {
                local: name.clone(),
                exported: name,
                target: targets[0],
            });
        }
    }
    if bindings.iter().all(|found| found.is_empty()) {
        return result;
    }

    let instance_new = Regex::new(
        r#"^\s*this\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*new\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\("#,
    );
    let instance_plain =
        Regex::new(r#"^\s*self\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\("#);
    let instance_attr = Regex::new(
        r#"^\s*self\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\("#,
    );
    type Family = (fn(FlowLanguage) -> Vec<FlowSink>, fn(&str) -> bool, u8);
    let families: [Family; 3] = [
        (sql_flow_sinks, contains_numeric_conversion, 0),
        (command_flow_sinks, contains_command_sanitizer, 1),
        (ssrf_flow_sinks, contains_numeric_conversion, 2),
    ];
    for (build_sinks, sanitized, family) in families {
        let summaries: Vec<FlowSummaries> = modules
            .iter()
            .enumerate()
            .map(|(index, module)| {
                let sinks = build_sinks(module.language);
                flow_summaries(
                    &lines[index],
                    module.language,
                    &sinks,
                    sanitized,
                    &functions[index],
                )
            })
            .collect();
        // Deep callee summaries: per file, function, and parameter, the
        // `(file index, sink line)` pairs a value passed in that position
        // reaches. They start from the shallow summaries pinned to their
        // own file, then iterate: a callee whose own imports forward the
        // value onward also contributes the sinks those imports reach.
        // Iterate until the summaries stop changing: each round propagates
        // one import hop, so chains of any length converge within one round
        // per module, and import cycles simply stop changing.
        // Per parameter, the `(file index, sink line)` pairs reached; per
        // function, one set per parameter; per module, one entry per callee.
        type DeepSummaries = Vec<Vec<std::collections::HashSet<(usize, usize)>>>;
        let mut deep: Vec<DeepSummaries> = modules
            .iter()
            .enumerate()
            .map(|(index, _)| {
                summaries[index]
                    .iter()
                    .map(|function| {
                        function
                            .iter()
                            .map(|lines| lines.iter().map(|line| (index, *line)).collect())
                            .collect()
                    })
                    .collect()
            })
            .collect();
        let build_imports = |caller: usize, deep_map: &[DeepSummaries]| -> Vec<ImportedCallee> {
            let module = &modules[caller];
            let mut imports = Vec::new();
            for binding in &bindings[caller] {
                let (receiver, target, pairs): (Option<String>, usize, Vec<(String, usize)>) =
                    match binding {
                        ImportBinding::Module {
                            binding,
                            target,
                            exported_only,
                        } => (
                            Some(binding.clone()),
                            *target,
                            exports[*target]
                                .iter()
                                .filter(|(name, _)| {
                                    !exported_only
                                        || name.chars().next().is_some_and(|ch| ch.is_uppercase())
                                })
                                .map(|(name, function)| (name.clone(), *function))
                                .collect(),
                        ),
                        ImportBinding::Function {
                            local,
                            exported,
                            target,
                        } => (
                            None,
                            *target,
                            exports[*target]
                                .get(exported)
                                .map(|function| vec![(local.clone(), *function)])
                                .unwrap_or_default(),
                        ),
                        // Star bindings are expanded into Function bindings
                        // before this pass; none remain here.
                        ImportBinding::Star { target } => (None, *target, Vec::new()),
                    };
                // Only resolve within one language family.
                if modules[target].language != module.language {
                    continue;
                }
                for (name, function) in pairs {
                    let params = functions[target][function].params.len();
                    let reached = deep_map[target][function].clone();
                    if reached.iter().all(|lines| lines.is_empty()) {
                        continue;
                    }
                    imports.push(ImportedCallee {
                        receiver: receiver.clone(),
                        name,
                        target,
                        params,
                        summaries: reached,
                    });
                }
            }
            // Chained Rust module paths: with `mod api;` in scope,
            // `pub mod users;` inside api, and so on, `api::users::f(...)`
            // and longer chains resolve by walking one module binding per
            // segment. The walk is bounded by the module count, so module
            // cycles cannot loop.
            if module.language == FlowLanguage::Rust {
                let mut chained = Vec::new();
                let mut frontier: Vec<(String, usize)> = bindings[caller]
                    .iter()
                    .filter_map(|binding| {
                        if let ImportBinding::Module {
                            binding: first,
                            target,
                            ..
                        } = binding
                        {
                            (modules[*target].language == FlowLanguage::Rust)
                                .then(|| (first.clone(), *target))
                        } else {
                            None
                        }
                    })
                    .collect();
                let mut depth = 1;
                while !frontier.is_empty() && depth < modules.len() {
                    depth += 1;
                    let mut next_frontier = Vec::new();
                    for (prefix, middle) in frontier {
                        for inner in &bindings[middle] {
                            let ImportBinding::Module {
                                binding: segment,
                                target,
                                exported_only,
                            } = inner
                            else {
                                continue;
                            };
                            if modules[*target].language != FlowLanguage::Rust {
                                continue;
                            }
                            let receiver = format!("{prefix}::{segment}");
                            for (name, function) in exports[*target].iter() {
                                if *exported_only
                                    && !name.chars().next().is_some_and(|ch| ch.is_uppercase())
                                {
                                    continue;
                                }
                                let reached = deep_map[*target][*function].clone();
                                if reached.iter().all(|lines| lines.is_empty()) {
                                    continue;
                                }
                                chained.push(ImportedCallee {
                                    receiver: Some(receiver.clone()),
                                    name: name.clone(),
                                    target: *target,
                                    params: functions[*target][*function].params.len(),
                                    summaries: reached,
                                });
                            }
                            next_frontier.push((receiver, *target));
                        }
                    }
                    frontier = next_frontier;
                }
                imports.extend(chained);
            }
            // JS instance variables: `this.repo = new Repo(...)` where
            // `Repo` is imported - a whole-module import (`const Repo =
            // require('./repo')`, `import * as Repo from './repo'`) or a
            // class import (`import Repo from './repo'`, `import { Repo }
            // from './repo'`, optionally `as`-aliased) - lets
            // `this.repo.m(...)` resolve to a method of the imported
            // file. Methods match by name within that file, whichever of
            // its classes defines them.
            if module.language == FlowLanguage::JavaScript {
                let Ok(instance_new) = instance_new.as_ref() else {
                    return imports;
                };
                for line in &lines[caller] {
                    let Some(captures) = instance_new.captures(line) else {
                        continue;
                    };
                    let (Some(variable), Some(class)) = (captures.get(1), captures.get(2)) else {
                        continue;
                    };
                    let target = bindings[caller].iter().find_map(|binding| {
                        let (name, target) = match binding {
                            ImportBinding::Module {
                                binding: name,
                                target,
                                ..
                            } => (name.as_str(), *target),
                            ImportBinding::Function { local, target, .. } => {
                                (local.as_str(), *target)
                            }
                            ImportBinding::Star { .. } => return None,
                        };
                        (name == class.as_str()
                            && modules[target].language == FlowLanguage::JavaScript)
                            .then_some(target)
                    });
                    let Some(target) = target else {
                        continue;
                    };
                    for (position, function) in functions[target].iter().enumerate() {
                        if !function.method {
                            continue;
                        }
                        let reached = deep_map[target][position].clone();
                        if reached.iter().all(|lines| lines.is_empty()) {
                            continue;
                        }
                        imports.push(ImportedCallee {
                            receiver: Some(format!("this.{}", variable.as_str())),
                            name: function.name.clone(),
                            target,
                            params: function.params.len(),
                            summaries: reached,
                        });
                    }
                }
            }
            // Python instance variables: `self.repo = Store(...)` where
            // `Store` comes from `from .store import Store`, or
            // `self.repo = store.Store(...)` with `import store`, lets
            // `self.repo.m(...)` resolve to a method of the imported
            // file. Methods match by name within that file, whichever of
            // its classes defines them.
            if module.language == FlowLanguage::Python {
                let (Ok(instance_plain), Ok(instance_attr)) =
                    (instance_plain.as_ref(), instance_attr.as_ref())
                else {
                    return imports;
                };
                for line in &lines[caller] {
                    let code = line.split('#').next().unwrap_or("");
                    let (variable, target) = if let Some(captures) = instance_attr.captures(code) {
                        let (Some(variable), Some(module_name)) =
                            (captures.get(1), captures.get(2))
                        else {
                            continue;
                        };
                        let target = bindings[caller].iter().find_map(|binding| {
                            if let ImportBinding::Module {
                                binding: name,
                                target,
                                ..
                            } = binding
                            {
                                (name.as_str() == module_name.as_str()
                                    && modules[*target].language == FlowLanguage::Python)
                                    .then_some(*target)
                            } else {
                                None
                            }
                        });
                        (variable, target)
                    } else if let Some(captures) = instance_plain.captures(code) {
                        let (Some(variable), Some(class)) = (captures.get(1), captures.get(2))
                        else {
                            continue;
                        };
                        let target = bindings[caller].iter().find_map(|binding| {
                            if let ImportBinding::Function { local, target, .. } = binding {
                                (local.as_str() == class.as_str()
                                    && modules[*target].language == FlowLanguage::Python)
                                    .then_some(*target)
                            } else {
                                None
                            }
                        });
                        (variable, target)
                    } else {
                        continue;
                    };
                    let Some(target) = target else {
                        continue;
                    };
                    for (position, function) in functions[target].iter().enumerate() {
                        if !function.method {
                            continue;
                        }
                        let reached = deep_map[target][position].clone();
                        if reached.iter().all(|lines| lines.is_empty()) {
                            continue;
                        }
                        imports.push(ImportedCallee {
                            receiver: Some(format!("self.{}", variable.as_str())),
                            name: function.name.clone(),
                            target,
                            params: function.params.len(),
                            summaries: reached,
                        });
                    }
                }
            }
            // A call resolves only when one file provides the (receiver,
            // name) pair: two files offering the same callable are ambiguous
            // and neither resolves. Duplicate bindings for the same target
            // collapse instead.
            let mut groups: std::collections::HashMap<(Option<String>, String), Vec<usize>> =
                std::collections::HashMap::new();
            for (position, callee) in imports.iter().enumerate() {
                groups
                    .entry((callee.receiver.clone(), callee.name.clone()))
                    .or_default()
                    .push(position);
            }
            let mut keep = vec![true; imports.len()];
            for positions in groups.values() {
                let target = imports[positions[0]].target;
                if positions[1..]
                    .iter()
                    .any(|&position| imports[position].target != target)
                {
                    for &position in positions {
                        keep[position] = false;
                    }
                } else {
                    for &position in &positions[1..] {
                        keep[position] = false;
                    }
                }
            }
            let mut deduped = Vec::new();
            for (position, callee) in imports.into_iter().enumerate() {
                if keep[position] {
                    deduped.push(callee);
                }
            }
            deduped
        };
        for _ in 0..modules.len().max(3) {
            let mut next = deep.clone();
            let mut changed = false;
            for (caller, module) in modules.iter().enumerate() {
                let imports = build_imports(caller, &deep);
                if imports.is_empty() {
                    continue;
                }
                let sinks = build_sinks(module.language);
                let calls = FlowCalls {
                    functions: &functions[caller],
                    summaries: &summaries[caller],
                    imports: &imports,
                };
                for (function_index, function) in functions[caller].iter().enumerate() {
                    for (position, param) in function.params.iter().enumerate() {
                        let (reached, via_calls, imported) = flow_pass(
                            &lines[caller],
                            function.body.clone(),
                            module.language,
                            &sinks,
                            sanitized,
                            std::slice::from_ref(param),
                            false,
                            Some(&calls),
                        );
                        let mut pairs: std::collections::HashSet<(usize, usize)> = reached
                            .iter()
                            .chain(via_calls.iter())
                            .map(|line| (caller, *line))
                            .collect();
                        pairs.extend(imported.iter().copied());
                        if pairs != next[caller][function_index][position] {
                            next[caller][function_index][position] = pairs;
                            changed = true;
                        }
                    }
                }
            }
            deep = next;
            if !changed {
                break;
            }
        }
        for (caller, module) in modules.iter().enumerate() {
            let imports = build_imports(caller, &deep);
            if imports.is_empty() {
                continue;
            }
            let sinks = build_sinks(module.language);
            let calls = FlowCalls {
                functions: &functions[caller],
                summaries: &summaries[caller],
                imports: &imports,
            };
            let (_, _, mut reached) = flow_pass(
                &lines[caller],
                0..lines[caller].len(),
                module.language,
                &sinks,
                sanitized,
                &[],
                true,
                Some(&calls),
            );
            for (body, seeds) in
                spring_annotated_seeds(&lines[caller], module.language, &functions[caller])
            {
                let (_, _, seeded_reached) = flow_pass(
                    &lines[caller],
                    body,
                    module.language,
                    &sinks,
                    sanitized,
                    &seeds,
                    true,
                    Some(&calls),
                );
                reached.extend(seeded_reached);
            }
            for (target, line) in reached {
                let entry = result.entry(modules[target].path.clone()).or_default();
                match family {
                    0 => entry.sql.insert(line),
                    1 => entry.command.insert(line),
                    _ => entry.ssrf.insert(line),
                };
            }
        }
    }
    result
}

/// Exported function names of a file, mapped to their index in `functions`.
/// JS/TS: `module.exports = { a, b: c }`, `exports.a = b`, `export function
/// a`, `export { a, b as c }`, `export default function a` / `export default
/// a` (under the conventional `default` key). Python: every top-level function. Go: every
/// package-level function (same-package visibility; cross-package callers
/// see only capitalized names, filtered at the binding). Java: the static,
/// non-private methods of the file's class. Rust: the `pub` free functions.
#[allow(clippy::items_after_test_module)]
fn flow_exports(
    lines: &[&str],
    language: FlowLanguage,
    functions: &[FlowFunction],
) -> std::collections::HashMap<String, usize> {
    let mut exported = std::collections::HashMap::new();
    let find = |local: &str| {
        functions
            .iter()
            .position(|function| function.name == local && !function.method)
    };
    if language == FlowLanguage::Python {
        for (index, function) in functions.iter().enumerate() {
            let top_level = lines
                .get(function.header)
                .is_some_and(|line| !line.starts_with(char::is_whitespace));
            if top_level && !function.method {
                exported.insert(function.name.clone(), index);
            }
        }
        return exported;
    }
    if language == FlowLanguage::Go {
        for (index, function) in functions.iter().enumerate() {
            exported.insert(function.name.clone(), index);
        }
        return exported;
    }
    if language == FlowLanguage::Java {
        for (index, function) in functions.iter().enumerate() {
            let Some(header) = lines.get(function.header) else {
                continue;
            };
            let words: std::collections::HashSet<&str> = header
                .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                .collect();
            if words.contains("static") && !words.contains("private") {
                exported.insert(function.name.clone(), index);
            }
        }
        return exported;
    }
    let is_identifier = |text: &str| {
        !text.is_empty()
            && text
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
    };
    if language == FlowLanguage::Rust {
        for (index, function) in functions.iter().enumerate() {
            let Some(header) = lines.get(function.header) else {
                continue;
            };
            let words: std::collections::HashSet<&str> = header
                .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                .collect();
            if words.contains("pub") && !function.method {
                exported.insert(function.name.clone(), index);
            }
        }
        return exported;
    }
    let (
        Ok(object_start),
        Ok(property),
        Ok(export_decl),
        Ok(export_list),
        Ok(export_default_fn),
        Ok(export_default_ref),
    ) = (
        Regex::new(r#"^\s*module\s*\.\s*exports\s*=\s*\{(.*)$"#),
        Regex::new(
            r#"^\s*(?:module\s*\.\s*)?exports\s*\.\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*;?\s*$"#,
        ),
        Regex::new(
            r#"^\s*export\s+(?:async\s+)?(?:function\s*\*?\s*|const\s+|let\s+|var\s+)([A-Za-z_$][A-Za-z0-9_$]*)"#,
        ),
        Regex::new(r#"^\s*export\s*\{([^}]*)\}"#),
        Regex::new(
            r#"^\s*export\s+default\s+(?:async\s+)?function\s*\*?\s*([A-Za-z_$][A-Za-z0-9_$]*)"#,
        ),
        Regex::new(r#"^\s*export\s+default\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*;?\s*$"#),
    )
    else {
        return exported;
    };
    let add_entries =
        |text: &str, separator: &str, exported: &mut std::collections::HashMap<String, usize>| {
            for entry in text.split(',') {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                let (left, right) = match entry.split_once(separator) {
                    Some((left, right)) => (left.trim(), right.trim()),
                    None => (entry, entry),
                };
                // `module.exports = { key: local }` / `export { local as key }`.
                let (key, local) = if separator == ":" {
                    (left, right)
                } else {
                    (right, left)
                };
                if is_identifier(key) && is_identifier(local) {
                    if let Some(index) = find(local) {
                        exported.insert(key.to_string(), index);
                    }
                }
            }
        };
    let mut in_object = false;
    for line in lines {
        let code = line.split("//").next().unwrap_or("");
        if in_object {
            let (body, done) = match code.split_once('}') {
                Some((body, _)) => (body, true),
                None => (code, false),
            };
            add_entries(body, ":", &mut exported);
            in_object = !done;
            continue;
        }
        if let Some(rest) = object_start.captures(code).and_then(|c| c.get(1)) {
            let rest = rest.as_str();
            match rest.split_once('}') {
                Some((body, _)) => add_entries(body, ":", &mut exported),
                None => {
                    add_entries(rest, ":", &mut exported);
                    in_object = true;
                }
            }
            continue;
        }
        if let Some(captures) = property.captures(code) {
            if let (Some(key), Some(local)) = (captures.get(1), captures.get(2)) {
                if let Some(index) = find(local.as_str()) {
                    exported.insert(key.as_str().to_string(), index);
                }
            }
            continue;
        }
        // `export default function f` / `export default f` register the
        // function under the conventional `default` key that default imports
        // look up.
        if let Some(name) = export_default_fn.captures(code).and_then(|c| c.get(1)) {
            if let Some(index) = find(name.as_str()) {
                exported.insert("default".to_string(), index);
            }
            continue;
        }
        if let Some(name) = export_default_ref.captures(code).and_then(|c| c.get(1)) {
            if let Some(index) = find(name.as_str()) {
                exported.insert("default".to_string(), index);
            }
            continue;
        }
        if let Some(name) = export_decl.captures(code).and_then(|c| c.get(1)) {
            if let Some(index) = find(name.as_str()) {
                exported.insert(name.as_str().to_string(), index);
            }
            continue;
        }
        if let Some(list) = export_list.captures(code).and_then(|c| c.get(1)) {
            add_entries(list.as_str(), " as ", &mut exported);
        }
    }
    exported
}

/// The directory a Rust file's `mod name;` declarations and `self::` paths
/// resolve against: `main.rs`/`lib.rs`/`mod.rs` use their own directory,
/// any other file uses a same-named subdirectory.
#[allow(clippy::items_after_test_module)]
fn rust_module_dir(path: &Path) -> Option<std::path::PathBuf> {
    let dir = path.parent()?;
    let stem = path.file_stem()?.to_string_lossy();
    if matches!(stem.as_ref(), "main" | "lib" | "mod") {
        Some(dir.to_path_buf())
    } else {
        Some(dir.join(stem.as_ref()))
    }
}

/// The crate root of a Rust file: the nearest ancestor directory, within the
/// project root, that holds `main.rs` or `lib.rs`.
#[allow(clippy::items_after_test_module)]
fn rust_crate_root(dir: &Path, root: &Path) -> Option<std::path::PathBuf> {
    let mut candidate = Some(dir);
    while let Some(path) = candidate {
        if path.join("main.rs").is_file() || path.join("lib.rs").is_file() {
            return Some(path.to_path_buf());
        }
        if path == root {
            break;
        }
        candidate = path.parent();
    }
    None
}

/// A Rust `mod name;` declaration or `use` path found in one file.
enum RustDeclaration {
    Mod(String),
    Use {
        segments: Vec<String>,
        alias: Option<String>,
        reexport: bool,
    },
}

/// The `mod`/`use` declarations of a Rust file. Grouped `use a::{b, c}`
/// items are expanded to one declaration each (`as` aliases and a `*` glob
/// item included); nested groups (`use a::{b::{c, d}}`) and nested path
/// items (`use a::{b::c, d}`) flatten to their full segment lists, a
/// tree spanning several lines is joined before flattening (bounded, so
/// an unterminated tree is skipped), and `pub use` re-exports are
/// recognized and flagged so the cross-file pass can resolve one hop
/// through them.
#[allow(clippy::items_after_test_module)]
fn rust_declarations(lines: &[&str]) -> Vec<RustDeclaration> {
    let mut declarations = Vec::new();
    let (Ok(mod_decl), Ok(use_decl)) = (
        Regex::new(r#"^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;"#),
        Regex::new(r#"^\s*(pub\s+)?use\s+(.+?)\s*;"#),
    ) else {
        return declarations;
    };
    let use_start = Regex::new(r#"^\s*(?:pub\s+)?use\s"#).ok();
    let mut index = 0;
    while index < lines.len() {
        let code = lines[index].split("//").next().unwrap_or("");
        if let Some(name) = mod_decl.captures(code).and_then(|c| c.get(1)) {
            declarations.push(RustDeclaration::Mod(name.as_str().to_string()));
            index += 1;
            continue;
        }
        if use_start.as_ref().is_some_and(|re| re.is_match(code)) {
            // A `use` tree may span several lines: join comment-stripped
            // lines with spaces until the braces balance and the final
            // `;` appears, bounded so an unterminated tree is skipped.
            let mut joined = String::new();
            let mut balance = 0i32;
            let mut end = index;
            while end < lines.len() && end - index < 40 {
                let piece = lines[end].split("//").next().unwrap_or("");
                balance += piece.matches('{').count() as i32;
                balance -= piece.matches('}').count() as i32;
                if !joined.is_empty() {
                    joined.push(' ');
                }
                joined.push_str(piece.trim_end());
                end += 1;
                if balance <= 0 && piece.contains(';') {
                    break;
                }
            }
            if let Some(captures) = use_decl.captures(&joined) {
                let reexport = captures.get(1).is_some();
                let body = captures.get(2).map(|m| m.as_str()).unwrap_or("");
                for (segments, alias) in expand_use_tree(body) {
                    declarations.push(RustDeclaration::Use {
                        segments,
                        alias,
                        reexport,
                    });
                }
            }
            index = end.max(index + 1);
            continue;
        }
        index += 1;
    }
    declarations
}

/// Every leaf of one `use` tree: the full segment list plus an optional
/// `as` alias. `body` is the text between `use` and the final `;`.
fn expand_use_tree(body: &str) -> Vec<(Vec<String>, Option<String>)> {
    let mut leaves = Vec::new();
    let mut cursor = body.trim();
    expand_use_tree_at(&mut Vec::new(), &mut cursor, &mut leaves);
    leaves
}

/// Parses one tree from the front of `cursor`, appending each leaf reached
/// to `leaves`. `prefix` carries the segments enclosing groups already
/// consumed; a malformed tail abandons only its own branch.
fn expand_use_tree_at(
    prefix: &mut Vec<String>,
    cursor: &mut &str,
    leaves: &mut Vec<(Vec<String>, Option<String>)>,
) {
    loop {
        *cursor = cursor.trim_start();
        if let Some(rest) = cursor.strip_prefix('{') {
            *cursor = rest;
            expand_use_group_at(prefix, cursor, leaves);
            return;
        }
        let Some(name) = take_use_ident(cursor) else {
            return;
        };
        prefix.push(name);
        *cursor = cursor.trim_start();
        if let Some(rest) = cursor.strip_prefix("as") {
            if rest.chars().next().is_some_and(char::is_whitespace) {
                *cursor = rest.trim_start();
                if let Some(alias) = take_use_ident(cursor) {
                    leaves.push((prefix.clone(), Some(alias)));
                }
                return;
            }
        }
        if let Some(rest) = cursor.strip_prefix("::") {
            *cursor = rest;
            continue;
        }
        leaves.push((prefix.clone(), None));
        return;
    }
}

/// Parses the comma-separated trees of one `{ ... }` group, each extending
/// `prefix`, through the closing brace.
fn expand_use_group_at(
    prefix: &[String],
    cursor: &mut &str,
    leaves: &mut Vec<(Vec<String>, Option<String>)>,
) {
    loop {
        *cursor = cursor.trim_start();
        if let Some(rest) = cursor.strip_prefix('}') {
            *cursor = rest;
            return;
        }
        if cursor.is_empty() {
            return;
        }
        let mut branch = prefix.to_owned();
        expand_use_tree_at(&mut branch, cursor, leaves);
        *cursor = cursor.trim_start();
        if let Some(rest) = cursor.strip_prefix(',') {
            *cursor = rest;
            continue;
        }
        if let Some(rest) = cursor.strip_prefix('}') {
            *cursor = rest;
        }
        return;
    }
}

/// Takes one tree item (`*` or an identifier) from the front of `cursor`.
fn take_use_ident(cursor: &mut &str) -> Option<String> {
    if let Some(rest) = cursor.strip_prefix('*') {
        *cursor = rest;
        return Some("*".to_string());
    }
    let len: usize = cursor
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .map(char::len_utf8)
        .sum();
    let ident = &cursor[..len];
    if ident
        .chars()
        .next()
        .is_none_or(|c| !(c.is_ascii_alphabetic() || c == '_'))
    {
        return None;
    }
    let ident = ident.to_string();
    *cursor = &cursor[len..];
    Some(ident)
}

/// The `package` clause of a Go file; files sharing it in one directory
/// share a namespace.
#[allow(clippy::items_after_test_module)]
fn go_package_clause(lines: &[&str]) -> Option<String> {
    let package = Regex::new(r#"^\s*package\s+([A-Za-z_][A-Za-z0-9_]*)"#).ok()?;
    lines.iter().find_map(|line| {
        package
            .captures(line.split("//").next().unwrap_or(""))
            .and_then(|captures| captures.get(1))
            .map(|name| name.as_str().to_string())
    })
}

/// The `package` statement of a Java file; `None` for the default package.
#[allow(clippy::items_after_test_module)]
fn java_package_clause(lines: &[&str]) -> Option<String> {
    let package = Regex::new(r#"^\s*package\s+([A-Za-z_][A-Za-z0-9_.]*)\s*;"#).ok()?;
    lines.iter().find_map(|line| {
        package
            .captures(line.split("//").next().unwrap_or(""))
            .and_then(|captures| captures.get(1))
            .map(|name| name.as_str().to_string())
    })
}

/// The first declared type name of a Java file, falling back to the file
/// stem (`UserService.java` conventionally declares `UserService`).
#[allow(clippy::items_after_test_module)]
fn java_class_name(lines: &[&str], path: &Path) -> Option<String> {
    let class =
        Regex::new(r#"(?:^|\s)(?:class|interface|enum|record)\s+([A-Za-z_][A-Za-z0-9_]*)"#).ok()?;
    for line in lines {
        let code = line.split("//").next().unwrap_or("");
        if let Some(name) = class.captures(code).and_then(|captures| captures.get(1)) {
            return Some(name.as_str().to_string());
        }
    }
    path.file_stem()
        .map(|stem| stem.to_string_lossy().to_string())
}

/// Import specs of a Go file as `(alias, path)` pairs, from both
/// `import "path"` and the grouped `import ( ... )` form. Blank and dot
/// imports are skipped.
#[allow(clippy::items_after_test_module)]
fn go_import_specs(lines: &[&str]) -> Vec<(Option<String>, String)> {
    let mut specs = Vec::new();
    let (Ok(single), Ok(group_start), Ok(entry)) = (
        Regex::new(r#"^\s*import\s+(?:([A-Za-z_][A-Za-z0-9_]*|[._])\s+)?"([^"]+)""#),
        Regex::new(r#"^\s*import\s*\(\s*$"#),
        Regex::new(r#"^\s*(?:([A-Za-z_][A-Za-z0-9_]*|[._])\s+)?"([^"]+)""#),
    ) else {
        return specs;
    };
    let mut in_group = false;
    for line in lines {
        let code = line.split("//").next().unwrap_or("").trim();
        if in_group {
            if code.starts_with(')') {
                in_group = false;
                continue;
            }
            if let Some(captures) = entry.captures(code) {
                let alias = captures.get(1).map(|name| name.as_str().to_string());
                if !matches!(alias.as_deref(), Some("_")) {
                    let path = captures.get(2).map_or("", |spec| spec.as_str());
                    specs.push((alias, path.to_string()));
                }
            }
            continue;
        }
        if group_start.is_match(code) {
            in_group = true;
            continue;
        }
        if let Some(captures) = single.captures(code) {
            let alias = captures.get(1).map(|name| name.as_str().to_string());
            if !matches!(alias.as_deref(), Some("_")) {
                let path = captures.get(2).map_or("", |spec| spec.as_str());
                specs.push((alias, path.to_string()));
            }
        }
    }
    specs
}

/// One Java `import` statement.
enum JavaImport {
    /// `import a.b.C;`
    Class { package: String, class: String },
    /// `import a.b.*;`
    PackageWildcard { package: String },
    /// `import static a.b.C.f;`
    StaticMember {
        package: String,
        class: String,
        member: String,
    },
    /// `import static a.b.C.*;`
    StaticWildcard { package: String, class: String },
}

/// The imports of a Java file. The package/class boundary uses the same
/// convention as `import a.b.C;` resolution: the last dotted segment is the
/// class (or, for `import static`, the member and the segment before it).
#[allow(clippy::items_after_test_module)]
fn java_imports(lines: &[&str]) -> Vec<JavaImport> {
    let mut imports = Vec::new();
    let Ok(import) =
        Regex::new(r#"^\s*import\s+(static\s+)?([A-Za-z_][A-Za-z0-9_.]*?)(\.\*)?\s*;"#)
    else {
        return imports;
    };
    for line in lines {
        let code = line.split("//").next().unwrap_or("").trim();
        let Some(captures) = import.captures(code) else {
            continue;
        };
        let is_static = captures.get(1).is_some();
        let dotted = captures.get(2).map_or("", |name| name.as_str());
        let wildcard = captures.get(3).is_some();
        let Some((path, last)) = dotted.rsplit_once('.') else {
            continue;
        };
        let parsed = match (is_static, wildcard) {
            (false, false) => Some(JavaImport::Class {
                package: path.to_string(),
                class: last.to_string(),
            }),
            (false, true) => Some(JavaImport::PackageWildcard {
                package: dotted.to_string(),
            }),
            (true, false) => {
                path.rsplit_once('.')
                    .map(|(package, class)| JavaImport::StaticMember {
                        package: package.to_string(),
                        class: class.to_string(),
                        member: last.to_string(),
                    })
            }
            (true, true) => {
                dotted
                    .rsplit_once('.')
                    .map(|(package, class)| JavaImport::StaticWildcard {
                        package: package.to_string(),
                        class: class.to_string(),
                    })
            }
        };
        if let Some(parsed) = parsed {
            imports.push(parsed);
        }
    }
    imports
}

/// The module path a `go.mod` declares.
#[allow(clippy::items_after_test_module)]
fn go_module_path(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let line = line.split("//").next().unwrap_or("").trim();
        let mut words = line.split_whitespace();
        if words.next() == Some("module") {
            words.next().map(str::to_string)
        } else {
            None
        }
    })
}

/// The directory holding the nearest `go.mod` at or above `dir` (stopping
/// at `root`), and the module path it declares.
#[allow(clippy::items_after_test_module)]
fn go_module_root_and_path(dir: &Path, root: &Path) -> Option<(std::path::PathBuf, String)> {
    let mut base = dir;
    loop {
        let go_mod = base.join("go.mod");
        if go_mod.is_file() {
            let content = std::fs::read_to_string(go_mod).ok()?;
            let module = go_module_path(&content)?;
            return Some((base.to_path_buf(), module));
        }
        if base == root {
            return None;
        }
        base = base.parent()?;
    }
}

/// `replace` directives of a `go.mod` that map a module path to a local
/// directory, as `(module path, target)` pairs where target is relative to
/// the `go.mod` (or absolute). Replacements to another module version have
/// no local directory and are skipped.
#[allow(clippy::items_after_test_module)]
fn go_replace_dirs(go_mod: &Path) -> Vec<(String, std::path::PathBuf)> {
    let Ok(content) = std::fs::read_to_string(go_mod) else {
        return Vec::new();
    };
    let mut dirs = Vec::new();
    let mut in_block = false;
    for line in content.lines() {
        let line = line.split("//").next().unwrap_or("").trim();
        if in_block {
            if line.starts_with(')') {
                in_block = false;
                continue;
            }
            push_replace(&mut dirs, line);
            continue;
        }
        let Some(rest) = line.strip_prefix("replace") else {
            continue;
        };
        let rest = rest.trim_start();
        if rest == "(" {
            in_block = true;
            continue;
        }
        if let Some(body) = rest.strip_prefix('(').map(str::trim_end) {
            // `replace ( old => new )` on one line.
            if let Some(body) = body.strip_suffix(')') {
                push_replace(&mut dirs, body);
            }
            continue;
        }
        push_replace(&mut dirs, rest);
    }
    dirs
}

/// One `old [version] => new [version]` replace body; kept only when `new`
/// is a local path (no version, starting with `.` or `/`).
fn push_replace(dirs: &mut Vec<(String, std::path::PathBuf)>, body: &str) {
    let Some((left, right)) = body.split_once("=>") else {
        return;
    };
    let old = left.split_whitespace().next().unwrap_or("");
    let right: Vec<&str> = right.split_whitespace().collect();
    if old.is_empty() || right.len() != 1 {
        return;
    }
    let new = right[0];
    if new.starts_with('.') || new.starts_with('/') {
        dirs.push((old.to_string(), std::path::PathBuf::from(new)));
    }
}

/// Every `(module dir, module path)` declared by a `go.mod` under `root`,
/// skipping excluded directories (`vendor`, `node_modules`, ...). Bounded so
/// a huge tree cannot stall the scan.
#[allow(clippy::items_after_test_module)]
fn go_nested_modules(root: &Path) -> Vec<(std::path::PathBuf, String)> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0usize;
    while let Some(dir) = pending.pop() {
        if found.len() >= 256 || visited >= 50_000 {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            let path = entry.path();
            if path.is_dir() {
                if !crate::scan::should_exclude(&path) {
                    pending.push(path);
                }
            } else if path.file_name().is_some_and(|name| name == "go.mod") {
                if let Some(module) = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|content| go_module_path(&content))
                {
                    if let Ok(canonical) = std::fs::canonicalize(&path) {
                        if let Some(parent) = canonical.parent() {
                            found.push((parent.to_path_buf(), module));
                        }
                    }
                }
            }
        }
    }
    found
}

/// Map an import outside the file's own module to a directory: through a
/// `replace` directive to a local directory (resolved against the module
/// root), or through another `go.mod` under the project root whose module
/// path prefixes the import. The longest matching module path wins.
#[allow(clippy::items_after_test_module)]
fn go_external_import_dir(
    spec: &str,
    module_root: &Path,
    replaces: &[(String, std::path::PathBuf)],
    nested: &[(std::path::PathBuf, String)],
) -> Option<std::path::PathBuf> {
    let mut best: Option<(usize, std::path::PathBuf)> = None;
    let mut offer = |module_path: &str, dir: std::path::PathBuf| {
        let relative = match spec.strip_prefix(module_path) {
            Some("") => std::path::PathBuf::new(),
            Some(rest) if rest.starts_with('/') => std::path::PathBuf::from(&rest[1..]),
            _ => return,
        };
        let candidate = dir.join(relative);
        if best
            .as_ref()
            .is_none_or(|(len, _)| module_path.len() > *len)
        {
            best = Some((module_path.len(), candidate));
        }
    };
    for (old, target) in replaces {
        offer(old, module_root.join(target));
    }
    for (dir, module_path) in nested {
        offer(module_path, dir.clone());
    }
    best.map(|(_, dir)| dir)
}

/// Resolve a file's relative imports to other project files.
#[allow(clippy::items_after_test_module)]
/// Resolve a relative JS/TS import specifier (`./x`, `../x`) to a scanned
/// file, trying the plain path, the common extensions, and index files.
#[allow(clippy::items_after_test_module)]
fn resolve_js_specifier(
    dir: &Path,
    spec: &str,
    index_of: &std::collections::HashMap<std::path::PathBuf, usize>,
) -> Option<usize> {
    if !(spec.starts_with("./") || spec.starts_with("../")) {
        return None;
    }
    let base = dir.join(spec);
    let mut candidates = vec![base.clone()];
    for ext in ["js", "ts", "mjs", "cjs"] {
        candidates.push(std::path::PathBuf::from(format!(
            "{}.{ext}",
            base.to_string_lossy()
        )));
        candidates.push(base.join(format!("index.{ext}")));
    }
    candidates
        .into_iter()
        .filter(|candidate| candidate.is_file())
        .find_map(|candidate| {
            std::fs::canonicalize(candidate)
                .ok()
                .and_then(|canonical| index_of.get(&canonical).copied())
        })
}

/// A re-export declaration of a JS/TS ("barrel") file.
enum JsReexport {
    Named {
        spec: String,
        source: String,
        name: String,
    },
    Glob {
        spec: String,
    },
    /// `export * as ns from './x'`: the barrel offers `ns` as a module
    /// (namespace) bound to the target file itself.
    Namespace {
        spec: String,
        name: String,
    },
}

/// Re-export declarations of one JS/TS file: `export { a, b as c } from
/// './x'`, `export * from './x'`, and `export * as ns from './x'`.
#[allow(clippy::items_after_test_module)]
/// JS declaration statements with multi-line ones joined: an `import`,
/// an `export { ... } from` / `export * from` re-export, or a
/// `const`/`let`/`var` destructuring that spans lines is flattened into
/// one space-separated statement so the single-line import and re-export
/// shapes still match. Joining starts only on a declaration opener and
/// stops once braces and parentheses balance and the statement
/// terminates (`;`, a closing quote, or `)`), bounded at 20 lines; every
/// other line passes through untouched. `//` comments are stripped per
/// line, so a specifier containing `//` does not join (relative
/// specifiers never contain one).
fn js_declarations(lines: &[&str]) -> Vec<String> {
    let mut statements = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let code = lines[index].split("//").next().unwrap_or("").trim();
        let destructures = ["const {", "let {", "var {"]
            .iter()
            .any(|head| code.starts_with(head));
        let opens = code.starts_with("import ")
            || code.starts_with("import{")
            || code.starts_with("import*")
            || code.starts_with("export {")
            || code.starts_with("export *")
            || ((code.starts_with("const ")
                || code.starts_with("let ")
                || code.starts_with("var "))
                && (destructures || code.contains("require(")));
        let balance = |text: &str| {
            let braces = text.matches('{').count() as i64 - text.matches('}').count() as i64;
            let parens = text.matches('(').count() as i64 - text.matches(')').count() as i64;
            (braces, parens)
        };
        let terminated = |text: &str, braces: i64, parens: i64| {
            braces <= 0
                && parens <= 0
                && (text.ends_with(';')
                    || text.ends_with('\'')
                    || text.ends_with('"')
                    || text.ends_with(')'))
        };
        if !opens {
            index += 1;
            continue;
        }
        let mut joined = code.to_string();
        let (mut braces, mut parens) = balance(&joined);
        let mut used = 1;
        while !terminated(&joined, braces, parens) && used < 20 && index + used < lines.len() {
            let next = lines[index + used].split("//").next().unwrap_or("").trim();
            if !next.is_empty() {
                joined.push(' ');
                joined.push_str(next);
                let (b, p) = balance(&joined);
                braces = b;
                parens = p;
            }
            used += 1;
        }
        statements.push(joined);
        index += used;
    }
    statements
}

fn js_reexports(lines: &[&str]) -> Vec<JsReexport> {
    let mut declarations = Vec::new();
    let (Ok(named), Ok(glob), Ok(namespace)) = (
        Regex::new(r#"^\s*export\s*\{([^}]*)\}\s*from\s+['"]([^'"]+)['"]\s*;?\s*$"#),
        Regex::new(r#"^\s*export\s*\*\s*from\s+['"]([^'"]+)['"]\s*;?\s*$"#),
        Regex::new(
            r#"^\s*export\s*\*\s*as\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+['"]([^'"]+)['"]\s*;?\s*$"#,
        ),
    ) else {
        return declarations;
    };
    let is_identifier = |text: &str| {
        !text.is_empty()
            && text
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
    };
    for statement in js_declarations(lines) {
        let code = statement.as_str();
        if let Some(captures) = named.captures(code) {
            let names = captures.get(1).map(|m| m.as_str()).unwrap_or("");
            let spec = captures
                .get(2)
                .map(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            for entry in names.split(',') {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                let (source, name) = match entry.split_once(" as ") {
                    Some((left, right)) => (left.trim(), right.trim()),
                    None => (entry, entry),
                };
                if is_identifier(source) && is_identifier(name) {
                    declarations.push(JsReexport::Named {
                        spec: spec.clone(),
                        source: source.to_string(),
                        name: name.to_string(),
                    });
                }
            }
            continue;
        }
        if let Some(captures) = namespace.captures(code) {
            if let (Some(name), Some(spec)) = (captures.get(1), captures.get(2)) {
                declarations.push(JsReexport::Namespace {
                    spec: spec.as_str().to_string(),
                    name: name.as_str().to_string(),
                });
            }
            continue;
        }
        if let Some(spec) = glob.captures(code).and_then(|c| c.get(1)) {
            declarations.push(JsReexport::Glob {
                spec: spec.as_str().to_string(),
            });
        }
    }
    declarations
}

fn flow_imports(
    lines: &[&str],
    language: FlowLanguage,
    path: &Path,
    root: &Path,
    index_of: &std::collections::HashMap<std::path::PathBuf, usize>,
) -> Vec<ImportBinding> {
    let mut bindings = Vec::new();
    let Some(dir) = path.parent() else {
        return bindings;
    };
    let lookup = |candidate: std::path::PathBuf| {
        std::fs::canonicalize(candidate)
            .ok()
            .and_then(|canonical| index_of.get(&canonical).copied())
    };
    let is_identifier = |text: &str| {
        !text.is_empty()
            && text
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
    };
    match language {
        FlowLanguage::JavaScript => {
            let resolve = |spec: &str| resolve_js_specifier(dir, spec, index_of);
            let (
                Ok(module_require),
                Ok(named_require),
                Ok(namespace_import),
                Ok(named_import),
                Ok(default_import),
                Ok(mixed_import),
            ) = (
                Regex::new(
                    r#"^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)\s*;?\s*$"#,
                ),
                Regex::new(
                    r#"^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)\s*;?\s*$"#,
                ),
                Regex::new(
                    r#"^\s*import\s+\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+['"]([^'"]+)['"]\s*;?\s*$"#,
                ),
                Regex::new(r#"^\s*import\s*\{([^}]*)\}\s*from\s+['"]([^'"]+)['"]\s*;?\s*$"#),
                Regex::new(
                    r#"^\s*import\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+['"]([^'"]+)['"]\s*;?\s*$"#,
                ),
                Regex::new(
                    r#"^\s*import\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*\{([^}]*)\}\s*from\s+['"]([^'"]+)['"]\s*;?\s*$"#,
                ),
            )
            else {
                return bindings;
            };
            for statement in js_declarations(lines) {
                let line = statement.as_str();
                for (re, module) in [(&module_require, true), (&namespace_import, true)] {
                    if let Some(captures) = re.captures(line) {
                        if let (Some(binding), Some(spec)) = (captures.get(1), captures.get(2)) {
                            if let Some(target) = resolve(spec.as_str()) {
                                if module {
                                    bindings.push(ImportBinding::Module {
                                        binding: binding.as_str().to_string(),
                                        target,
                                        exported_only: false,
                                    });
                                }
                            }
                        }
                    }
                }
                // `import f from './x'` binds the local name to the target's
                // `default` export; `import f, { g } from './x'` binds both.
                // `import type ...` lines are skipped: they never produce a
                // callable binding.
                if !line.trim_start().starts_with("import type") {
                    if let Some(captures) = mixed_import.captures(line) {
                        if let (Some(local), Some(names), Some(spec)) =
                            (captures.get(1), captures.get(2), captures.get(3))
                        {
                            if let Some(target) = resolve(spec.as_str()) {
                                bindings.push(ImportBinding::Function {
                                    local: local.as_str().to_string(),
                                    exported: "default".to_string(),
                                    target,
                                });
                                for entry in names.as_str().split(',') {
                                    let entry = entry.trim();
                                    let (exported, local) = match entry.split_once(" as ") {
                                        Some((left, right)) => (left.trim(), right.trim()),
                                        None => (entry, entry),
                                    };
                                    if is_identifier(exported) && is_identifier(local) {
                                        bindings.push(ImportBinding::Function {
                                            local: local.to_string(),
                                            exported: exported.to_string(),
                                            target,
                                        });
                                    }
                                }
                            }
                        }
                    } else if let Some(captures) = default_import.captures(line) {
                        if let (Some(local), Some(spec)) = (captures.get(1), captures.get(2)) {
                            if let Some(target) = resolve(spec.as_str()) {
                                bindings.push(ImportBinding::Function {
                                    local: local.as_str().to_string(),
                                    exported: "default".to_string(),
                                    target,
                                });
                            }
                        }
                    }
                }
                for (re, separator) in [(&named_require, ":"), (&named_import, " as ")] {
                    if let Some(captures) = re.captures(line) {
                        if let (Some(names), Some(spec)) = (captures.get(1), captures.get(2)) {
                            let Some(target) = resolve(spec.as_str()) else {
                                continue;
                            };
                            for entry in names.as_str().split(',') {
                                let entry = entry.trim();
                                let (exported, local) = match entry.split_once(separator) {
                                    Some((left, right)) => (left.trim(), right.trim()),
                                    None => (entry, entry),
                                };
                                if is_identifier(exported) && is_identifier(local) {
                                    bindings.push(ImportBinding::Function {
                                        local: local.to_string(),
                                        exported: exported.to_string(),
                                        target,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        FlowLanguage::Python => {
            let resolve_module = |dots: usize, dotted: &str| -> Option<usize> {
                let relative: std::path::PathBuf =
                    dotted.split('.').filter(|p| !p.is_empty()).collect();
                let bases: Vec<std::path::PathBuf> = if dots > 0 {
                    let mut base = dir.to_path_buf();
                    for _ in 1..dots {
                        base = base.parent()?.to_path_buf();
                    }
                    vec![base]
                } else {
                    vec![dir.to_path_buf(), root.to_path_buf()]
                };
                bases.into_iter().find_map(|base| {
                    let target = base.join(&relative);
                    [
                        std::path::PathBuf::from(format!("{}.py", target.to_string_lossy())),
                        target.join("__init__.py"),
                    ]
                    .into_iter()
                    .filter(|candidate| candidate.is_file())
                    .find_map(lookup)
                })
            };
            let (Ok(from_import), Ok(plain_import), Ok(star_import)) = (
                Regex::new(
                    r#"^from\s+(\.*)([A-Za-z_][A-Za-z0-9_.]*)?\s+import\s+([A-Za-z_][A-Za-z0-9_,\s]*)$"#,
                ),
                Regex::new(
                    r#"^import\s+([A-Za-z_][A-Za-z0-9_.]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*$"#,
                ),
                Regex::new(r#"^from\s+(\.*)([A-Za-z_][A-Za-z0-9_.]*)?\s+import\s+\*\s*$"#),
            ) else {
                return bindings;
            };
            // Parenthesized from-imports (`from .x import (\n a,\n b\n)`,
            // black's format, and single-line `from .x import (a)`) are
            // flattened to the plain shape first: lines join until the
            // parens balance (bounded 40 lines), then the parens drop.
            let mut normalized: Vec<String> = Vec::with_capacity(lines.len());
            {
                let mut index = 0;
                while index < lines.len() {
                    let code = lines[index].split('#').next().unwrap_or("").trim();
                    if !(code.starts_with("from ") && code.contains(" import (")) {
                        normalized.push(code.to_string());
                        index += 1;
                        continue;
                    }
                    let mut joined = code.to_string();
                    let mut balance =
                        joined.matches('(').count() as i64 - joined.matches(')').count() as i64;
                    let mut used = 1;
                    while balance > 0 && used < 40 && index + used < lines.len() {
                        let next = lines[index + used].split('#').next().unwrap_or("").trim();
                        joined.push(' ');
                        joined.push_str(next);
                        balance =
                            joined.matches('(').count() as i64 - joined.matches(')').count() as i64;
                        used += 1;
                    }
                    normalized.push(joined.replace(['(', ')'], ""));
                    index += used;
                }
            }
            for code in &normalized {
                let code = code.as_str();
                if let Some(captures) = star_import.captures(code) {
                    let dots = captures.get(1).map_or(0, |m| m.as_str().len());
                    let dotted = captures.get(2).map_or("", |m| m.as_str());
                    if dots == 0 && dotted.is_empty() {
                        continue;
                    }
                    if let Some(target) = resolve_module(dots, dotted) {
                        bindings.push(ImportBinding::Star { target });
                    }
                    continue;
                }
                if let Some(captures) = from_import.captures(code) {
                    let dots = captures.get(1).map_or(0, |m| m.as_str().len());
                    let dotted = captures.get(2).map_or("", |m| m.as_str());
                    let names = captures.get(3).map_or("", |m| m.as_str());
                    if dots == 0 && dotted.is_empty() {
                        continue;
                    }
                    let module_target = if dotted.is_empty() {
                        None
                    } else {
                        resolve_module(dots, dotted)
                    };
                    for entry in names.split(',') {
                        let entry = entry.trim();
                        let (exported, local) = match entry.split_once(" as ") {
                            Some((left, right)) => (left.trim(), right.trim()),
                            None => (entry, entry),
                        };
                        if !is_identifier(exported) || !is_identifier(local) {
                            continue;
                        }
                        // `from .pkg import service` may name a module.
                        let submodule = if dotted.is_empty() {
                            resolve_module(dots, exported)
                        } else {
                            resolve_module(dots, &format!("{dotted}.{exported}"))
                        };
                        if let Some(target) = submodule {
                            bindings.push(ImportBinding::Module {
                                binding: local.to_string(),
                                target,
                                exported_only: false,
                            });
                        } else if let Some(target) = module_target {
                            bindings.push(ImportBinding::Function {
                                local: local.to_string(),
                                exported: exported.to_string(),
                                target,
                            });
                        }
                    }
                    continue;
                }
                if let Some(captures) = plain_import.captures(code) {
                    let dotted = captures.get(1).map_or("", |m| m.as_str());
                    let binding = match captures.get(2) {
                        Some(alias) => alias.as_str().to_string(),
                        None if !dotted.contains('.') => dotted.to_string(),
                        None => continue,
                    };
                    if let Some(target) = resolve_module(0, dotted) {
                        bindings.push(ImportBinding::Module {
                            binding,
                            target,
                            exported_only: false,
                        });
                    }
                }
            }
        }
        _ => {}
    }
    bindings
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
        "parse::<i",
        "parse::<u",
        "parse::<f",
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
    request_flow_sink_lines(
        content,
        language,
        &sql_flow_sinks(language),
        contains_numeric_conversion,
    )
}

#[allow(clippy::items_after_test_module)]
fn sql_flow_sinks(language: FlowLanguage) -> Vec<FlowSink> {
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
        FlowLanguage::Rust => &[
            (
                r#"\bsqlx\s*::\s*(query|query_as|query_scalar|raw_sql)\s*\("#,
                first_argument,
            ),
            (
                r#"\b(?:conn|db|tx|pool|client|connection)\s*\.\s*(execute|query|query_row|query_map|query_one|query_opt|query_and_then|prepare|batch_execute)\s*\("#,
                first_argument,
            ),
        ],
    };
    patterns
        .iter()
        .filter_map(|(pattern, arguments)| {
            Regex::new(pattern).ok().map(|call| FlowSink {
                call,
                arguments: *arguments,
                line_requires: None,
            })
        })
        .collect()
}

#[allow(clippy::items_after_test_module)]
fn shell_command_argument(name: &str) -> Vec<usize> {
    match name {
        "Command" => vec![2],
        "CommandContext" => vec![3],
        _ => vec![2],
    }
}

#[allow(clippy::items_after_test_module)]
fn contains_command_sanitizer(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("shlex.quote(")
        || lower.contains("pipes.quote(")
        || contains_numeric_conversion(text)
}

/// Find OS command sinks whose command text is built from request input in
/// the same file.
///
/// Sources and propagation match the SQL injection model. Sinks are calls that
/// hand a command string to a shell: Python `os.system`/`os.popen`,
/// `subprocess.getoutput`, and `subprocess` calls with `shell=True`; Node
/// `child_process` `exec`/`execSync`; Java `Runtime.exec` and
/// `ProcessBuilder("sh", "-c", ...)`; Go `exec.Command("sh", "-c", ...)`;
/// Rust `Command::new("sh").arg("-c").arg(cmd)` single-line chains.
/// Argument-vector process calls without a shell are not sinks.
/// `shlex.quote` and numeric conversions stop the flow. Same-file and
/// straight-line only; no interprocedural claim.
#[allow(clippy::items_after_test_module)]
fn command_injection_sink_lines(
    content: &str,
    extension: &str,
) -> std::collections::HashSet<usize> {
    let Some(language) = flow_language(extension) else {
        return std::collections::HashSet::new();
    };
    request_flow_sink_lines(
        content,
        language,
        &command_flow_sinks(language),
        contains_command_sanitizer,
    )
}

#[allow(clippy::items_after_test_module)]
fn command_flow_sinks(language: FlowLanguage) -> Vec<FlowSink> {
    let shell_prefix = r#""(?:/bin/)?(?:sh|bash|zsh)"\s*,\s*"-c"|"cmd(?:\.exe)?"\s*,\s*"/c""#;
    let patterns: &[(&str, FlowArguments, Option<&str>)] = match language {
        FlowLanguage::Python => &[
            (r#"\bos\s*\.\s*(system|popen)\s*\("#, first_argument, None),
            (
                r#"\b(?:subprocess|commands)\s*\.\s*(getoutput|getstatusoutput)\s*\("#,
                first_argument,
                None,
            ),
            (
                r#"\bsubprocess\s*\.\s*(run|call|check_call|check_output|Popen)\s*\("#,
                first_argument,
                Some(r#"\bshell\s*=\s*True\b"#),
            ),
        ],
        FlowLanguage::JavaScript => &[
            (r#"(?:^|[^.\w$])(exec|execSync)\s*\("#, first_argument, None),
            (
                r#"\b(?:child_process|childProcess|cp)\s*\.\s*(exec|execSync)\s*\("#,
                first_argument,
                None,
            ),
        ],
        FlowLanguage::Java => &[
            (
                r#"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*(exec)\s*\("#,
                first_argument,
                None,
            ),
            (
                r#"\bnew\s+(ProcessBuilder)\s*\("#,
                shell_command_argument,
                Some(shell_prefix),
            ),
        ],
        FlowLanguage::Go => &[(
            r#"\bexec\s*\.\s*(Command|CommandContext)\s*\("#,
            shell_command_argument,
            Some(shell_prefix),
        )],
        FlowLanguage::Rust => &[(
            r#"\.\s*(arg)\s*\("#,
            first_argument,
            Some(
                r#"Command\s*::\s*new\s*\(\s*"(?:/bin/)?(?:sh|bash|zsh)"\s*\)\s*\.\s*arg\s*\(\s*"-c""#,
            ),
        )],
    };
    patterns
        .iter()
        .filter_map(|(pattern, arguments, requires)| {
            let call = Regex::new(pattern).ok()?;
            let line_requires = match requires {
                Some(required) => Some(Regex::new(required).ok()?),
                None => None,
            };
            Some(FlowSink {
                call,
                arguments: *arguments,
                line_requires,
            })
        })
        .collect()
}

#[allow(clippy::items_after_test_module)]
fn outbound_url_argument(name: &str) -> Vec<usize> {
    match name {
        "request" | "NewRequest" => vec![1],
        "NewRequestWithContext" => vec![2],
        _ => vec![0],
    }
}

/// Find outbound HTTP requests whose URL is built from request input in the
/// same file.
///
/// Sources and propagation match the SQL injection model. Only the URL
/// argument counts: Python `requests`/`httpx` calls and `urlopen`; JS
/// `fetch`, `axios`, `got`, and `http(s).get/request`; Java `new URL`,
/// `URI.create`, and `RestTemplate` calls; Go `http.Get/Post/Head/PostForm`
/// and `http.NewRequest*`; Rust `reqwest`/`ureq` `get`/`post`/... calls. A
/// request value sent only as a query parameter,
/// body, or header of a fixed URL is not reported. Host allowlists are not
/// modeled as sanitizers; numeric conversions stop the flow. Same-file and
/// straight-line only; no interprocedural claim.
#[allow(clippy::items_after_test_module)]
fn ssrf_sink_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    let Some(language) = flow_language(extension) else {
        return std::collections::HashSet::new();
    };
    request_flow_sink_lines(
        content,
        language,
        &ssrf_flow_sinks(language),
        contains_numeric_conversion,
    )
}

#[allow(clippy::items_after_test_module)]
fn ssrf_flow_sinks(language: FlowLanguage) -> Vec<FlowSink> {
    let patterns: &[&str] = match language {
        FlowLanguage::Python => &[
            r#"\b(?:requests|httpx|session|client)\s*\.\s*(get|post|put|delete|head|patch|options|request)\s*\("#,
            r#"\b(?:urllib\s*\.\s*request\s*\.\s*)?(urlopen)\s*\("#,
        ],
        FlowLanguage::JavaScript => &[
            r#"(?:^|[^.\w$])(fetch|got|axios)\s*\("#,
            r#"\baxios\s*\.\s*(get|post|put|delete|head|patch|request)\s*\("#,
            r#"\bhttps?\s*\.\s*(get|request)\s*\("#,
        ],
        FlowLanguage::Java => &[
            r#"\bnew\s+(URL)\s*\("#,
            r#"\bURI\s*\.\s*(create)\s*\("#,
            r#"\b[A-Za-z_]*[Rr]est[Tt]emplate\s*\.\s*(getForObject|getForEntity|postForObject|postForEntity|exchange)\s*\("#,
        ],
        FlowLanguage::Go => {
            &[r#"\bhttp\s*\.\s*(Get|Post|Head|PostForm|NewRequest|NewRequestWithContext)\s*\("#]
        }
        FlowLanguage::Rust => &[
            r#"\b(?:reqwest|ureq)\s*::\s*(get|post|put|delete|head|patch)\s*\("#,
            r#"\b(?:client|reqwest)\s*\.\s*(get|post|put|delete|head|patch|request)\s*\("#,
        ],
    };
