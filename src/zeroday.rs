use crate::finding::{
    Confidence, Finding, FindingReport, FindingType, OwaspCategory, RemediationEffort, Severity,
};
use crate::groq::GroqClient;
use crate::indexer;
use crate::output;
use crate::scan;
use anyhow::Result;
use colored::*;
use ignore::WalkBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::path::Path;

// ── Constants ───────────────────────────────────────────────────────

/// Maximum lines a function can have before being flagged as complex
const COMPLEXITY_THRESHOLD: usize = 80;

/// Conditionals/branch count threshold for complexity
const BRANCH_THRESHOLD: usize = 6;

/// Known input sources (variables/functions that bring untrusted data)
const TAINT_SOURCES: &[&str] = &[
    "request", "req", "params", "body", "query", "input",
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER",
    "ctx.request", "self.request", "this.request",
    "args", "kwargs", "argv", "stdin",
    "get_query_params", "get_json_args", "form_data",
    "request.data", "request.json", "request.form",
    "req.body", "req.query", "req.params",
    "getInput", "getParameter", "getQueryString",
    "HttpServletRequest", "HttpRequest",
];

/// Known dangerous sinks (functions that execute/query/write to system)
const TAINT_SINKS: &[&str] = &[
    "exec", "system", "popen", "eval", "assert",
    "query", "execute", "raw_query", "rawQuery",
    "open", "write", "delete", "chmod", "unlink",
    "fs.writeFile", "fs.writeFileSync", "fs.appendFile",
    "os.system", "subprocess.call", "subprocess.Popen",
    "shell_exec", "passthru", "proc_open",
    "runtime.exec", "ProcessBuilder",
    "cmd.exe", "/bin/sh", "/bin/bash",
];

/// Known sanitization/validation functions (breaks taint propagation)
const SANITIZERS: &[&str] = &[
    "sanitize", "validate", "escape", "filter",
    "htmlspecialchars", "htmlentities", "strip_tags",
    "escapeHtml", "escapeShellArg", "escapeshellarg",
    "encodeURI", "encodeURIComponent",
    "parseInt", "parseFloat", "Number",
    "intval", "floatval", "filter_var",
    "is_numeric", "ctype_digit", "preg_match",
    "str_replace", "preg_replace",
];

// ── Anomaly Types ───────────────────────────────────────────────────

/// Types of zero-day anomalies the detector can find
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyType {
    FunctionComplexity,
    DangerousApiProximity,
    MissingBoundaryCheck,
    TypeConfusionRisk,
    SuspiciousErrorHandling,
    TaintedPath,
    UntrustedToSink,
    BusinessLogicFlaw,
    RaceCondition,
}

impl AnomalyType {
    pub fn name(&self) -> &'static str {
        match self {
            AnomalyType::FunctionComplexity => "Function Complexity Anomaly",
            AnomalyType::DangerousApiProximity => "Dangerous API Proximity",
            AnomalyType::MissingBoundaryCheck => "Missing Boundary Check",
            AnomalyType::TypeConfusionRisk => "Type Confusion Risk",
            AnomalyType::SuspiciousErrorHandling => "Suspicious Error Handling",
            AnomalyType::TaintedPath => "Tainted Path Traversal",
            AnomalyType::UntrustedToSink => "Untrusted Data to Sink",
            AnomalyType::BusinessLogicFlaw => "Business Logic Flaw",
            AnomalyType::RaceCondition => "Potential Race Condition",
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            AnomalyType::FunctionComplexity => "anomaly",
            AnomalyType::DangerousApiProximity => "anomaly",
            AnomalyType::MissingBoundaryCheck => "anomaly",
            AnomalyType::TypeConfusionRisk => "anomaly",
            AnomalyType::SuspiciousErrorHandling => "anomaly",
            AnomalyType::TaintedPath => "flow",
            AnomalyType::UntrustedToSink => "flow",
            AnomalyType::BusinessLogicFlaw => "ai",
            AnomalyType::RaceCondition => "ai",
        }
    }
}

// ── Zero-Day Finding ────────────────────────────────────────────────

/// A zero-day anomaly finding with extra metadata
#[derive(Debug, Clone)]
pub struct ZerodayFinding {
    pub finding: Finding,
    pub anomaly_type: AnomalyType,
    pub risk_score: f64,
}

impl ZerodayFinding {
    pub fn new(
        anomaly_type: AnomalyType,
        title: &str,
        description: &str,
        severity: Severity,
        confidence: Confidence,
        file_path: &str,
        line_number: usize,
        code_snippet: &str,
        remediation: &str,
    ) -> Self {
        let finding_type = match anomaly_type {
            AnomalyType::BusinessLogicFlaw => FindingType::BusinessLogic,
            AnomalyType::DangerousApiProximity | AnomalyType::TypeConfusionRisk => {
                FindingType::Injection
            }
            AnomalyType::MissingBoundaryCheck => FindingType::Vulnerability,
            _ => FindingType::Vulnerability,
        };

        let risk = match severity {
            Severity::Critical => 9.0,
            Severity::High => 7.0,
            Severity::Medium => 5.0,
            Severity::Low => 3.0,
            Severity::Info => 1.0,
        };

        let exploitability = match confidence {
            Confidence::High => 0.7,
            Confidence::Medium => 0.5,
            Confidence::Low => 0.3,
        };

        let effort = match severity {
            Severity::Critical | Severity::High => RemediationEffort::Hours,
            _ => RemediationEffort::Minutes,
        };

        let mut finding = Finding::new(
            finding_type,
            format!("[ZERO-DAY] {}", title),
            description,
            severity,
            confidence,
            "zeroday",
        )
        .at(file_path, line_number)
        .with_code(code_snippet)
        .with_remediation(remediation)
        .with_exploitability(exploitability)
        .with_effort(effort);

        // Tag with stable CWE identifiers for triage workflows
        finding = finding.with_cwe(match anomaly_type {
            AnomalyType::TaintedPath => "CWE-22",
            AnomalyType::UntrustedToSink | AnomalyType::DangerousApiProximity => "CWE-74",
            AnomalyType::FunctionComplexity => "CWE-710",
            AnomalyType::MissingBoundaryCheck => "CWE-125",
            AnomalyType::TypeConfusionRisk => "CWE-843",
            AnomalyType::SuspiciousErrorHandling => "CWE-532",
            AnomalyType::BusinessLogicFlaw => "CWE-840",
            AnomalyType::RaceCondition => "CWE-362",
        });

        // Tag with appropriate OWASP category
        match anomaly_type {
            AnomalyType::DangerousApiProximity | AnomalyType::TaintedPath | AnomalyType::UntrustedToSink => {
                finding = finding.with_owasp(OwaspCategory::A03Injection);
            }
            AnomalyType::MissingBoundaryCheck => {
                finding = finding.with_owasp(OwaspCategory::A04InsecureDesign);
            }
            AnomalyType::TypeConfusionRisk => {
                finding = finding.with_owasp(OwaspCategory::A02CryptographicFailures);
            }
            AnomalyType::SuspiciousErrorHandling => {
                finding = finding.with_owasp(OwaspCategory::A09LoggingFailures);
            }
            AnomalyType::BusinessLogicFlaw => {
                finding = finding.with_owasp(OwaspCategory::A01BrokenAccessControl);
            }
            _ => {}
        }

        Self {
            finding,
            anomaly_type,
            risk_score: risk,
        }
    }
}

// ── Output Report ───────────────────────────────────────────────────

/// Full zero-day analysis report
pub struct ZerodayReport {
    pub anomalies: Vec<ZerodayFinding>,
    pub flow_findings: Vec<ZerodayFinding>,
    pub ai_findings: Vec<ZerodayFinding>,
    pub scanned_files: usize,
    pub project_path: String,
}

impl ZerodayReport {
    pub fn new(project_path: &str) -> Self {
        Self {
            anomalies: Vec::new(),
            flow_findings: Vec::new(),
            ai_findings: Vec::new(),
            scanned_files: 0,
            project_path: project_path.to_string(),
        }
    }

    pub fn total(&self) -> usize {
        self.anomalies.len() + self.flow_findings.len() + self.ai_findings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// Convert all findings into a FindingReport
    pub fn to_finding_report(&self) -> FindingReport {
        let mut report = FindingReport::new("zeroday", &self.project_path);
        for zf in &self.anomalies {
            report.add(zf.finding.clone());
        }
        for zf in &self.flow_findings {
            report.add(zf.finding.clone());
        }
        for zf in &self.ai_findings {
            report.add(zf.finding.clone());
        }
        report.sort_by_risk();
        report
    }

    pub fn print_summary(&self) {
        println!();
        println!(
            "  {} {}\n",
            "[!]".bright_yellow().bold(),
            "CipherAI Zero-Day Anomaly Scan Results".bold()
        );
        println!(
            "  {} Scanned {} source files",
            "[SCAN]".cyan(),
            self.scanned_files.to_string().bold()
        );

        let a = self.anomalies.len();
        let f = self.flow_findings.len();
        let ai = self.ai_findings.len();
        let total = self.total();

        println!(
            "  {} {} anomalies, {} flow issues, {} AI findings — {} total",
            "[FOUND]".cyan(),
            a.to_string().yellow(),
            f.to_string().yellow(),
            ai.to_string().yellow(),
            total.to_string().bold()
        );

        if total == 0 {
            println!();
            println!(
                "  {} No zero-day anomalies detected. Good — your code appears clean.",
                "[OK]".green().bold()
            );
            return;
        }

        // Print anomaly findings
        for zf in &self.anomalies {
            print_zeroday_finding(zf);
        }

        // Print flow findings
        for zf in &self.flow_findings {
            print_zeroday_finding(zf);
        }

        // Print AI findings
        for zf in &self.ai_findings {
            print_zeroday_finding(zf);
        }

        // Risk breakdown
        println!();
        println!("  {} Risk Distribution", "[STATS]".bright_blue().bold());
        println!("  {}", "-".repeat(40).dimmed());

        let all = self
            .anomalies
            .iter()
            .chain(self.flow_findings.iter())
            .chain(self.ai_findings.iter())
            .collect::<Vec<_>>();

        let critical = all.iter().filter(|f| f.finding.severity == Severity::Critical).count();
        let high = all.iter().filter(|f| f.finding.severity == Severity::High).count();
        let medium = all.iter().filter(|f| f.finding.severity == Severity::Medium).count();
        let low = all.iter().filter(|f| f.finding.severity == Severity::Low).count();

        println!(
            "  {} {}  {} {}  {} {}  {} {}  ({} total)",
            "CRITICAL".red().bold(),
            critical.to_string().red().bold(),
            "HIGH".yellow().bold(),
            high.to_string().yellow().bold(),
            "MEDIUM".cyan(),
            medium.to_string().cyan(),
            "LOW".dimmed(),
            low.to_string().dimmed(),
            total.to_string().bold()
        );

        println!();
        println!(
            "  {} These are NOVEL findings not caught by signature-based scanners.",
            "[ZERO-DAY]".bright_yellow().bold()
        );
        println!(
            "  {} Review each one manually — they may represent unknown vulnerabilities.",
            "[WARNING]".yellow()
        );
    }
}

fn print_zeroday_finding(zf: &ZerodayFinding) {
    println!();
    let category_tag = match zf.anomaly_type.category() {
        "anomaly" => "[ANOMALY]".bright_magenta(),
        "flow" => "[FLOW]".bright_red(),
        "ai" => "[AI-ZD]".bright_cyan(),
        _ => "[?]".dimmed(),
    };

    println!(
        "  {} {} [{}] {}",
        category_tag,
        zf.finding.severity.label(),
        zf.anomaly_type.name(),
        zf.finding.title.bold()
    );
    if let Some(ref fp) = zf.finding.file_path {
        let line_info = zf
            .finding
            .line_number
            .map(|l| format!(":{}", l))
            .unwrap_or_default();
        println!("    {} {}{}", "File:".bold().dimmed(), fp.yellow(), line_info);
    }
    if let Some(ref code) = zf.finding.code_snippet {
        for line in code.lines().take(3) {
            println!("    | {}", line.dimmed());
        }
        if code.lines().count() > 3 {
            println!(
                "    | {} more lines...",
                (code.lines().count() - 3).to_string().dimmed()
            );
        }
    }
    println!("    {}", zf.finding.description.trim());
    println!(
        "    {} Confidence: {} | Risk: {:.1}/10",
        "->".bold(),
        zf.finding.confidence.label(),
        zf.risk_score
    );
    if let Some(ref remediation) = zf.finding.remediation {
        println!("    {} {}", "Fix:".bold().green(), remediation.trim());
    }
}

// ── Layer 1: Anomaly Detection ──────────────────────────────────────

/// File-level analysis context
struct FileContext {
    path: String,
    lines: Vec<String>,
    ext: String,
}

/// Detect anomalies in a single file
fn detect_file_anomalies(ctx: &FileContext) -> Vec<ZerodayFinding> {
    let mut findings = Vec::new();

    // Run all anomaly detectors
    findings.extend(detect_complex_functions(ctx));
    findings.extend(detect_dangerous_proximity(ctx));
    findings.extend(detect_missing_boundary_checks(ctx));
    findings.extend(detect_type_confusion(ctx));
    findings.extend(detect_suspicious_error_handling(ctx));

    findings
}

/// Parse functions from source lines and detect complexity anomalies
fn detect_complex_functions(ctx: &FileContext) -> Vec<ZerodayFinding> {
    let mut findings = Vec::new();

    // Find function boundaries by tracking brace depth
    let mut brace_depth = 0i32;
    let mut current_func: Option<(usize, String)> = None;
    let mut func_lines: HashMap<usize, Vec<usize>> = HashMap::new(); // func_start_line -> line numbers

    for (i, line) in ctx.lines.iter().enumerate() {
        let line_num = i + 1;
        let trimmed = line.trim();

        // Detect function/block starts
        if is_function_signature(trimmed, &ctx.ext) {
            let name = extract_function_name(trimmed);
            current_func = Some((line_num, name));
            func_lines.insert(line_num, Vec::new());
        }

        // Track brace depth
        for ch in trimmed.chars() {
            match ch {
                '{' => {
                    brace_depth += 1;

                    // If this is the first opening brace after a function, map it
                    if brace_depth == 1 && current_func.is_none() {
                        // Anonymous block
                        current_func = Some((line_num, "<anonymous>".to_string()));
                        func_lines.insert(line_num, Vec::new());
                    }
                }
                '}' => {
                    brace_depth -= 1;
                    if brace_depth <= 0 && current_func.is_some() {
                        let (start, name) = current_func.take().unwrap();
                        let lines_in_func = func_lines.get(&start).map(|v| v.len()).unwrap_or(0);

                        // Check complexity
                        if lines_in_func > COMPLEXITY_THRESHOLD {
                            let start_line = start;
                            let snippet = get_snippet(&ctx.lines, start_line, 5);

                            findings.push(ZerodayFinding::new(
                                AnomalyType::FunctionComplexity,
                                &format!("Overly complex function: '{}' ({} lines)", name, lines_in_func),
                                &format!(
                                    "Function '{}' spans {} lines (threshold: {}). \
                                     Complex functions are prone to logic errors, missing edge cases, \
                                     and hard-to-spot vulnerabilities. Consider refactoring into smaller \
                                     focused functions.",
                                    name, lines_in_func, COMPLEXITY_THRESHOLD
                                ),
                                Severity::Medium,
                                Confidence::Medium,
                                &ctx.path,
                                start_line,
                                &snippet,
                                &format!(
                                    "Break '{}' into smaller functions (< {} lines each). \
                                     Extract separate concerns into named helper functions.",
                                    name, COMPLEXITY_THRESHOLD
                                ),
                            ));
                        }

                        // Check branch count
                        let branch_count = func_lines
                            .get(&start)
                            .map(|lns| {
                                lns.iter()
                                    .filter(|&&ln| {
                                        let t = ctx.lines[ln - 1].trim();
                                        t.starts_with("if")
                                            || t.starts_with("else if")
                                            || t.starts_with("elif")
                                            || t.starts_with("match")
                                            || t.starts_with("switch")
                                            || t.starts_with("case")
                                            || t.starts_with("for")
                                            || t.starts_with("while")
                                            || t.starts_with("catch")
                                    })
                                    .count()
                            })
                            .unwrap_or(0);

                        if branch_count > BRANCH_THRESHOLD {
                            let snippet = get_snippet(&ctx.lines, start, 5);
                            findings.push(ZerodayFinding::new(
                                AnomalyType::FunctionComplexity,
                                &format!(
                                    "High cyclomatic complexity in '{}' ({} branches)",
                                    name, branch_count
                                ),
                                &format!(
                                    "Function '{}' has {} conditional branches (threshold: {}). \
                                     High complexity correlates with hidden bugs and security \
                                     vulnerabilities. Attackers exploit edge cases in complex logic.",
                                    name, branch_count, BRANCH_THRESHOLD
                                ),
                                Severity::Medium,
                                Confidence::Low,
                                &ctx.path,
                                start,
                                &snippet,
                                "Restructure with early returns, guard clauses, and strategy pattern \
                                 to reduce branch density.",
                            ));
                        }
                    }
                }
                _ => {}
            }
        }

        // Track lines within current function (for counting)
        if let Some((start, _)) = &current_func {
            if let Some(lines) = func_lines.get_mut(start) {
                lines.push(line_num);
            }
        }

        // Reset depth tracking for each language
        if brace_depth < 0 {
            brace_depth = 0;
        }
    }

    findings
}

/// Detect dangerous API calls near user input handling
fn detect_dangerous_proximity(ctx: &FileContext) -> Vec<ZerodayFinding> {
    let mut findings = Vec::new();

    // Identify lines with source references
    let mut source_lines: Vec<usize> = Vec::new();
    // Identify lines with sink references
    let mut sink_lines: Vec<usize> = Vec::new();

    for (i, line) in ctx.lines.iter().enumerate() {
        let line_num = i + 1;
        let trimmed = line.trim();

        // Skip comments
        if is_comment(trimmed, &ctx.ext) {
            continue;
        }

        let lower = trimmed.to_lowercase();

        // Check for taint sources
        for src in TAINT_SOURCES {
            if lower.contains(&src.to_lowercase()) {
                source_lines.push(line_num);
                break;
            }
        }

        // Check for dangerous sinks
        for sink in TAINT_SINKS {
            if lower.contains(sink) {
                sink_lines.push(line_num);
                break;
            }
        }
    }

    // If both sources and sinks exist within 5 lines of each other, flag it
    for &src_line in &source_lines {
        for &sink_line in &sink_lines {
            let distance = if src_line > sink_line {
                src_line - sink_line
            } else {
                sink_line - src_line
            };

            if distance <= 5 && distance > 0 {
                let snippet = if src_line < sink_line {
                    get_snippet_range(&ctx.lines, src_line, sink_line)
                } else {
                    get_snippet_range(&ctx.lines, sink_line, src_line)
                };

                let near_line = std::cmp::max(src_line, sink_line) - 1;
                let snippet_line = if near_line > 0 { near_line } else { 1 };

                findings.push(ZerodayFinding::new(
                    AnomalyType::DangerousApiProximity,
                    "Dangerous API called near user-controlled data",
                    &format!(
                        "User input (line {}) is within {} lines of a dangerous API call (line {}). \
                         This pattern often leads to injection vulnerabilities that signature-based \
                         scanners miss because the data flow isn't direct concatenation.",
                        src_line, distance, sink_line
                    ),
                    Severity::High,
                    Confidence::Medium,
                    &ctx.path,
                    snippet_line,
                    &snippet,
                    "Ensure user input is validated and sanitized before reaching any \
                     execution/query/file APIs. Use parameterized APIs and input allowlists.",
                ));
                break; // One flag per source-sink pair
            }
        }
    }

    findings
}

/// Detect missing array/index boundary checks
fn detect_missing_boundary_checks(ctx: &FileContext) -> Vec<ZerodayFinding> {
    let mut findings = Vec::new();

    for (i, line) in ctx.lines.iter().enumerate() {
        let line_num = i + 1;
        let trimmed = line.trim();

        if is_comment(trimmed, &ctx.ext) {
            continue;
        }

        let lower = trimmed.to_lowercase();

        // Look for unchecked array access patterns
        let has_unchecked_access = {
            let unchecked = [
                "array[", "list[", "vector[", "arr[", "data[", "items[",
                "results[", "records[", "rows[",
            ];
            unchecked.iter().any(|p| lower.contains(p))
        };

        if !has_unchecked_access {
            continue;
        }

        // Check if there's a length/bounds check nearby (within previous 4 lines)
        let start = if i >= 4 { i - 4 } else { 0 };
        let has_bounds_check = (start..i).any(|j| {
            let prev_lower = ctx.lines[j].trim().to_lowercase();
            prev_lower.contains(".len()")
                || prev_lower.contains(".length")
                || prev_lower.contains("count(")
                || prev_lower.contains("sizeof")
                || prev_lower.contains("is_empty")
                || prev_lower.contains("isempty")
                || prev_lower.contains("isset(")
                || prev_lower.contains("array_key_exists")
                || prev_lower.contains("in_array")
                || prev_lower.contains("contains_key")
                || prev_lower.contains("has_index")
        });

        if !has_bounds_check {
            findings.push(ZerodayFinding::new(
                AnomalyType::MissingBoundaryCheck,
                "Array/list access without bounds check",
                &format!(
                    "Line {} accesses an array/list/vector index without a preceeding bounds \
                     or length check. This can cause panics, out-of-bounds reads, or memory \
                     safety issues — especially with untrusted input.",
                    line_num
                ),
                Severity::High,
                Confidence::Low,
                &ctx.path,
                line_num,
                trimmed,
                "Always check array bounds before access: verify .len() > index or use \
                 safe access methods like .get() that return Option/Maybe types.",
            ));
        }
    }

    findings
}

/// Detect type confusion risks (unsafe transmutes, any casts)
fn detect_type_confusion(ctx: &FileContext) -> Vec<ZerodayFinding> {
    let mut findings = Vec::new();

    for (i, line) in ctx.lines.iter().enumerate() {
        let line_num = i + 1;
        let trimmed = line.trim();

        if is_comment(trimmed, &ctx.ext) {
            continue;
        }

        let lower = trimmed.to_lowercase();

        // Pattern 1: Unsafe transmute
        if lower.contains("transmute") || lower.contains("mem::transmute") {
            findings.push(ZerodayFinding::new(
                AnomalyType::TypeConfusionRisk,
                "Unsafe type transmute detected",
                &format!(
                    "Line {} uses transmute() which reinterprets bytes of one type as another. \
                     This is a leading cause of undefined behavior and memory safety vulnerabilities.",
                    line_num
                ),
                Severity::High,
                Confidence::High,
                &ctx.path,
                line_num,
                trimmed,
                "Avoid transmute() where possible. Use From/Into traits, safe casts, \
                 or crates like 'bytemuck' that provide checked transmutation.",
            ));
        }

        // Pattern 2: Unsafe pointer dereference near data
        if lower.contains("*const ") || lower.contains("*mut ") || lower.contains("as *mut") {
            // Check if near any data handling
            let start = if i >= 3 { i - 3 } else { 0 };
            let end = std::cmp::min(i + 3, ctx.lines.len());
            let has_data_nearby = (start..end).any(|j| {
                if j == i {
                    return false;
                }
                let nl = ctx.lines[j].trim().to_lowercase();
                TAINT_SOURCES
                    .iter()
                    .any(|s| nl.contains(&s.to_lowercase()))
            });

            if has_data_nearby {
                findings.push(ZerodayFinding::new(
                    AnomalyType::TypeConfusionRisk,
                    "Unsafe pointer near data handling",
                    &format!(
                        "Line {} uses unsafe pointer operations near data handling. \
                         This combination can lead to type confusion, use-after-free, \
                         and memory corruption vulnerabilities.",
                        line_num
                    ),
                    Severity::Critical,
                    Confidence::Medium,
                    &ctx.path,
                    line_num,
                    trimmed,
                    "Minimize unsafe code. Wrap unsafe operations in safe abstractions \
                     with thorough safety invariants and validation.",
                ));
            }
        }

        // Pattern 3: 'any' type casts (TypeScript/JS)
        if ctx.ext == "ts" || ctx.ext == "tsx" || ctx.ext == "js" || ctx.ext == "jsx" {
            if lower.contains("as any") || lower.contains("@ts-ignore") {
                findings.push(ZerodayFinding::new(
                    AnomalyType::TypeConfusionRisk,
                    "Type-safety bypass: 'any' cast or @ts-ignore",
                    &format!(
                        "Line {} bypasses type checking with 'as any' or @ts-ignore. \
                         This hides potential type confusion bugs from the compiler.",
                        line_num
                    ),
                    Severity::Medium,
                    Confidence::Medium,
                    &ctx.path,
                    line_num,
                    trimmed,
                    "Use proper type definitions instead of 'any'. If you must use it, \
                     add validation at the boundary to ensure the value has the expected shape.",
                ));
            }
        }
    }

    findings
}

/// Detect suspicious error handling (bare catch, silent failures)
fn detect_suspicious_error_handling(ctx: &FileContext) -> Vec<ZerodayFinding> {
    let mut findings = Vec::new();

    let mut in_catch_block = false;
    let mut catch_start = 0;
    let mut catch_line = "";
    let mut catch_brace_depth = 0;

    for (i, line) in ctx.lines.iter().enumerate() {
        let line_num = i + 1;
        let trimmed = line.trim();

        if is_comment(trimmed, &ctx.ext) {
            continue;
        }

        let lower = trimmed.to_lowercase();

        // Detect catch/try/except blocks
        if lower.starts_with("catch")
            || lower.starts_with("except")
            || lower.starts_with("rescue")
            || trimmed.starts_with("} catch")
        {
            in_catch_block = true;
            catch_start = line_num;
            catch_line = trimmed;
            catch_brace_depth = 0;
            continue;
        }

        if in_catch_block {
            // Count braces
            for ch in trimmed.chars() {
                match ch {
                    '{' => catch_brace_depth += 1,
                    '}' => {
                        catch_brace_depth -= 1;
                        if catch_brace_depth < 0 {
                            // End of catch block
                            // Check if it was empty/too small
                            let block_lines = line_num - catch_start;
                            if block_lines <= 2 && !lower.contains("log") && !lower.contains("error") {
                                findings.push(ZerodayFinding::new(
                                    AnomalyType::SuspiciousErrorHandling,
                                    "Bare/silent catch block — errors swallowed",
                                    &format!(
                                        "Line {}: catch block ({} lines) has no logging or handling. \
                                         Silently swallowing exceptions hides security-relevant errors \
                                         from monitoring and debugging.",
                                        catch_start, block_lines + 1
                                    ),
                                    Severity::High,
                                    Confidence::High,
                                    &ctx.path,
                                    catch_start,
                                    catch_line,
                                    "Always log or handle errors in catch blocks. At minimum, \
                                     log the error message. For security-critical operations, \
                                     implement proper error recovery and alerting.",
                                ));
                            }
                            in_catch_block = false;
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Flag 'except: pass' pattern (Python hiding errors)
        if ctx.ext == "py" {
            if trimmed.starts_with("except") && trimmed.contains(":") && !trimmed.contains("log") {
                // Check next line
                if i + 1 < ctx.lines.len() {
                    let next = ctx.lines[i + 1].trim();
                    if next == "pass" || next.starts_with("#") {
                        findings.push(ZerodayFinding::new(
                            AnomalyType::SuspiciousErrorHandling,
                            "Pass on exception — error silently ignored",
                            &format!(
                                "Line {}: '{}' followed by 'pass'. Silently ignoring exceptions \
                                 can hide security breaches during error conditions.",
                                line_num, trimmed
                            ),
                            Severity::High,
                            Confidence::High,
                            &ctx.path,
                            line_num,
                            trimmed,
                            "At minimum log the exception. For security-critical code, \
                             implement proper error recovery with monitoring alerts.",
                        ));
                    }
                }
            }
        }
    }

    findings
}

// ── Layer 2: Cross-Flow Taint Analysis ──────────────────────────────

/// Analyze taint flow in a file: track data from source to sink
fn detect_taint_flow(ctx: &FileContext) -> Vec<ZerodayFinding> {
    let mut findings = Vec::new();
    let mut tainted_vars: HashMap<String, usize> = HashMap::new(); // var_name -> line defined

    for (i, line) in ctx.lines.iter().enumerate() {
        let line_num = i + 1;
        let trimmed = line.trim();

        if is_comment(trimmed, &ctx.ext) {
            continue;
        }

        let lower = trimmed.to_lowercase();

        // Step 1: Detect assignments from taint sources
        for src in TAINT_SOURCES {
            if lower.contains(&src.to_lowercase()) {
                // Extract the variable being assigned
                if let Some(var_name) = extract_assigned_var(trimmed) {
                    tainted_vars.insert(var_name.to_lowercase(), line_num);
                } else if let Some(var_name) = extract_function_param(trimmed, src) {
                    tainted_vars.insert(var_name.to_lowercase(), line_num);
                }
                break;
            }
        }

        // Step 2: Propagate taint through assignments
        // If line is `x = y` and y is tainted, x becomes tainted
        for (tainted_var, def_line) in tainted_vars.clone().iter() {
            if lower.contains(tainted_var) && trimmed.contains('=') {
                if let Some(new_var) = extract_assigned_var(trimmed) {
                    tainted_vars.insert(new_var.to_lowercase(), *def_line);
                }
            }
        }

        // Step 3: Check if any tainted variable reaches a sink
        for tainted_var in tainted_vars.keys() {
            let var_lower = tainted_var.to_lowercase();
            for sink in TAINT_SINKS {
                if lower.contains(sink) && (lower.contains(&var_lower) || trimmed.contains(&var_lower)) {
                    // Check if there's sanitization nearby
                    // Look up when this variable was defined
                    if let Some(&def_line) = tainted_vars.get(tainted_var) {
                    let start = if i >= 3 { i - 3 } else { 0 };
                    let has_sanitizer = (start..=i).any(|j| {
                        let prev_lower = ctx.lines[j].trim().to_lowercase();
                        SANITIZERS.iter().any(|s| prev_lower.contains(s))
                    });

                    if !has_sanitizer {
                        let snippet = get_snippet_range(&ctx.lines, def_line, line_num);
                        let risk = if sink == &"exec" || sink == &"system" || sink == &"eval" {
                            Severity::Critical
                        } else {
                            Severity::High
                        };

                        findings.push(ZerodayFinding::new(
                            AnomalyType::UntrustedToSink,
                            &format!(
                                "Untrusted data '{}' reaches dangerous sink: {}",
                                tainted_var, sink
                            ),
                            &format!(
                                "Variable '{}' (defined at line {}) from user input reaches '{}' \
                                 at line {} without passing through any validation/sanitization. \
                                 This is a novel injection vector — no known signature matches this \
                                 specific data flow path.",
                                tainted_var, def_line, sink, line_num
                            ),
                            risk,
                            Confidence::Medium,
                            &ctx.path,
                            def_line,
                            &snippet,
                            &format!(
                                "Add validation before '{}' is used by '{}'. Use an allowlist \
                                 for expected values and reject anything that doesn't match. \
                                 Consider using parameterized APIs instead.",
                                tainted_var, sink
                            ),
                        ));
                    }
                    }
                    break;
                }
            }
        }

        // Check for path traversal via concatenation
        let has_path_source = TAINT_SOURCES
            .iter()
            .any(|s| lower.contains(&s.to_lowercase()));
        let has_path_sink = ["open(", "fopen(", "readfile(", "file_get_contents", "fs::read", "File::open"]
            .iter()
            .any(|s| lower.contains(s));

        if has_path_source && has_path_sink {
            let has_sanitizer_nearby = (if i >= 5 { i - 5 } else { 0 }..std::cmp::min(i + 2, ctx.lines.len()))
                .any(|j| {
                    let pl = ctx.lines[j].trim().to_lowercase();
                    pl.contains("..")
                        || pl.contains("basename")
                        || pl.contains("realpath")
                        || pl.contains("canonicalize")
                        || pl.contains("sanitize")
                });

            if !has_sanitizer_nearby {
                findings.push(ZerodayFinding::new(
                    AnomalyType::TaintedPath,
                    "User-controlled path reaches file operation without validation",
                    &format!(
                        "Line {} uses user-controlled data in a file operation without path \
                         validation. This is a potential path traversal vulnerability that \
                         allows reading/writing arbitrary files.",
                        line_num
                    ),
                    Severity::Critical,
                    Confidence::Medium,
                    &ctx.path,
                    line_num,
                    trimmed,
                    "Validate file paths: reject paths with '..' or absolute paths, \
                     use an allowlist of permitted paths, or use a chroot/jail mechanism.",
                ));
            }
        }
    }

    findings
}

// ── Layer 3: AI Zero-Day Hunter ─────────────────────────────────────

/// Run AI-powered zero-day analysis on the indexed codebase
async fn run_ai_zeroday(
    project_path: &Path,
    model: Option<&str>,
    progress: &ProgressBar,
) -> Result<Vec<ZerodayFinding>> {
    progress.set_message("Connecting to AI for zero-day analysis...");

    let index = match indexer::load_index(project_path)? {
        Some(idx) => idx,
        None => return Ok(Vec::new()),
    };

    let client = match GroqClient::from_env() {
        Ok(c) => c,
        Err(_) => {
            progress.finish_and_clear();
            return Ok(Vec::new());
        }
    };

    // Build queries focused on novel/unknown vulnerabilities
    let zeroday_queries = [
        "authentication bypass login logic flaw race condition",
        "authorization privilege escalation business logic",
        "input validation sanitization injection novel path",
        "race condition TOCTOU time-of-check time-of-use",
        "cryptographic weakness nonce randomness prediction",
        "session token management insecure state",
        "error handling information leakage exception path",
        "business logic money payment rate limit bypass",
        "access control horizontal privilege escalation",
        "unsafe deserialization type confusion memory",
    ];

    let mut reviewed_chunks = std::collections::HashSet::new();
    let mut context = String::new();

    for query in &zeroday_queries {
        if reviewed_chunks.len() >= 50 {
            break;
        }
        progress.set_message(format!("AI analyzing: {}...", &query[..std::cmp::min(query.len(), 40)]));

        let results = indexer::search_index(&index, query, 3);
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
        return Ok(Vec::new());
    }

    progress.finish_and_clear();

    let system_prompt = r#"You are Cipher, an expert in finding ZERO-DAY vulnerabilities — novel, unknown security flaws that no existing scanner or signature would catch.

Your mission: analyze the provided code and identify **truly novel vulnerabilities** that:
1. No regex pattern or signature would detect (not SQLi, not XSS, not hardcoded keys)
2. Are business logic flaws, subtle authentication bypasses, race conditions, or design-level weaknesses
3. Could be chained with other issues for a real attack

For each zero-day vulnerability you find, respond in this JSON format:
{
  "findings": [
    {
      "title": "Short title (prefix with [ZERO-DAY] for truly novel issues)",
      "description": "Detailed explanation including why this is novel/undetectable by signatures",
      "type": "business-logic|race-condition|authentication|authorization|injection|cryptography|design-flaw",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "confidence": "HIGH|MEDIUM|LOW",
      "file_path": "relative/path/to/file.rs",
      "line_number": 42,
      "remediation": "How to fix this novel vulnerability"
    }
  ]
}

CRITICAL GUIDELINES:
- ONLY report issues you are confident are real
- Focus on novel patterns: logic flaws, design weaknesses, subtle bypasses
- PREFER HIGH/MEDIUM confidence over guessing
- If you find nothing novel, return {"findings": []}
- Respond with ONLY the JSON, no other text"#;

    let user_prompt = format!(
        r#"Analyze this code for ZERO-DAY vulnerabilities — novel, unknown patterns that no signature-based scanner would detect:

{context}

Focus on: business logic flaws, race conditions, auth bypasses, design-level weaknesses, and subtle data validation gaps.
Return ONLY valid JSON with your findings. If nothing novel found, return {{"findings": []}}."#
    );

    let response = client
        .chat(system_prompt, &user_prompt, model)
        .await
        .map_err(|e| anyhow::anyhow!("AI zero-day analysis failed: {}", e))?;

    parse_ai_zeroday_findings(&response, project_path)
}

/// Parse AI JSON response into ZerodayFinding objects
fn parse_ai_zeroday_findings(response: &str, project_path: &Path) -> Result<Vec<ZerodayFinding>> {
    let json_str = if let Some(start) = response.find("{\"findings\"") {
        let end = response[start..]
            .rfind('}')
            .map(|i| start + i + 1)
            .unwrap_or(response.len());
        &response[start..end]
    } else {
        return Ok(Vec::new());
    };

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
    }

    #[derive(serde::Deserialize)]
    struct AiResponse {
        findings: Vec<AiFinding>,
    }

    let ai_response: AiResponse = match serde_json::from_str(json_str) {
        Ok(r) => r,
        Err(_) => return Ok(Vec::new()),
    };

    let mut findings = Vec::new();

    for af in ai_response.findings {
        let title = af.title.unwrap_or_else(|| "Unknown zero-day vulnerability".to_string());
        let description = af.description.unwrap_or_default();
        let severity = parse_zeroday_severity(&af.severity.unwrap_or_default());
        let confidence = parse_zeroday_confidence(&af.confidence.unwrap_or_default());
        let anomaly_type = match af.finding_type.as_deref() {
            Some("race-condition") => AnomalyType::RaceCondition,
            Some("business-logic") => AnomalyType::BusinessLogicFlaw,
            _ => AnomalyType::BusinessLogicFlaw,
        };

        let (file_path, line_number) = match af.file_path {
            Some(fp) => {
                let full_path = project_path.join(&fp);
                (full_path.to_string_lossy().to_string(), af.line_number.unwrap_or(0))
            }
            None => continue,
        };

        findings.push(ZerodayFinding::new(
            anomaly_type,
            &title,
            &description,
            severity,
            confidence,
            &file_path,
            line_number,
            "",
            af.remediation.as_deref().unwrap_or("Review and fix manually"),
        ));
    }

    Ok(findings)
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Check if a line is a function signature
pub fn is_function_signature(line: &str, ext: &str) -> bool {
    let lower = line.to_lowercase();
    // Rust
    if lower.starts_with("fn ") && lower.contains('(') {
        return true;
    }
    // Python
    if lower.starts_with("def ") && lower.contains('(') && lower.ends_with(':') {
        return true;
    }
    // JavaScript/TypeScript
    if ext == "js" || ext == "jsx" || ext == "ts" || ext == "tsx" {
        if lower.starts_with("function ") && lower.contains('(') {
            return true;
        }
        if lower.contains("= function(") || lower.contains("= (") && lower.contains(") =>") {
            return true;
        }
        if lower.starts_with("async function") && lower.contains('(') {
            return true;
        }
    }
    // Go
    if ext == "go" && lower.starts_with("func ") && lower.contains('(') {
        return true;
    }
    // Java/C#/Kotlin/C++
    let sig_keywords = ["public ", "private ", "protected ", "internal "];
    if sig_keywords.iter().any(|k| lower.contains(k)) && lower.contains('(') && lower.contains(')') {
        return true;
    }
    // PHP
    if ext == "php" && lower.starts_with("function ") && lower.contains('(') {
        return true;
    }
    // Ruby
    if ext == "rb" && lower.starts_with("def ") && lower.contains('(') && lower.ends_with(')') {
        return true;
    }

    false
}

/// Extract function name from a signature line
pub fn extract_function_name(line: &str) -> String {
    let lower = line.trim().to_lowercase();

    // Try common patterns
    for keyword in &["fn ", "function ", "def ", "func "] {
        if let Some(idx) = lower.find(keyword) {
            let after = &line[idx + keyword.len()..].trim();
            if let Some(paren) = after.find('(') {
                // Handle generics: <T>
                let name_part = &after[..paren].trim();
                // Remove generics from name
                if let Some(gt) = name_part.find('<') {
                    return name_part[..gt].trim().to_string();
                }
                return name_part.to_string();
            }
        }
    }

    "<anonymous>".to_string()
}

/// Extract variable name from an assignment (e.g., "let x = foo" -> "x")
pub fn extract_assigned_var(line: &str) -> Option<String> {
    let trimmed = line.trim();

    // Pattern: let/mut/var/const x = ...
    // Put longer patterns first so "let mut " is checked before "let "
    for keyword in &["let mut ", "let ", "var ", "const ", "val ", "final "]
    {
        if trimmed.to_lowercase().starts_with(keyword) {
            let after = &trimmed[keyword.len()..].trim();
            if let Some(eq) = after.find('=') {
                let var_part = after[..eq].trim();
                // Remove type annotation and other noise
                if let Some(colon) = var_part.find(':') {
                    return Some(var_part[..colon].trim().to_string());
                }
                // Handle destructuring patterns
                if var_part.contains('{') || var_part.contains('(') || var_part.starts_with('[') {
                    return None; // Skip destructuring
                }
                return Some(var_part.to_string());
            }
        }
    }

    // Pattern: x = ... (simple assignment)
    if !trimmed.starts_with("if")
        && !trimmed.starts_with("for")
        && !trimmed.starts_with("while")
        && trimmed.contains('=')
        && !trimmed.contains("==")
        && !trimmed.contains("!=")
        && !trimmed.contains("<=")
        && !trimmed.contains(">=")
    {
        if let Some(eq) = trimmed.find('=') {
            let var_part = trimmed[..eq].trim();
            // Must be a simple identifier
            if var_part.is_empty() || var_part.contains(' ') || var_part.contains('(') {
                return None;
            }
            return Some(var_part.to_string());
        }
    }

    None
}

/// Extract a parameter from a function definition that receives tainted input
fn extract_function_param(line: &str, source_keyword: &str) -> Option<String> {
    let trimmed = line.trim();

    // Find the source keyword in the line
    let lower = trimmed.to_lowercase();
    let keyword_lower = source_keyword.to_lowercase();
    let pos = lower.find(&keyword_lower)?;

    // Look backwards from the keyword for the parameter name
    let before = &trimmed[..pos];
    if let Some(param_end) = before.rfind(|c: char| c == ',' || c == '(') {
        let param = before[param_end + 1..].trim();
        if !param.is_empty() && !param.contains(' ') && !param.contains('=') {
            return Some(param.to_string());
        }
    }

    None
}

/// Get a snippet from the code
fn get_snippet(lines: &[String], start_line: usize, max_lines: usize) -> String {
    let start = if start_line > 0 { start_line - 1 } else { 0 };
    let end = std::cmp::min(start + max_lines, lines.len());
    if start < end {
        lines[start..end].join("\n")
    } else {
        String::new()
    }
}

/// Get a snippet spanning from start to end line
fn get_snippet_range(lines: &[String], start_line: usize, end_line: usize) -> String {
    let start = if start_line > 0 { start_line - 1 } else { 0 };
    let end = std::cmp::min(end_line, lines.len());
    if start < end {
        lines[start..end].join("\n")
    } else {
        String::new()
    }
}

/// Check if a line is a comment
pub fn is_comment(line: &str, _ext: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with("--")
        || trimmed.is_empty()
}

// ── Severity/Confidence Parsers ─────────────────────────────────────

fn parse_zeroday_severity(s: &str) -> Severity {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

fn parse_zeroday_confidence(s: &str) -> Confidence {
    match s.to_uppercase().as_str() {
        "HIGH" => Confidence::High,
        "MEDIUM" => Confidence::Medium,
        _ => Confidence::Low,
    }
}

// ── External API ────────────────────────────────────────────────────

/// Scan for zero-day anomalies without any output (for use by other commands)
///
/// Runs layers 1 (Anomaly Detection) and 2 (Taint Flow Analysis) silently.
/// Layer 3 (AI) is only run if `use_ai` is true.
pub async fn collect_zeroday_findings(
    project_path: &Path,
    anomaly_only: bool,
    no_flow: bool,
) -> Result<ZerodayReport> {
    let canonical_path = std::fs::canonicalize(project_path)?;
    let mut report = ZerodayReport::new(&canonical_path.to_string_lossy());

    let walker = WalkBuilder::new(&canonical_path)
        .git_ignore(true)
        .git_global(true)
        .hidden(false)
        .max_depth(Some(scan::MAX_WALK_DEPTH))
        .build();

    for result in walker {
        if report.scanned_files >= scan::MAX_SCAN_FILES {
            break;
        }

        match result {
            Ok(entry) => {
                let path = entry.path();
                if path.is_file() && !scan::should_exclude(path) && !scan::is_binary(path) {
                    let ext = path
                        .extension()
                        .map(|e| e.to_str().unwrap_or("").to_lowercase())
                        .unwrap_or_default();
                    if !ext.is_empty() && is_supported_ext(&ext) {
                        match std::fs::read_to_string(path) {
                            Ok(content) => {
                                let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
                                let ctx = FileContext {
                                    path: path.to_string_lossy().to_string(),
                                    lines,
                                    ext,
                                };

                                // Layer 1: Anomaly Detection (always runs)
                                let anomalies = detect_file_anomalies(&ctx);
                                report.anomalies.extend(anomalies);

                                // Layer 2: Taint Flow Analysis
                                if !no_flow && !anomaly_only {
                                    let flow = detect_taint_flow(&ctx);
                                    report.flow_findings.extend(flow);
                                }
                            }
                            Err(_) => {}
                        }
                        report.scanned_files += 1;
                    }
                }
            }
            Err(_) => {}
        }
    }

    report.anomalies.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap_or(std::cmp::Ordering::Equal));
    report.flow_findings.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap_or(std::cmp::Ordering::Equal));

    Ok(report)
}

/// Run the `cipher-ai zeroday` command
///
/// Detects zero-day vulnerabilities across 3 layers:
/// 1. Anomaly Detection (static code analysis)
/// 2. Taint Flow Analysis (source→sink tracking)
/// 3. AI Zero-Day Hunter (LLM-based novel vuln search)
pub async fn run_zeroday(
    project_path: &Path,
    use_ai: bool,
    model: Option<&str>,
    format: &str,
    output: Option<&str>,
    anomaly_only: bool,
    no_flow: bool,
) -> Result<()> {
    let canonical_path = std::fs::canonicalize(project_path)?;

    output::print_header("Zero-Day Vulnerability Analysis", Some("3-layer novel vulnerability detection"));
    output::print_info("Layers", &format!(
        "{}{}{}",
        "Anomaly Detection".bold(),
        if !no_flow { " + Taint Flow Analysis".to_string() } else { String::new() },
        if use_ai { " + AI Zero-Day Hunter".to_string() } else { String::new() },
    ));

    // Use the shared collection function
    let mut report = collect_zeroday_findings(project_path, anomaly_only, no_flow).await?;
    report.project_path = canonical_path.to_string_lossy().to_string();

    // Layer 3: AI Zero-Day Hunter
    if use_ai {
        let ai_spinner = ProgressBar::new_spinner();
        ai_spinner.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} Running AI zero-day analysis...")
                .unwrap(),
        );
        ai_spinner.enable_steady_tick(std::time::Duration::from_millis(100));

        match run_ai_zeroday(&canonical_path, model, &ai_spinner).await {
            Ok(ai_findings) => {
                report.ai_findings = ai_findings;
                if !report.ai_findings.is_empty() {
                    output::print_ok("AI Hunter", &format!(
                        "found {} novel zero-day candidates",
                        report.ai_findings.len().to_string().bold()
                    ));
                }
            }
            Err(e) => {
                output::print_warn("AI Hunter", &format!(
                    "analysis failed: {} (continuing with static analysis)", e
                ));
            }
        }
    }

    // Handle output format
    if format == "json" || format == "sarif" {
        let finding_report = report.to_finding_report();
        let output_str = if format == "sarif" {
            crate::review::generate_sarif(&finding_report, &canonical_path)
        } else {
            crate::review::generate_review_json(&finding_report)
        };

        if let Some(out_path) = output {
            std::fs::write(out_path, &output_str)?;
            output::print_ok("Output", &format!(
                "{} written to {}",
                format.to_uppercase().yellow().bold(),
                out_path.yellow()
            ));
        } else {
            println!("{}", output_str);
        }
        output::print_footer();
        return Ok(());
    }

    // Print the report
    report.print_summary();

    // Recommendations
    if !report.is_empty() {
        output::print_recommendations(&[
            "Run cipher-ai attack to see if these findings connect into an attack chain",
            "Use cipher-ai ask for deeper AI analysis on specific anomalies",
            "Review each finding manually — they represent potentially unknown vulnerabilities",
        ]);
    }

    output::print_footer();
    Ok(())
}

/// Supported file extensions for zero-day scanning
fn is_supported_ext(ext: &str) -> bool {
    matches!(
        ext,
        "rs" | "js" | "jsx" | "ts" | "tsx" | "py" | "go" | "rb" | "java" | "kt"
            | "swift" | "c" | "cpp" | "h" | "hpp" | "cs" | "php" | "sh" | "bash"
            | "vue" | "svelte" | "dart" | "scala" | "lua"
    )
}
