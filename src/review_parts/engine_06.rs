#[cfg(test)]
mod policy_view_tests {
    use super::*;

    fn inj(file: &str) -> Finding {
        Finding::new(
            FindingType::Injection,
            "SQL Injection",
            "d",
            Severity::High,
            Confidence::High,
            "r",
        )
        .at(file, 4)
    }

    #[test]
    fn policy_view_relativizes_paths_under_root() {
        let root = std::path::Path::new("/repo");
        let under = inj("/repo/src/app.rs");
        let outside = inj("/other/app.rs");
        let viewed = policy_findings_view(&[under, outside], root);
        assert_eq!(viewed[0].file_path.as_deref(), Some("src/app.rs"));
        // Paths outside the scanned root are left untouched.
        assert_eq!(viewed[1].file_path.as_deref(), Some("/other/app.rs"));
        // The relativized view fingerprints exactly like a natively relative finding.
        assert_eq!(
            stable_fingerprints(&viewed[..1]),
            stable_fingerprints(&[inj("src/app.rs")])
        );
    }
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
                downgrade_test_context(&mut report.findings, &canonical_path);
                mark_deployment_context(&mut report.findings, &canonical_path);
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
        let policy_findings = policy_findings_view(&report.findings, &canonical_path);
        let baseline = crate::policy::Policy::baseline_from(&policy_findings);
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
        let policy_findings = policy_findings_view(&report.findings, &canonical_path);
        let evaluation = policy.evaluate(&policy_findings)?;
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
            | "erb"
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
            | "properties"
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

/// Emit escaped repository-relative URIs even when a reported source no longer exists.
fn sarif_source_uri(file: Option<&str>, root: &Path) -> String {
    let Some(file) = file else {
        return ".".to_string();
    };
    let root = root.to_string_lossy().replace('\\', "/");
    let file = file.replace('\\', "/");
    let relative = file
        .strip_prefix(&format!("{}/", root.trim_end_matches('/')))
        .unwrap_or(&file);
    let uri = if Path::new(relative).is_absolute() || relative.as_bytes().get(1) == Some(&b':') {
        format!("file:///{relative}")
    } else {
        relative.to_string()
    };
    uri.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"/-._~:".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
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
            let file_uri = sarif_source_uri(f.file_path.as_deref(), project_path);

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
                        "{}\n\n**Remediation:** {}\n\n**Source-to-sink path:** {}",
                        f.description,
                        f.remediation.as_deref().unwrap_or("Not specified"),
                        f.source_to_sink
                            .as_ref()
                            .map(|steps| steps
                                .iter()
                                .map(|step| format!(
                                    "{}:{} [{}] {}",
                                    step.file, step.line, step.action, step.detail
                                ))
                                .collect::<Vec<_>>()
                                .join(" -> "))
                            .unwrap_or_else(|| "Not established by analysis.".to_string())
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
include!("scanner_regression_tests_01.rs");
include!("scanner_regression_tests_02.rs");
include!("scanner_regression_tests_03.rs");
include!("scanner_regression_tests_04.rs");
include!("scanner_regression_tests_05.rs");
include!("scanner_regression_tests_06.rs");
include!("scanner_regression_tests_07.rs");
include!("scanner_regression_tests_08.rs");
}

/// Lines that end with `execute_sql(` whose next non-blank line starts with an
/// ALL-CAPS constant argument (`MULTI, chunked_fetch=...`).
fn wrapped_constant_execute_sql_lines(content: &str) -> std::collections::HashSet<usize> {
    let mut found = std::collections::HashSet::new();
    let lines: Vec<&str> = content.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        if !line
            .trim_end()
            .to_ascii_lowercase()
            .ends_with(concat!("execute_", "sql("))
        {
            continue;
        }
        let next = lines[idx + 1..]
            .iter()
            .map(|l| l.trim())
            .find(|l| !l.is_empty());
        if let Some(next) = next {
            let name_len = next
                .find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
                .unwrap_or(next.len());
            let rest = next[name_len..].trim_start();
            if name_len > 0
                && next.starts_with(|c: char| c.is_ascii_uppercase() || c == '_')
                && (rest.starts_with(',') || rest.starts_with(')'))
            {
                found.insert(idx + 1);
            }
        }
    }
    found
}

/// Lines inside a Django template `Engine(...)` constructor call, in a Python
/// file that imports `django.template`. The call ends where its parentheses
/// balance (at most 12 lines).
fn django_template_engine_call_lines(content: &str, ext: &str) -> std::collections::HashSet<usize> {
    let mut found = std::collections::HashSet::new();
    if ext != "py" || !content.contains("django.template") {
        return found;
    }
    let lines: Vec<&str> = content.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        let Some(pos) = line.find("Engine(") else {
            continue;
        };
        let before = &line[..pos];
        if before
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
        {
            continue;
        }
        let mut depth = 0i32;
        for (offset, l) in lines[idx..].iter().take(12).enumerate() {
            let text = if offset == 0 { &l[pos..] } else { l };
            found.insert(idx + offset + 1);
            depth += text.matches('(').count() as i32 - text.matches(')').count() as i32;
            if depth <= 0 {
                break;
            }
        }
    }
    found
}

/// Line numbers inside Python docstrings: a string statement that starts a
/// line with a triple quote (nothing before it, so not an assignment, call
/// argument or SQL passed to a function). Used to keep documentation prose
/// from being read as a call site.
fn python_docstring_line_numbers(content: &str, ext: &str) -> std::collections::HashSet<usize> {
    let mut lines_in_docstring = std::collections::HashSet::new();
    if ext != "py" {
        return lines_in_docstring;
    }
    // `open` is a docstring block, `other` a triple-quoted string that is data
    // (assignment, argument), whose lines and closing quote are never docstrings.
    let mut open: Option<&str> = None;
    let mut other: Option<&str> = None;
    let mut previous = String::new();
    for (idx, line) in content.lines().enumerate() {
        let number = idx + 1;
        let trimmed = line.trim();
        if let Some(quote) = open {
            lines_in_docstring.insert(number);
            if trimmed.contains(quote) {
                open = None;
                previous = trimmed.to_string();
            }
            continue;
        }
        if let Some(quote) = other {
            if trimmed.contains(quote) {
                other = None;
                previous = trimmed.to_string();
            }
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        let body = trimmed.trim_start_matches(['r', 'R', 'u', 'U']);
        let quote = if body.starts_with("\"\"\"") {
            "\"\"\""
        } else if body.starts_with("'''") {
            "'''"
        } else {
            // Not a string statement; a triple quote later in the line opens data.
            for q in ["\"\"\"", "'''"] {
                if trimmed.matches(q).count() % 2 == 1 {
                    other = Some(q);
                }
            }
            previous = trimmed.to_string();
            continue;
        };
        // A docstring follows a `def`/`class` header or opens the module.
        let is_docstring = previous.is_empty() || previous.ends_with(':');
        if is_docstring {
            lines_in_docstring.insert(number);
            if !body[3..].contains(quote) {
                open = Some(quote);
            }
        } else if !body[3..].contains(quote) {
            other = Some(quote);
        }
        previous = trimmed.to_string();
    }
    lines_in_docstring
}

