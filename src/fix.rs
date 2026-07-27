use crate::finding::{Finding, Severity};
use crate::groq::GroqClient;
use crate::{deps, review, secrets};
use anyhow::{Context, Result};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use similar::{ChangeTag, TextDiff};
use std::io::Write;
use std::path::{Path, PathBuf};

/// A generated fix plan for a specific security finding
pub struct FixPlan {
    /// The finding that this fix resolves (stored for reference/display)
    #[allow(dead_code)]
    pub finding: Finding,
    pub file_path: PathBuf,
    pub original_code: String,
    pub fixed_code: String,
    pub explanation: String,
    pub start_line: usize,
    pub end_line: usize,
}

/// Run the `cipher-ai fix` command
pub async fn run_fix(
    project_path: &Path,
    finding_id: Option<&str>,
    risk_level: Option<&str>,
    target_file: Option<&str>,
    fix_all: bool,
    list_only: bool,
    auto_apply: bool,
) -> Result<()> {
    let canonical_path = std::fs::canonicalize(project_path)?;

    println!(
        "{} {}\n",
        "[FIX]".bright_blue().bold(),
        "CipherAI Auto-Fix".bold()
    );

    // Step 1: Scan for all findings
    println!("  {} Scanning for fixable findings...\n", "[*]".cyan());

    let findings = collect_fixable_findings(&canonical_path).await?;

    if findings.is_empty() {
        println!("  {} No fixable findings found.", "[-]".yellow());
        println!(
            "  Run {} or {} first to generate findings.",
            "cipher-ai review".yellow(),
            "cipher-ai deps".yellow()
        );
        return Ok(());
    }

    // Step 2: Filter findings by user criteria.
    // filter_findings returns owned Finding values to avoid lifetime gymnastics.
    let filtered = filter_findings(&findings, finding_id, risk_level, target_file, fix_all);

    if filtered.is_empty() {
        println!("  {} No findings match your filter criteria.", "[*]".yellow());
        if !list_only {
            println!();
            println!("  Available filters:");
            println!(
                "    {} {}  Fix a specific finding",
                "  --id <UUID>".cyan(),
                "-".dimmed()
            );
            println!(
                "    {} {}  Fix findings in a file",
                "  --file <PATH>".cyan(),
                "-".dimmed()
            );
            println!(
                "    {} {}  Fix findings by risk level",
                "  --risk <LEVEL>".cyan(),
                "-".dimmed()
            );
            println!(
                "    {} {}     Fix all findings",
                "  --all".cyan(),
                "-".dimmed()
            );
            println!(
                "    {} {}  List findings without fixing",
                "  --list".cyan(),
                "-".dimmed()
            );
            println!();
            println!("  Finding IDs for the current scan:");
            print_fixable_findings(
                &findings.iter().map(|f| f as &Finding).collect::<Vec<&Finding>>(),
                &canonical_path,
            );
        }
        return Ok(());
    }

    // Step 3: If --list, just show findings and exit
    if list_only {
        println!("  {} Fixable findings:", "[LIST]".bold());
        print_fixable_findings(
            &filtered.iter().map(|f| f as &Finding).collect::<Vec<&Finding>>(),
            &canonical_path,
        );
        return Ok(());
    }

    // Step 4: Filter out findings without a file path (can't auto-fix those)
    let fixable: Vec<&Finding> = filtered
        .iter()
        .filter(|f| {
            let has_path = f.file_path.is_some();
            if !has_path {
                eprintln!("  {} Skipping '{}' — no file path", "⏭".yellow(), f.title);
            }
            has_path
        })
        .collect();

    if fixable.is_empty() {
        println!("  {} No fixable findings (all lack file paths).", "[-]".yellow());
        return Ok(());
    }

    // Step 5: Initialize AI client
    let client = GroqClient::from_env().context(
        "GROQ_API_KEY required for fix generation.\nSet it via:\n  export GROQ_API_KEY=gsk_your_key_here",
    )?;

    println!(
        "  {} {} fixes to generate — using AI to create patches\n",
        "[AI]".cyan(),
        fixable.len().to_string().bold()
    );

    // Step 6: Generate and apply fixes one at a time
    let mut success_count = 0u32;
    let mut skip_count = 0u32;
    let mut fail_count = 0u32;

    for (i, finding) in fixable.iter().enumerate() {
        let file_path = finding.file_path.as_deref().unwrap_or("");
        let line_info = finding
            .line_number
            .map(|l| format!(":{}", l))
            .unwrap_or_default();

        println!(
            "\n  {} {}/{}  {}  {}{}",
            "-".repeat(50).dimmed(),
            (i + 1).to_string().bold(),
            fixable.len().to_string().bold(),
            finding.severity.badge(),
            file_path.yellow(),
            line_info,
        );
        println!(
            "  {} {}",
            finding.finding_type.icon(),
            finding.title.bold()
        );

        match generate_fix(&client, finding, &canonical_path).await {
            Ok(fix_plan) => {
                // Show the diff
                println!();
                display_diff(&fix_plan);
                println!();

                // Show explanation
                println!("  {} {}", "[NOTE]".bold(), "What changed:".bold());
                for line in fix_plan.explanation.trim().lines() {
                    println!("    {}", line);
                }
                println!();

                // Apply or skip
                if auto_apply {
                    if let Err(e) = apply_fix(&fix_plan) {
                        eprintln!("  {} Failed to apply fix: {}", "[ERR]".red(), e);
                        fail_count += 1;
                    } else {
                        println!(
                            "  {} Applied fix to {}{}",
                            "[OK]".green().bold(),
                            file_path.yellow(),
                            line_info
                        );
                        success_count += 1;
                    }
                } else {
                    print!("  {} Apply this fix? [Y/n] ", "[IDEA]".bold());
                    std::io::stdout().flush()?;

                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    let input = input.trim().to_lowercase();

                    if input.is_empty() || input == "y" || input == "yes" {
                        if let Err(e) = apply_fix(&fix_plan) {
                            eprintln!("  {} Failed to apply fix: {}", "[ERR]".red(), e);
                            fail_count += 1;
                        } else {
                            println!(
                                "  {} Applied fix to {}{}",
                                "[OK]".green().bold(),
                                file_path.yellow(),
                                line_info
                            );
                            success_count += 1;
                        }
                    } else {
                        println!("  {} Skipped.", "⏭".yellow());
                        skip_count += 1;
                    }
                }
            }
            Err(e) => {
                eprintln!("  {} Fix generation failed: {}", "[ERR]".red(), e);
                fail_count += 1;
            }
        }
    }

    // Step 7: Summary
    println!();
    println!("  {}", "-".repeat(50).dimmed());
    println!("  {} Fix session complete", "[OK]".green().bold());
    println!(
        "    {} {} applied  {} {} skipped  {} {} failed",
        "[OK]".green(),
        success_count.to_string().bold().green(),
        "⏭".yellow(),
        skip_count.to_string().bold().yellow(),
        "[ERR]".red(),
        fail_count.to_string().bold().red(),
    );

    Ok(())
}

/// Collect all fixable findings from all analysis modules
async fn collect_fixable_findings(project_path: &Path) -> Result<Vec<Finding>> {
    let mut all = Vec::new();

    // Security review findings (pattern-based only, no AI to keep it fast)
    if let Ok(report) = review::collect_review_findings(project_path, false, None).await {
        all.extend(report.findings);
    }

    // Dependency findings
    if let Ok(report) = deps::collect_deps_findings(project_path, false).await {
        all.extend(report.findings);
    }

    // Secret findings
    if let Ok(report) = secrets::collect_secrets_findings(project_path) {
        all.extend(report.findings);
    }

    // Sort by risk score (highest first)
    all.sort_by(|a, b| {
        b.risk_score()
            .partial_cmp(&a.risk_score())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(all)
}

/// Filter findings by user-provided criteria.
/// Returns owned `Finding` values so callers don't need lifetimes.
fn filter_findings(
    findings: &[Finding],
    finding_id: Option<&str>,
    risk_level: Option<&str>,
    target_file: Option<&str>,
    fix_all: bool,
) -> Vec<Finding> {
    if fix_all {
        return findings.to_vec();
    }

    if let Some(id) = finding_id {
        // Exact match by full UUID
        let matching: Vec<Finding> = findings
            .iter()
            .filter(|f| f.id == id)
            .cloned()
            .collect();
        if !matching.is_empty() {
            return matching;
        }
        // Prefix match for convenience (short UUIDs)
        let matching: Vec<Finding> = findings
            .iter()
            .filter(|f| f.id.starts_with(id))
            .cloned()
            .collect();
        if !matching.is_empty() {
            return matching;
        }
    }

    if let Some(file) = target_file {
        let file_lower = file.to_lowercase();
        let matching: Vec<Finding> = findings
            .iter()
            .filter(|f| {
                f.file_path
                    .as_deref()
                    .map(|fp| fp.to_lowercase().contains(&file_lower))
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        if !matching.is_empty() {
            return matching;
        }
    }

    if let Some(level) = risk_level {
        let sev = match level.to_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            _ => None,
        };
        if let Some(severity) = sev {
            let matching: Vec<Finding> = findings
                .iter()
                .filter(|f| f.severity.score() >= severity.score())
                .cloned()
                .collect();
            if !matching.is_empty() {
                return matching;
            }
        }
    }

    Vec::new()
}

/// Print fixable findings in a table format.
/// Accepts a slice of references so it can be called with either
/// `&[&Finding]` or slices built from owned collections.
fn print_fixable_findings(findings: &[&Finding], _project_path: &Path) {
    if findings.is_empty() {
        println!("  {} No fixable findings.", "[-]".yellow());
        return;
    }

    println!();
    println!(
        "  {} {:12} {:36} {:6}  {}",
        "ID".bold().dimmed(),
        "File".bold().dimmed(),
        "Title".bold().dimmed(),
        "Risk".bold().dimmed(),
        "Severity".bold().dimmed(),
    );
    println!("  {}", "-".repeat(95).dimmed());

    for finding in findings {
        let id_short = if finding.id.len() > 8 {
            &finding.id[..8]
        } else {
            &finding.id
        };
        let fp = finding
            .file_path
            .as_deref()
            .unwrap_or("<unknown>")
            .split('/')
            .last()
            .unwrap_or("<unknown>");
        let line = finding
            .line_number
            .map(|l| l.to_string())
            .unwrap_or_default();
        let location = if line.is_empty() {
            fp.to_string()
        } else {
            format!("{}:{}", fp, line)
        };

        let risk_str = format!("{:.0}/10", finding.risk_score());

        // Truncate title to fit: use the plain string, truncate, then bold
        let title_plain = &finding.title;
        let title_truncated = if title_plain.len() > 36 {
            format!("{}…", &title_plain[..35])
        } else {
            title_plain.to_string()
        };

        println!(
            "  {} {:12} {:36} {:>6}  {}",
            id_short.cyan().dimmed(),
            location.yellow().dimmed(),
            title_truncated.bold(),
            risk_str.dimmed(),
            finding.severity.label(),
        );
    }
    println!();
    println!(
        "  {} Use {} to fix a specific finding",
        "[IDEA]".bold(),
        "cipher-ai fix --id <ID>".cyan()
    );
}

/// Generate a fix for a specific finding using AI
async fn generate_fix(
    client: &GroqClient,
    finding: &Finding,
    _project_path: &Path,
) -> Result<FixPlan> {
    let file_path = finding
        .file_path
        .as_deref()
        .context("Finding has no file path")?;
    let file_path = PathBuf::from(file_path);

    // Read the current file content fresh from disk
    let file_content = std::fs::read_to_string(&file_path)
        .with_context(|| format!("Cannot read file: {}", file_path.display()))?;

    let all_lines: Vec<&str> = file_content.lines().collect();
    let total_lines = all_lines.len();

    // Determine which lines to extract for context
    let target_line = finding.line_number.unwrap_or(1).saturating_sub(1); // 0-indexed

    let context_start = if target_line >= 10 { target_line - 10 } else { 0 };
    let context_end = (target_line + 11).min(total_lines);

    let original_lines: Vec<&str> = all_lines[context_start..context_end].to_vec();
    let original_code = original_lines.join("\n");

    let start_line_1based = context_start + 1;
    let end_line_1based = context_end;

    // Build a context snippet showing line numbers with a >>> marker at the vulnerable line
    let mut numbered_context = String::new();
    for (i, line) in original_lines.iter().enumerate() {
        let line_num = context_start + i + 1;
        let marker = if finding.line_number.map_or(false, |l| line_num == l) {
            " >>>"
        } else {
            "    "
        };
        numbered_context.push_str(&format!("{:4}{} {}\n", line_num, marker, line));
    }

    // Build the AI prompt
    // Show raw code (without line numbers) as the replacement target to prevent
    // the AI from including line-number prefixes in its output.
    // `original_code` was already computed above as `original_lines.join("\n")`.

    let finding_type_str = finding.finding_type.to_string();
    let severity_str = finding.severity.to_string();
    let confidence_str = finding.confidence.to_string();
    let remediation = finding
        .remediation
        .as_deref()
        .unwrap_or("No specific remediation provided.");

    let system_prompt = r#"You are Cipher, an expert application security engineer. Your job is to generate secure patches for code vulnerabilities.

For each vulnerability, you receive:
1. The finding details (title, description, severity, confidence, remediation)
2. The vulnerable code (without line numbers) that you must replace
3. A line-numbered reference for context only

You must respond with a JSON object containing:
- "fixed_code": The COMPLETE replacement for the code block. Return ALL lines — only change the vulnerable ones and keep everything else identical.
- "explanation": A brief explanation of what was vulnerable and how the fix addresses it (1-3 sentences)

Rules:
- Only fix the specific vulnerability — do not change unrelated code
- Preserve the same code style, indentation, and conventions
- Make minimal changes — prefer the least invasive fix
- The fixed_code must contain ONLY source code — NO line numbers, NO markers, NO prefixes
- Return ONLY valid JSON, no other text or markdown formatting"#;

    let user_prompt = format!(
        r#"Finding:
  Title: {title}
  Type: {finding_type}
  Severity: {severity}
  Confidence: {confidence}
  Description: {description}
  Remediation: {remediation}

The vulnerable code is at lines {start_line}–{end_line} (line {target} is the issue).

Code to fix (replace these exact lines):
```
{raw_code}
```

Line reference (numbered, for context only — DO NOT include these numbers in your output):
```
{numbered_context}
```

Generate a secure fix. Return JSON with "fixed_code" (the complete replacement, NO line numbers/markers) and "explanation".
"#,
        title = finding.title,
        finding_type = finding_type_str,
        severity = severity_str,
        confidence = confidence_str,
        description = finding.description,
        remediation = remediation,
        start_line = start_line_1based,
        end_line = end_line_1based,
        target = finding.line_number.unwrap_or(start_line_1based),
        raw_code = original_code,
        numbered_context = numbered_context,
    );

    // Show progress indicator
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("    {spinner:.green} Generating fix...")
            .unwrap(),
    );
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));

    let response = client
        .chat(system_prompt, &user_prompt, None)
        .await
        .map_err(|e| anyhow::anyhow!("AI fix generation failed: {}", e))?;

    spinner.finish_and_clear();

    // Parse the JSON response
    let (fixed_code, explanation) = parse_fix_response(&response)?;

    // SAFETY CHECK: The AI MUST return roughly the same number of lines as the original.
    // If it returns too few lines, it would corrupt the file by deleting code.
    // If it returns too many, it might be adding unrelated code.
    let fixed_lines_count = fixed_code.lines().count();
    let original_lines_count = original_lines.len();

    if fixed_lines_count < original_lines_count.saturating_sub(4)
        || fixed_lines_count > original_lines_count + 4
    {
        anyhow::bail!(
            "AI returned {} lines but expected ~{} lines. The patch is unsafe — refusing to apply.\n  Try running the command again, or fix the vulnerability manually.",
            fixed_lines_count,
            original_lines_count,
        );
    }

    Ok(FixPlan {
        finding: finding.clone(),
        file_path,
        original_code,
        fixed_code,
        explanation,
        start_line: start_line_1based,
        end_line: end_line_1based,
    })
}

/// Parse the AI's JSON fix response
fn parse_fix_response(response: &str) -> Result<(String, String)> {
    // Extract JSON from the response (handles markdown code blocks and extra text)
    let json_str = if let Some(start) = response.find('{') {
        let end = response[start..]
            .rfind('}')
            .map(|i| start + i + 1)
            .unwrap_or(response.len());
        &response[start..end]
    } else {
        anyhow::bail!("No JSON object found in AI response");
    };

    #[derive(serde::Deserialize)]
    struct FixResponse {
        fixed_code: Option<String>,
        explanation: Option<String>,
    }

    let parsed: FixResponse = serde_json::from_str(json_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse AI fix response: {}", e))?;

    let fixed_code = parsed.fixed_code.unwrap_or_default();
    let explanation =
        parsed.explanation.unwrap_or_else(|| "No explanation provided.".to_string());

    if fixed_code.is_empty() {
        anyhow::bail!("AI returned an empty fix");
    }

    // The AI sometimes nests the code inside markdown code fences inside the JSON string.
    // The JSON extraction above already handles the outer fences, but the fixed_code
    // string value itself might contain ``` markers.
    let cleaned = fixed_code
        .trim()
        .trim_start_matches("```")
        .trim_start_matches("```rust")
        .trim_start_matches("```python")
        .trim_start_matches("```javascript")
        .trim_start_matches("```typescript")
        .trim_start_matches("```go")
        .trim_start_matches("```java")
        .trim_start_matches("```ruby")
        .trim_end_matches("```")
        .trim()
        .to_string();

    Ok((cleaned, explanation))
}

/// Display a colored diff between original and fixed code
fn display_diff(fix: &FixPlan) {
    println!("    {} {}", "-".repeat(40).dimmed(), "Diff".dimmed());
    println!(
        "    {} {}",
        "File:".bold().dimmed(),
        fix.file_path.display().to_string().yellow()
    );
    println!(
        "    {} Lines {}-{}",
        "Range:".bold().dimmed(),
        fix.start_line.to_string().cyan(),
        fix.end_line.to_string().cyan()
    );
    println!();

    let diff = TextDiff::from_lines(&fix.original_code, &fix.fixed_code);

    let mut has_changes = false;
    for change in diff.iter_all_changes() {
        let (sign, style) = match change.tag() {
            ChangeTag::Delete => ("-".red().bold(), change.value().red()),
            ChangeTag::Insert => ("+".green().bold(), change.value().green()),
            ChangeTag::Equal => (" ".dimmed(), change.value().dimmed()),
        };
        has_changes = has_changes || change.tag() != ChangeTag::Equal;

        if change.value().ends_with('\n') {
            print!("    {} {}", sign, style);
        } else {
            println!("    {} {}", sign, style);
        }
    }

    if !has_changes {
        println!(
            "    {} No changes detected (code already matches fix).",
            "(i)".blue()
        );
    }
}

/// Apply a fix plan to the file on disk.
/// Replaces `start_line..end_line` in the file with the AI-generated fixed code.
fn apply_fix(fix: &FixPlan) -> Result<()> {
    let file_content = std::fs::read_to_string(&fix.file_path)
        .with_context(|| format!("Cannot read file for writing: {}", fix.file_path.display()))?;

    let all_lines: Vec<&str> = file_content.lines().collect();
    let total_lines = all_lines.len();

    if fix.start_line > total_lines || fix.end_line > total_lines {
        anyhow::bail!(
            "Line range {}–{} exceeds file length {}",
            fix.start_line,
            fix.end_line,
            total_lines
        );
    }

    let orig_start_0 = fix.start_line.saturating_sub(1);
    let orig_end_0 = fix.end_line.min(total_lines);

    // Split the file into: [before] [to_replace] [after]
    let before = &all_lines[..orig_start_0];
    let after = &all_lines[orig_end_0..];

    let mut new_content = String::new();

    // Lines before the fix
    for line in before {
        new_content.push_str(line);
        new_content.push('\n');
    }

    // Fixed code
    new_content.push_str(&fix.fixed_code);
    if !fix.fixed_code.ends_with('\n') {
        new_content.push('\n');
    }

    // Lines after the fix
    for line in after {
        new_content.push_str(line);
        new_content.push('\n');
    }

    // Write back to file
    std::fs::write(&fix.file_path, new_content)
        .with_context(|| format!("Failed to write to {}", fix.file_path.display()))?;

    Ok(())
}
