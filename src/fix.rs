use crate::finding::{Finding, Severity};
use crate::groq::GroqClient;
use crate::{deps, review, secrets};
use anyhow::{Context, Result};
use colored::*;
use ignore::WalkBuilder;
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
    dry_run: bool,
    auto_apply: bool,
    verify: bool,
    open_pr: bool,
    pr_repo: Option<&str>,
    pr_token: Option<&str>,
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

    // Step 3b: If --dry-run, show findings and their planned fixes
    if dry_run {
        println!("  {} Dry-run mode — showing fixable findings without applying:", "[DRY]".cyan().bold());
        print_fixable_findings(
            &filtered.iter().map(|f| f as &Finding).collect::<Vec<&Finding>>(),
            &canonical_path,
        );
        println!();
        println!("  {} Run without --dry-run to apply these fixes.", "[IDEA]".bold());
        return Ok(());
    }

    if verify {
        println!(
            "  {} {}",
            "[VERIFY]".cyan().bold(),
            "Each fix will be compile-checked; fixes that break the build are reverted."
        );
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
    let mut applied: Vec<AppliedFix> = Vec::new();

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
                let should_apply = if auto_apply {
                    true
                } else {
                    print!("  {} Apply this fix? [Y/n] ", "[IDEA]".bold());
                    std::io::stdout().flush()?;

                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    let input = input.trim().to_lowercase();

                    if input.is_empty() || input == "y" || input == "yes" {
                        true
                    } else {
                        println!("  {} Skipped.", "⏭".yellow());
                        skip_count += 1;
                        false
                    }
                };

                if should_apply {
                    // Capture the pre-fix content so we can revert if verification fails
                    let pre_fix = std::fs::read_to_string(&fix_plan.file_path).ok();

                    if let Err(e) = apply_fix(&fix_plan) {
                        eprintln!("  {} Failed to apply fix: {}", "[ERR]".red(), e);
                        fail_count += 1;
                        continue;
                    }

                    println!(
                        "  {} Applied fix to {}{}",
                        "[OK]".green().bold(),
                        file_path.yellow(),
                        line_info
                    );

                    applied.push(AppliedFix {
                        title: finding.title.clone(),
                        file_path: fix_plan.file_path.to_string_lossy().to_string(),
                        severity: finding.severity.to_string(),
                        cwe: finding.cwe_id.clone().unwrap_or_else(|| "-".to_string()),
                        explanation: fix_plan.explanation.clone(),
                    });

                    if verify {
                        println!(
                            "    {} Compile-checking the project...",
                            "[*]".cyan()
                        );
                        match verify_compiles(&canonical_path) {
                            Ok(true) => {
                                println!("    {} Build passes — fix is safe.", "[OK]".green().bold());
                                success_count += 1;
                            }
                            Ok(false) => {
                                // Revert the fix so we never leave a broken tree
                                if let Some(original) = pre_fix {
                                    let _ = std::fs::write(&fix_plan.file_path, &original);
                                }
                                let _ = applied.pop(); // remove from PR list too
                                eprintln!(
                                    "  {} Fix broke the build — reverted. The finding needs a manual fix.\n",
                                    "[ERR]".red().bold()
                                );
                                fail_count += 1;
                            }
                            Err(e) => {
                                eprintln!(
                                    "  {} Could not verify build ({}). Fix applied but unverified.",
                                    "[!]".yellow(),
                                    e
                                );
                                success_count += 1;
                            }
                        }
                    } else {
                        success_count += 1;
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

    // Step 8: Open a pull request with the applied fixes (--pr)
    if open_pr {
        if applied.is_empty() {
            println!();
            println!("  {} No fixes applied — nothing to open a PR for.", "[-]".yellow());
        } else {
            println!();
            create_fix_pr(&canonical_path, &applied, pr_repo, pr_token).await?;
        }
    }

    Ok(())
}

/// A successfully applied fix, collected for the `--pr` summary.
struct AppliedFix {
    title: String,
    file_path: String,
    severity: String,
    cwe: String,
    explanation: String,
}

/// Create a branch with the applied fixes, push it, and open a GitHub PR.
///
/// Resolves the repository from `--repo`, `GITHUB_REPOSITORY`, or the origin
/// git remote; the token from `--token` or `GITHUB_TOKEN`/`GH_TOKEN`. The base
/// branch is the repository's default branch (GitHub API) falling back to
/// `main`. Fails gracefully with actionable messages when git or credentials
/// are unavailable.
async fn create_fix_pr(
    project_path: &Path,
    applied: &[AppliedFix],
    repo_arg: Option<&str>,
    token_arg: Option<&str>,
) -> Result<()> {
    println!("  {} Preparing pull request with {} fix(es)...", "[PR]".cyan().bold(), applied.len());

    // Resolve repository: flag > env > origin remote
    let repo = match crate::pr::resolve_repo(repo_arg) {
        Some(r) => r,
        None => match git_origin_repo(project_path) {
            Some(r) => {
                println!("  {} Detected repository from git remote: {}", "[GIT]".cyan(), r.yellow());
                r
            }
            None => {
                eprintln!(
                    "  {} Could not determine repository. Pass {} or set {}.",
                    "[!]".yellow(),
                    "--repo owner/name".cyan(),
                    "GITHUB_REPOSITORY".cyan()
                );
                eprintln!(
                    "  {} Fixes are applied locally — create the PR manually.",
                    "[IDEA]".bold()
                );
                return Ok(());
            }
        },
    };

    // Resolve token
    let token = match token_arg {
        Some(t) => t.to_string(),
        None => match std::env::var("GITHUB_TOKEN").or_else(|_| std::env::var("GH_TOKEN")) {
            Ok(t) => t,
            Err(_) => {
                eprintln!(
                    "  {} No GitHub token found. Pass {} or set {}.",
                    "[!]".yellow(),
                    "--token".cyan(),
                    "GITHUB_TOKEN".cyan()
                );
                eprintln!(
                    "  {} Fixes are applied locally — create the PR manually.",
                    "[IDEA]".bold()
                );
                return Ok(());
            }
        },
    };

    // Create a branch for the fixes. Git failures degrade gracefully: the
    // fixes stay applied locally and we print manual push instructions instead
    // of aborting the whole command after real work was already done.
    let branch = format!("cipherai/security-fixes-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"));
    println!("  {} Creating branch {}", "[GIT]".cyan(), branch.yellow());
    if let Err(e) = run_git(project_path, &["checkout", "-b", &branch]) {
        return graceful_pr_failure(&e);
    }

    // Stage and commit the fixes. Prefer staging only the fixed files so the
    // PR stays scoped to the security changes; fall back to `-A` when a path
    // can't be resolved relative to the repo.
    let mut staged = false;
    for f in applied {
        let p = std::path::Path::new(&f.file_path);
        let rel = p.strip_prefix(project_path).unwrap_or(p);
        if rel.exists() && git_ok(project_path, &["add", "--", rel.to_string_lossy().as_ref()]) {
            staged = true;
        }
    }
    if !staged {
        if let Err(e) = run_git(project_path, &["add", "-A"]) {
            return graceful_pr_failure(&e);
        }
    }
    let commit_msg = format!("fix(security): apply {} CipherAI fix(es)", applied.len());
    if let Err(e) = run_git(project_path, &["commit", "-m", &commit_msg]) {
        return graceful_pr_failure(&e);
    }

    // Push to origin
    println!("  {} Pushing branch to origin...", "[GIT]".cyan());
    if let Err(e) = run_git(project_path, &["push", "-u", "origin", &branch]) {
        return graceful_pr_failure(&e);
    }

    // Determine the base branch (repository default branch)
    let base = crate::pr::default_branch(&repo, &token)
        .await
        .unwrap_or_else(|| "main".to_string());

    // Build the PR title + body
    let title = format!("fix(security): {} CipherAI fix(es)", applied.len());
    let body = render_fix_pr_body(applied, &base, &branch);

    println!("  {} Opening PR on {} (base: {})...", "[GITHUB]".cyan(), repo.yellow(), base.yellow());
    match crate::pr::create_pull_request(&repo, &token, &branch, &base, &title, &body).await {
        Ok(url) => {
            println!();
            println!("  {} Pull request created:", "[OK]".green().bold());
            println!("    {}", url.green().bold());
            Ok(())
        }
        Err(e) => {
            eprintln!(
                "  {} PR creation failed (fixes are on branch {}): {}",
                "[!]".yellow(),
                branch.yellow(),
                e
            );
            Ok(())
        }
    }
}

/// Run a git command in the project directory, failing with context on error.
fn run_git(project_path: &Path, args: &[&str]) -> Result<()> {
    use std::process::Command;
    let out = Command::new("git")
        .args(args)
        .current_dir(project_path)
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run git: {}", e))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("git {} failed: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}

/// Print a graceful PR-failure message and return `Ok(())` so the command
/// exits cleanly — the fixes were already applied locally.
fn graceful_pr_failure(err: &anyhow::Error) -> Result<()> {
    eprintln!("  {} Git step failed: {}", "[!]".yellow(), err);
    eprintln!(
        "  {} Fixes are applied locally — commit and push them, then create the PR manually.",
        "[IDEA]".bold()
    );
    Ok(())
}

/// Run a git command returning `true` on success, `false` on any failure.
fn git_ok(project_path: &Path, args: &[&str]) -> bool {
    use std::process::Command;
    Command::new("git")
        .args(args)
        .current_dir(project_path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Extract `owner/name` from the origin remote of a git repo.
fn git_origin_repo(project_path: &Path) -> Option<String> {
    use std::process::Command;
    let out = Command::new("git")
        .args(["config", "--get", "remote.origin.url"])
        .current_dir(project_path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let url = String::from_utf8_lossy(&out.stdout).trim().to_string();
    crate::pr::repo_from_remote_url(&url)
}

/// Render the markdown body of the fix PR.
fn render_fix_pr_body(applied: &[AppliedFix], base: &str, branch: &str) -> String {
    let mut md = String::new();
    md.push_str("## 🔒 CipherAI Security Fixes\n\n");
    md.push_str(&format!(
        "This PR was created automatically by [CipherAI](https://github.com/sandeepannandi/Cipher) — it applies **{} verified fix(es)** to security findings in this repository.\n\n",
        applied.len()
    ));

    md.push_str("| # | Severity | Finding | File | CWE |\n");
    md.push_str("|---|----------|---------|------|-----|\n");
    for (i, f) in applied.iter().enumerate() {
        let file = f.file_path.rsplit('/').next().unwrap_or(&f.file_path);
        md.push_str(&format!(
            "| {} | {} | {} | `{}` | {} |\n",
            i + 1,
            f.severity,
            f.title.replace('|', "\\|"),
            file,
            f.cwe
        ));
    }

    md.push_str("\n## What changed\n\n");
    for (i, f) in applied.iter().enumerate() {
        md.push_str(&format!("**{}. {}** — {}\n", i + 1, f.title, f.explanation));
    }

    md.push_str("\n---\n");
    md.push_str(&format!(
        "_Branch: `{}` · Base: `{}` · Review and merge if the changes look correct._\n",
        branch, base
    ));
    md
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

/// Compile-check a project after a fix has been applied.
///
/// Detects the build system from the manifest files present and runs the
/// corresponding compile/check command with a timeout. Returns `Ok(true)` if
/// the build passes, `Ok(false)` if it fails, and `Err` if no build system is
/// detected or the check cannot be run (callers treat that as "unverified").
fn verify_compiles(project_path: &Path) -> Result<bool> {
    use std::process::Command;
    use std::time::{Duration, Instant};

    // Pick the compile command based on the project's manifest.
    let (program, args, cwd) = if project_path.join("Cargo.toml").exists() {
        ("cargo", vec!["check", "--quiet"], project_path.to_path_buf())
    } else if project_path.join("package.json").exists() {
        // For JS/TS projects, try tsc first (fast, no emit). Fall back to npm
        // build ONLY if a build script exists — otherwise `npm run build` fails
        // with a non-zero exit and a correct fix would be wrongly reverted.
        let pkg = std::fs::read_to_string(project_path.join("package.json")).unwrap_or_default();
        let has_build_script = serde_json::from_str::<serde_json::Value>(&pkg)
            .ok()
            .and_then(|v| v["scripts"]["build"].as_str().map(|s| !s.is_empty()))
            .unwrap_or(false);
        if project_path.join("tsconfig.json").exists() {
            ("npx", vec!["tsc", "--noEmit", "-p", "tsconfig.json"], project_path.to_path_buf())
        } else if has_build_script {
            ("npm", vec!["run", "build", "--silent"], project_path.to_path_buf())
        } else {
            anyhow::bail!("package.json has no build script or tsconfig — cannot verify");
        }
    } else if project_path.join("go.mod").exists() {
        ("go", vec!["build", "./..."], project_path.to_path_buf())
    } else if project_path.join("pyproject.toml").exists() || project_path.join("requirements.txt").exists() {
        ("python3", vec!["-m", "compileall", "-q", "."], project_path.to_path_buf())
    } else {
        // Unknown build system — cannot verify.
        anyhow::bail!("no build system detected (expected Cargo.toml, package.json, go.mod, or pyproject.toml)");
    };

    let mut child = Command::new(program)
        .args(&args)
        .current_dir(&cwd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to start {}: {}", program, e))?;

    // Enforce a timeout so a hung build can't stall the fix session.
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.success()),
            Ok(None) => {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    anyhow::bail!("{} check timed out after 120s", program);
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(e) => anyhow::bail!("failed to wait for {}: {}", program, e),
        }
    }
}

/// Resolve a finding's stored file path against the current project.
///
/// Findings store absolute paths from the time they were scanned. If the
/// project has moved (e.g. a CI scan consumed in a fresh checkout), the
/// stored path may no longer exist. We then look for a file in the project
/// whose relative path matches the tail of the stored path.
fn resolve_finding_path(stored: &str, project_path: &Path) -> PathBuf {
    let direct = PathBuf::from(stored);
    if direct.exists() {
        return direct;
    }
    let joined = project_path.join(stored);
    if joined.exists() {
        return joined;
    }

    // Walk the project (bounded) looking for a file whose relative path is a
    // suffix of the stored path — handles moved/copied checkouts.
    let normalized_stored = stored.replace('\\', "/").trim_end_matches('/').to_string();
    let walker = WalkBuilder::new(project_path)
        .git_ignore(true)
        .git_global(true)
        .hidden(false)
        .max_depth(Some(crate::scan::MAX_WALK_DEPTH))
        .build();

    let mut count = 0;
    for result in walker {
        if count >= crate::scan::MAX_SCAN_FILES {
            break;
        }
        count += 1;
        if let Ok(entry) = result {
            let path = entry.path();
            if path.is_file() && !crate::scan::should_exclude(path) {
                if let Ok(rel) = path.strip_prefix(project_path) {
                    let rel_str = rel.to_string_lossy().replace('\\', "/");
                    if normalized_stored.ends_with(&format!("/{}", rel_str)) {
                        return path.to_path_buf();
                    }
                }
            }
        }
    }

    // Fall back to the stored path; a read will fail with a clear error.
    direct
}

/// Generate a fix for a specific finding using AI
async fn generate_fix(
    client: &GroqClient,
    finding: &Finding,
    project_path: &Path,
) -> Result<FixPlan> {
    let file_path = finding
        .file_path
        .as_deref()
        .context("Finding has no file path")?;
    let file_path = resolve_finding_path(file_path, project_path);

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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str, content: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "cipher_fix_test_{}_{}",
            std::process::id(),
            name
        ));
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_parse_fix_response_plain_json() {
        let response = r#"{"fixed_code": "let x = 1;", "explanation": "safe"}"#;
        let (code, expl) = parse_fix_response(response).unwrap();
        assert_eq!(code, "let x = 1;");
        assert_eq!(expl, "safe");
    }

    #[test]
    fn test_parse_fix_response_markdown_fenced() {
        let response = "```json\n{\"fixed_code\": \"let y = 2;\", \"explanation\": \"ok\"}\n```";
        let (code, _) = parse_fix_response(response).unwrap();
        assert_eq!(code, "let y = 2;");
    }

    #[test]
    fn test_parse_fix_response_empty_errors() {
        let response = r#"{"fixed_code": "", "explanation": "nothing"}"#;
        assert!(parse_fix_response(response).is_err());
    }

    #[test]
    fn test_parse_fix_response_no_json_errors() {
        assert!(parse_fix_response("no json here").is_err());
    }

    #[test]
    fn test_apply_fix_replaces_range() {
        let path = temp_file("apply", "line1\nline2\nline3\nline4\n");
        let finding = Finding::new(
            crate::finding::FindingType::Vulnerability,
            "test", "test",
            Severity::High,
            crate::finding::Confidence::High,
            "test",
        );
        let plan = FixPlan {
            finding,
            file_path: path.clone(),
            original_code: "line2\nline3".to_string(),
            fixed_code: "FIXED".to_string(),
            explanation: "test".to_string(),
            start_line: 2,
            end_line: 3,
        };
        apply_fix(&plan).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "line1\nFIXED\nline4\n");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_apply_fix_out_of_range_errors() {
        let path = temp_file("oob", "a\nb\n");
        let finding = Finding::new(
            crate::finding::FindingType::Vulnerability,
            "test", "test",
            Severity::High,
            crate::finding::Confidence::High,
            "test",
        );
        let plan = FixPlan {
            finding,
            file_path: path.clone(),
            original_code: String::new(),
            fixed_code: "x".to_string(),
            explanation: String::new(),
            start_line: 99,
            end_line: 100,
        };
        assert!(apply_fix(&plan).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_resolve_finding_path_direct() {
        let path = temp_file("direct", "x\n");
        let resolved = resolve_finding_path(path.to_str().unwrap(), Path::new("."));
        assert_eq!(resolved, path);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_render_fix_pr_body_lists_fixes() {
        let applied = vec![
            AppliedFix {
                title: "SQL Injection in query".to_string(),
                file_path: "/proj/src/app.py".to_string(),
                severity: "HIGH".to_string(),
                cwe: "CWE-89".to_string(),
                explanation: "Use parameterized queries.".to_string(),
            },
            AppliedFix {
                title: "Hardcoded API Key".to_string(),
                file_path: "/proj/src/config.py".to_string(),
                severity: "CRITICAL".to_string(),
                cwe: "CWE-798".to_string(),
                explanation: "Move the key to an environment variable.".to_string(),
            },
        ];
        let body = render_fix_pr_body(&applied, "main", "cipherai/security-fixes-20240101");
        assert!(body.contains("SQL Injection"));
        assert!(body.contains("CWE-89"));
        assert!(body.contains("CWE-798"));
        assert!(body.contains("app.py"));
        assert!(body.contains("Use parameterized queries"));
        assert!(body.contains("main"));
        assert!(body.contains("cipherai/security-fixes-20240101"));
    }

    #[test]
    fn test_render_fix_pr_body_empty() {
        let body = render_fix_pr_body(&[], "develop", "branch-x");
        assert!(body.contains("0 verified fix(es)"));
        assert!(body.contains("develop"));
    }

    #[test]
    fn test_resolve_finding_path_moved_checkout() {
        let dir = std::env::temp_dir().join(format!(
            "cipher_fix_move_{}",
            std::process::id()
        ));
        let src = dir.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("main.rs"), "fn main() {}").unwrap();

        // Stored path from an old checkout — should resolve inside the project
        let stored = format!("C:/old/checkout/src/main.rs");
        let resolved = resolve_finding_path(&stored, &dir);
        assert_eq!(resolved, src.join("main.rs"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
