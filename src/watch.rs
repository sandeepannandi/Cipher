// ── CipherAI Security Watch ─────────────────────────────────────────
//
// Continuous monitoring: scans the project on an interval, persists a
// fingerprint of the findings, and reports what is NEW since the last scan.
// With `--pr`, new findings automatically trigger a fix session that opens
// a GitHub pull request (dependabot-style remediation).
//
// State is stored at `.cipher-ai/watch-state.json` so `--once` runs (e.g. a
// nightly CI cron) accumulate history across invocations.

use crate::finding::{Finding, Severity};
use crate::{fix, output, pr};
use anyhow::Result;
use colored::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Where the watch state (previous findings fingerprint) is persisted.
const STATE_FILE: &str = ".cipher-ai/watch-state.json";

/// Persisted state of the last watch scan.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct WatchState {
    last_scan: String,
    /// Sorted fingerprints of the findings from the last scan.
    fingerprints: Vec<String>,
}

/// A stable fingerprint of a finding for change detection.
/// Two scans of the same issue produce the same fingerprint.
fn fingerprint(f: &Finding) -> String {
    format!(
        "{}:{}:{}:{}",
        f.file_path.as_deref().unwrap_or(""),
        f.line_number.unwrap_or(0),
        f.title.to_lowercase(),
        f.severity
    )
}

/// Which fingerprints are present now but were absent in the previous scan?
fn new_fingerprints(prev: &[String], current: &[String]) -> Vec<String> {
    current
        .iter()
        .filter(|fp| !prev.contains(fp))
        .cloned()
        .collect()
}

/// Load the previous watch state (or an empty default).
fn load_state(path: &Path) -> WatchState {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Persist the watch state, creating the parent directory if needed.
fn save_state(path: &Path, state: &WatchState) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_string_pretty(state)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Run the `cipher-ai watch` command.
///
/// - Scans the project (all scanners) every `interval_minutes`.
/// - Compares findings against the previous scan and prints what's new.
/// - With `open_pr`, automatically fixes new findings (at/above `risk_level`)
///   and opens a GitHub PR containing the fixes.
/// - With `once`, runs a single scan and exits (for cron/CI).
pub async fn run_watch(
    project_path: &Path,
    interval_minutes: u64,
    risk_level: Option<&str>,
    open_pr: bool,
    repo: Option<&str>,
    token: Option<&str>,
    once: bool,
) -> Result<()> {
    let canonical_path = std::fs::canonicalize(project_path)?;
    let state_path = canonical_path.join(STATE_FILE);
    let interval = std::time::Duration::from_secs(interval_minutes.max(1) * 60);

    output::print_header("Security Watch", Some(&canonical_path.display().to_string()));
    if once {
        println!("  {} Single scan mode (--once) — for cron/CI", "[MODE]".cyan());
    } else {
        println!(
            "  {} Monitoring every {} minute(s) — Ctrl+C to stop",
            "[MODE]".cyan(),
            interval_minutes.to_string().bold()
        );
    }
    println!();

    // Baseline on the first run: nothing to compare against yet.
    let mut prev = load_state(&state_path);
    let mut baseline = prev.fingerprints.is_empty();

    loop {
        // Step 1: scan
        output::print_step(1, 3, "Running security scans (review + secrets + deps + zeroday + attack)");
        let (findings, _attack_count) = match pr::collect_pr_findings(&canonical_path).await {
            Ok(v) => v,
            Err(e) => {
                output::print_fail("Scans", &e.to_string());
                if once {
                    break;
                }
                tokio::time::sleep(interval).await;
                continue;
            }
        };

        let critical = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium = findings.iter().filter(|f| f.severity == Severity::Medium).count();

        output::print_ok("Scans", &format!(
            "{} critical, {} high, {} medium, {} total",
            critical.to_string().red().bold(),
            high.to_string().yellow().bold(),
            medium.to_string().cyan(),
            findings.len().to_string().bold()
        ));

        let mut fingerprints: Vec<String> = findings.iter().map(fingerprint).collect();
        fingerprints.sort();
        fingerprints.dedup();
        let new_fps = new_fingerprints(&prev.fingerprints, &fingerprints);

        // Step 2: report new findings
        output::print_step(2, 3, "Comparing against last scan");
        if baseline {
            println!(
                "  {} Baseline scan — {} finding(s) recorded. No previous state to compare.",
                "[OK]".green(),
                fingerprints.len().to_string().bold()
            );
        } else if new_fps.is_empty() {
            println!(
                "  {} No new findings since {}.",
                "[OK]".green(),
                prev.last_scan.dimmed()
            );
        } else {
            println!(
                "  {} {} NEW finding(s) since {}:",
                "[ALERT]".red().bold(),
                new_fps.len().to_string().bold().red(),
                prev.last_scan.dimmed()
            );
            for fp in new_fps.iter().take(20) {
                println!("    {} {}", "+".red().bold(), fp.dimmed());
            }
            if new_fps.len() > 20 {
                println!("    ... and {} more", (new_fps.len() - 20).to_string().dimmed());
            }
        }
        println!();

        // Step 3: auto-fix new findings (optional). Never fires on the very
        // first (baseline) scan — the baseline establishes the state to
        // compare against, so `--pr` only opens a PR when something is
        // genuinely new relative to a previous scan.
        if open_pr && !baseline && !new_fps.is_empty() {
            // run_fix accepts a single finding ID, so the PR remediates all
            // findings at/above the risk level (new + still-present).
            output::print_step(3, 3, "Fixing high+ findings and opening a PR");
            let level = risk_level.unwrap_or("high");
            // fix_all=false + risk level: filter_findings returns only findings
            // at/above the threshold, so `--risk` actually gates what gets fixed.
            match fix::run_fix(
                &canonical_path,
                None,
                Some(level),
                None,
                false, // fix_all — rely on the risk filter instead
                false, // list_only
                false, // dry_run
                true,  // auto_apply
                false, // verify
                true,  // open_pr
                repo,
                token,
            )
            .await
            {
                Ok(()) => output::print_ok("Fix PR", "fix session complete"),
                Err(e) => output::print_warn("Fix PR", &format!("auto-fix failed ({})", e)),
            }
            println!();
        } else if open_pr && !baseline && new_fps.is_empty() {
            println!("  {} No new findings — nothing to fix.", "[SKIP]".dimmed());
            println!();
        }

        // Persist state so the next run compares against this one.
        let state = WatchState {
            last_scan: chrono::Utc::now().to_rfc3339(),
            fingerprints,
        };
        if let Err(e) = save_state(&state_path, &state) {
            output::print_warn("State", &format!("could not save watch state ({})", e));
        }
        prev = state;
        baseline = false;

        if once {
            break;
        }

        println!(
            "  {} Next scan in {} minute(s)...",
            "[CLOCK]".dimmed(),
            interval_minutes.to_string().dimmed()
        );
        tokio::time::sleep(interval).await;
        println!();
    }

    output::print_footer();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Confidence, FindingType};

    fn mk(title: &str, path: &str, line: usize, sev: Severity) -> Finding {
        Finding::new(
            FindingType::Vulnerability,
            title,
            "desc",
            sev,
            Confidence::High,
            "watch-test",
        )
        .at(path, line)
    }

    #[test]
    fn test_fingerprint_is_stable() {
        let a = mk("SQL Injection", "/proj/a.py", 10, Severity::High);
        let b = mk("SQL Injection", "/proj/a.py", 10, Severity::High);
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn test_fingerprint_differs_on_location() {
        let a = mk("SQL Injection", "/proj/a.py", 10, Severity::High);
        let b = mk("SQL Injection", "/proj/a.py", 20, Severity::High);
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn test_new_fingerprints_detects_added() {
        let prev = vec!["a:1:x".to_string(), "b:2:y".to_string()];
        let current = vec!["a:1:x".to_string(), "b:2:y".to_string(), "c:3:z".to_string()];
        let new = new_fingerprints(&prev, &current);
        assert_eq!(new, vec!["c:3:z".to_string()]);
    }

    #[test]
    fn test_new_fingerprints_ignores_removed() {
        let prev = vec!["a:1:x".to_string(), "b:2:y".to_string()];
        let current = vec!["a:1:x".to_string()]; // b was fixed
        let new = new_fingerprints(&prev, &current);
        assert!(new.is_empty());
    }

    #[test]
    fn test_new_fingerprints_empty_when_identical() {
        let prev = vec!["a:1:x".to_string()];
        let current = vec!["a:1:x".to_string()];
        assert!(new_fingerprints(&prev, &current).is_empty());
    }

    #[test]
    fn test_watch_state_roundtrip() {
        let dir = std::env::temp_dir().join(format!("cipher_watch_state_{}", std::process::id()));
        let path = dir.join("watch-state.json");
        let state = WatchState {
            last_scan: "2026-01-01T00:00:00Z".to_string(),
            fingerprints: vec!["a:1:x".to_string()],
        };
        save_state(&path, &state).unwrap();
        let loaded = load_state(&path);
        assert_eq!(loaded.last_scan, state.last_scan);
        assert_eq!(loaded.fingerprints, state.fingerprints);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
