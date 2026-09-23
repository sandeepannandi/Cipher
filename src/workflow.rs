//! GitHub Actions workflow checks.
//!
//! Line-oriented and indentation-aware, so every finding keeps an exact line
//! and snippet. All checks are local to one workflow file: no claims are made
//! about reusable workflows, composite actions or repository settings.

use crate::finding::{
    Confidence, Finding, FindingType, OwaspCategory, RemediationEffort, Severity,
};
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

pub const UNTRUSTED_CHECKOUT_TITLE: &str =
    "GitHub Actions — Untrusted Checkout in Privileged Workflow";
pub const SCRIPT_INJECTION_TITLE: &str = "GitHub Actions — Script Injection";
pub const UNPINNED_ACTION_TITLE: &str = "GitHub Actions — Unpinned Third-Party Action";
pub const WRITE_ALL_TITLE: &str = "GitHub Actions — Write-All Token Permissions";
pub const SECRETS_DUMP_TITLE: &str = "GitHub Actions — All Secrets Exposed";

struct Patterns {
    top_level_on: Regex,
    top_level_jobs: Regex,
    privileged_trigger: Regex,
    script_key: Regex,
    expression: Regex,
    untrusted_input: Regex,
    checkout_key: Regex,
    untrusted_head: Regex,
    pr_checkout_command: Regex,
    uses: Regex,
    full_sha: Regex,
    write_all: Regex,
    secrets_dump: Regex,
}

fn patterns() -> &'static Patterns {
    static PATTERNS: OnceLock<Patterns> = OnceLock::new();
    PATTERNS.get_or_init(|| Patterns {
        top_level_on: Regex::new(r#"^(?:on|"on"|'on'|true)\s*:"#).expect("valid regex"),
        top_level_jobs: Regex::new(r"^jobs\s*:").expect("valid regex"),
        privileged_trigger: Regex::new(r"\b(?:pull_request_target|workflow_run)\b")
            .expect("valid regex"),
        script_key: Regex::new(r"^(\s*(?:-\s+)?)(run|script)\s*:\s*(.*)$").expect("valid regex"),
        expression: Regex::new(r"\$\{\{(.*?)\}\}").expect("valid regex"),
        // Attacker-controlled text fields (issue/PR/comment/commit/branch
        // content). Numeric ids such as pull_request.number are not included.
        untrusted_input: Regex::new(
            r"(?ix)
            \bgithub\.head_ref\b
            | \bgithub\.event\.(?:
                  issue\.(?:title|body)
                | pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch)
                | comment\.body
                | review\.body
                | review_comment\.body
                | discussion\.(?:title|body)
                | pages(?:\[\d+\]|\.\*)?\.page_name
                | commits(?:\[\d+\]|\.\*)?\.(?:message|author\.(?:email|name))
                | head_commit\.(?:message|author\.(?:email|name))
                | workflow_run\.(?:head_branch|head_commit\.(?:message|author\.(?:email|name))
                    | pull_requests(?:\[\d+\]|\.\*)?\.head\.ref)
              )\b",
        )
        .expect("valid regex"),
        checkout_key: Regex::new(r"^\s*(?:-\s+)?(?:ref|repository)\s*:\s*(.+)$")
            .expect("valid regex"),
        untrusted_head: Regex::new(
            r"(?i)github\.event\.pull_request\.head\.(?:sha|ref|repo\.full_name)|github\.head_ref|github\.event\.workflow_run\.(?:head_sha|head_branch|head_repository\.full_name)|refs/pull/",
        )
        .expect("valid regex"),
        pr_checkout_command: Regex::new(r"\bgh\s+pr\s+checkout\b").expect("valid regex"),
        uses: Regex::new(r#"^\s*(?:-\s+)?uses\s*:\s*['"]?([^'"\s#]+)"#).expect("valid regex"),
        full_sha: Regex::new(r"^[0-9a-fA-F]{40}$").expect("valid regex"),
        write_all: Regex::new(r#"^\s*permissions\s*:\s*['"]?write-all['"]?\s*(?:#.*)?$"#)
            .expect("valid regex"),
        secrets_dump: Regex::new(r"(?i)\btojson\s*\(\s*secrets\s*\)").expect("valid regex"),
    })
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn is_comment_or_blank(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.is_empty() || trimmed.starts_with('#')
}

/// True for GitHub Actions workflow files: YAML under `.github/workflows/`, or
/// a YAML document with top-level `on:` and `jobs:` keys.
pub fn is_github_workflow(path: &Path, content: &str) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext != "yml" && ext != "yaml" {
        return false;
    }
    let normalized = path.to_string_lossy().replace('\\', "/");
    if normalized.contains("/.github/workflows/") || normalized.starts_with(".github/workflows/") {
        return true;
    }
    let p = patterns();
    let mut has_on = false;
    let mut has_jobs = false;
    for line in content.lines() {
        has_on |= p.top_level_on.is_match(line);
        has_jobs |= p.top_level_jobs.is_match(line);
    }
    has_on && has_jobs
}

/// Whether the workflow's top-level `on:` triggers include
/// `pull_request_target` or `workflow_run`.
fn has_privileged_trigger(lines: &[&str]) -> bool {
    let p = patterns();
    let mut in_on = false;
    for line in lines {
        if is_comment_or_blank(line) {
            continue;
        }
        if indent_of(line) == 0 {
            in_on = p.top_level_on.is_match(line);
            if in_on {
                let inline = line.split_once(':').map(|(_, v)| v).unwrap_or("");
                let inline = inline.split('#').next().unwrap_or("");
                if p.privileged_trigger.is_match(inline) {
                    return true;
                }
            }
            continue;
        }
        if in_on {
            let code = line.split('#').next().unwrap_or("");
            let key = code.trim_start().trim_start_matches('-').trim_start();
            let key = key.split(':').next().unwrap_or("").trim();
            if key == "pull_request_target" || key == "workflow_run" {
                return true;
            }
        }
    }
    false
}

/// Line indexes (0-based) of the step that contains `idx`: from its `- ` list
/// item to the line before the next sibling or shallower line.
fn step_bounds(lines: &[&str], idx: usize) -> Option<(usize, usize)> {
    let target_indent = indent_of(lines[idx]);
    let mut start = None;
    for i in (0..=idx).rev() {
        let line = lines[i];
        if is_comment_or_blank(line) {
            continue;
        }
        let indent = indent_of(line);
        if line.trim_start().starts_with("- ") && (indent < target_indent || i == idx) {
            start = Some((i, indent));
            break;
        }
        if indent < target_indent && !line.trim_start().starts_with("- ") && i != idx {
            // Walked out through a mapping parent (e.g. `with:`); keep going.
            continue;
        }
    }
    let (start, dash_indent) = start?;
    let mut end = lines.len() - 1;
    for (i, line) in lines.iter().enumerate().skip(start + 1) {
        if is_comment_or_blank(line) {
            continue;
        }
        if indent_of(line) <= dash_indent {
            end = i - 1;
            break;
        }
    }
    Some((start, end))
}

fn step_uses_checkout(lines: &[&str], idx: usize) -> bool {
    let p = patterns();
    let Some((start, end)) = step_bounds(lines, idx) else {
        return false;
    };
    lines[start..=end].iter().any(|line| {
        p.uses
            .captures(line)
            .and_then(|c| c.get(1))
            .is_some_and(|m| {
                m.as_str()
                    .to_ascii_lowercase()
                    .starts_with("actions/checkout@")
            })
    })
}

/// Lines (0-based) that belong to `run:` / `script:` values, inline or block.
fn script_lines(lines: &[&str]) -> Vec<usize> {
    let p = patterns();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if is_comment_or_blank(line) {
            i += 1;
            continue;
        }
        if let Some(caps) = p.script_key.captures(line) {
            let key_col = caps.get(1).map(|m| m.as_str().len()).unwrap_or(0);
            let value = caps.get(3).map(|m| m.as_str().trim()).unwrap_or("");
            if value.starts_with('|') || value.starts_with('>') || value.is_empty() {
                let mut j = i + 1;
                while j < lines.len() {
                    let next = lines[j];
                    if next.trim().is_empty() {
                        j += 1;
                        continue;
                    }
                    if indent_of(next) <= key_col {
                        break;
                    }
                    out.push(j);
                    j += 1;
                }
                i = j;
                continue;
            }
            out.push(i);
        }
        i += 1;
    }
    out
}

fn finding(
    path: &Path,
    line_number: usize,
    line: &str,
    spec: (&str, FindingType, Severity, Confidence, OwaspCategory, &str),
    description: &str,
    remediation: &str,
) -> Finding {
    let (title, finding_type, severity, confidence, owasp, cwe) = spec;
    let (exploitability, effort) = match severity {
        Severity::Critical => (0.8, RemediationEffort::Hours),
        Severity::High => (0.6, RemediationEffort::Hours),
        Severity::Medium => (0.4, RemediationEffort::Minutes),
        _ => (0.2, RemediationEffort::Minutes),
    };
    Finding::new(
        finding_type,
        title,
        description,
        severity,
        confidence,
        "security-review",
    )
    .at(path.to_string_lossy().to_string(), line_number)
    .with_code(line.to_string())
    .with_remediation(remediation)
    .with_owasp(owasp)
    .with_cwe(cwe)
    .with_exploitability(exploitability)
    .with_effort(effort)
}

/// Scan one GitHub Actions workflow. Callers check [`is_github_workflow`].
pub fn scan_workflow(path: &Path, content: &str) -> Vec<Finding> {
    let p = patterns();
    let lines: Vec<&str> = content.lines().collect();
    let mut findings = Vec::new();
    let privileged = has_privileged_trigger(&lines);
    let scripts = script_lines(&lines);

    // 1. Privileged trigger + checkout of PR-controlled code.
    if privileged {
        for (idx, line) in lines.iter().enumerate() {
            if is_comment_or_blank(line) {
                continue;
            }
            let checkout_ref = p
                .checkout_key
                .captures(line)
                .and_then(|c| c.get(1))
                .is_some_and(|v| p.untrusted_head.is_match(v.as_str()))
                && step_uses_checkout(&lines, idx);
            let checkout_cmd = scripts.contains(&idx) && p.pr_checkout_command.is_match(line);
            if checkout_ref || checkout_cmd {
                findings.push(finding(
                    path,
                    idx + 1,
                    line,
                    (
                        UNTRUSTED_CHECKOUT_TITLE,
                        FindingType::Vulnerability,
                        Severity::Critical,
                        Confidence::High,
                        OwaspCategory::A08IntegrityFailures,
                        "CWE-829",
                    ),
                    "This workflow runs on pull_request_target or workflow_run, which have a write-capable token and access to secrets, and it checks out code from the pull request head. Any build or script step that runs that code lets a fork author execute code with those privileges.",
                    "Use the pull_request trigger for building untrusted code. If a privileged trigger is required, do not check out the PR head, or split the work: an unprivileged pull_request job builds, and a separate job with no untrusted code consumes only its artifacts.",
                ));
            }
        }
    }

    // 2. Attacker-controlled text interpolated into a script.
    for &idx in &scripts {
        let line = lines[idx];
        let tainted = p
            .expression
            .captures_iter(line)
            .filter_map(|c| c.get(1))
            .any(|expr| p.untrusted_input.is_match(expr.as_str()));
        if tainted {
            findings.push(finding(
                path,
                idx + 1,
                line,
                (
                    SCRIPT_INJECTION_TITLE,
                    FindingType::Injection,
                    Severity::High,
                    Confidence::High,
                    OwaspCategory::A03Injection,
                    "CWE-94",
                ),
                "A ${{ }} expression containing attacker-controlled text (issue, pull request, comment, commit or branch content) is expanded directly into a run or github-script body. The text is substituted before the shell or script runs, so crafted content can execute commands in the workflow.",
                "Pass the value through an environment variable (env: TITLE: ${{ github.event.issue.title }}) and reference it as \"$TITLE\" in the script, instead of interpolating the expression into the script body.",
            ));
        }
    }

    for (idx, line) in lines.iter().enumerate() {
        if is_comment_or_blank(line) {
            continue;
        }

        // 3. Third-party action not pinned to a full commit SHA.
        if let Some(target) = p.uses.captures(line).and_then(|c| c.get(1)) {
            let target = target.as_str();
            if !target.starts_with("./") && !target.starts_with("docker://") {
                let (action, reference) = target.split_once('@').unwrap_or((target, ""));
                let owner = action.split('/').next().unwrap_or("").to_ascii_lowercase();
                let first_party = owner == "actions" || owner == "github";
                if !first_party && !p.full_sha.is_match(reference) {
                    findings.push(finding(
                        path,
                        idx + 1,
                        line,
                        (
                            UNPINNED_ACTION_TITLE,
                            FindingType::Dependency,
                            Severity::Medium,
                            Confidence::High,
                            OwaspCategory::A08IntegrityFailures,
                            "CWE-829",
                        ),
                        "A third-party action is referenced by a tag or branch instead of a full commit SHA. Tags and branches can be moved, so a compromised or malicious upstream change runs in this workflow with its token and secrets.",
                        "Pin the action to a full 40-character commit SHA (uses: owner/repo@<sha> # vX.Y.Z) and update it deliberately, for example with Dependabot.",
                    ));
                }
            }
        }

        // 4a. Blanket write permissions.
        if p.write_all.is_match(line) {
            findings.push(finding(
                path,
                idx + 1,
                line,
                (
                    WRITE_ALL_TITLE,
                    FindingType::Misconfiguration,
                    Severity::High,
                    Confidence::High,
                    OwaspCategory::A05SecurityMisconfiguration,
                    "CWE-732",
                ),
                "permissions: write-all gives the GITHUB_TOKEN write access to every scope, so any compromised step can push code, change releases or alter repository settings it has no need for.",
                "Grant only the scopes the job needs, e.g. permissions: { contents: read } and add specific write scopes per job.",
            ));
        }

        // 4b. Whole secrets context serialized.
        if p.secrets_dump.is_match(line) {
            findings.push(finding(
                path,
                idx + 1,
                line,
                (
                    SECRETS_DUMP_TITLE,
                    FindingType::Misconfiguration,
                    Severity::High,
                    Confidence::High,
                    OwaspCategory::A05SecurityMisconfiguration,
                    "CWE-200",
                ),
                "toJSON(secrets) serializes every repository and organization secret into one value, exposing all of them to the step or action that receives it instead of only the secret it needs.",
                "Pass only the specific secrets the step needs, e.g. ${{ secrets.DEPLOY_TOKEN }}.",
            ));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(source: &str) -> Vec<(String, usize)> {
        let path = Path::new("repo/.github/workflows/test.yml");
        let mut out: Vec<(String, usize)> = scan_workflow(path, source)
            .into_iter()
            .map(|f| (f.title, f.line_number.unwrap_or(0)))
            .collect();
        out.sort_by_key(|(_, line)| *line);
        out
    }

    #[test]
    fn detects_workflow_files() {
        assert!(is_github_workflow(
            Path::new("a/.github/workflows/ci.yml"),
            ""
        ));
        assert!(is_github_workflow(
            Path::new("fixture.yaml"),
            "on: push\njobs:\n  a:\n    runs-on: x\n"
        ));
        assert!(!is_github_workflow(
            Path::new("config.yml"),
            "name: app\nport: 80\n"
        ));
        assert!(!is_github_workflow(
            Path::new("a/.github/workflows/ci.rs"),
            ""
        ));
    }

    #[test]
    fn untrusted_checkout_under_pull_request_target() {
        let src = "on:\n  pull_request_target:\n    types: [opened]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: npm install\n";
        assert_eq!(scan(src), vec![(UNTRUSTED_CHECKOUT_TITLE.to_string(), 10)]);
    }

    #[test]
    fn same_checkout_under_pull_request_is_not_flagged() {
        let src = "on: [pull_request]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n";
        assert!(scan(src).is_empty());
    }

    #[test]
    fn default_checkout_under_pull_request_target_is_not_flagged() {
        let src = "on: pull_request_target\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/labeler@v5\n";
        assert!(scan(src).is_empty());
    }

    #[test]
    fn gh_pr_checkout_under_workflow_run() {
        let src = "on:\n  workflow_run:\n    workflows: [CI]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          gh pr checkout 1\n          make\n";
        assert_eq!(scan(src), vec![(UNTRUSTED_CHECKOUT_TITLE.to_string(), 9)]);
    }

    #[test]
    fn script_injection_inline_and_block() {
        let src = "on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n      - name: block\n        run: |\n          echo start\n          echo \"${{ github.event.pull_request.head.ref }}\"\n      - uses: actions/github-script@v7\n        with:\n          script: |\n            console.log(`${{ github.event.comment.body }}`)\n";
        assert_eq!(
            scan(src),
            vec![
                (SCRIPT_INJECTION_TITLE.to_string(), 6),
                (SCRIPT_INJECTION_TITLE.to_string(), 10),
                (SCRIPT_INJECTION_TITLE.to_string(), 14),
            ]
        );
    }

    #[test]
    fn env_indirection_and_numeric_fields_are_safe() {
        let src = "on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          TITLE: ${{ github.event.issue.title }}\n        run: |\n          echo \"$TITLE\"\n          echo ${{ github.event.issue.number }}\n          # echo ${{ github.event.issue.title }}\n";
        assert!(scan(src).is_empty());
    }

    #[test]
    fn unpinned_third_party_actions() {
        let sha = "b4ffde65f46336ab88eb53be808477a3936bae11";
        let src = format!("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: dtolnay/rust-toolchain@stable\n      - uses: softprops/action-gh-release@{sha} # v2\n      - uses: ./local-action\n      - uses: github/codeql-action/upload-sarif@v3\n      - uses: 'someone/thing@v1'\n");
        assert_eq!(
            scan(&src),
            vec![
                (UNPINNED_ACTION_TITLE.to_string(), 7),
                (UNPINNED_ACTION_TITLE.to_string(), 11),
            ]
        );
    }

    #[test]
    fn write_all_and_secrets_dump() {
        let src = "on: push\npermissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n    steps:\n      - env:\n          ALL: ${{ toJSON(secrets) }}\n        run: ./deploy.sh\n";
        assert_eq!(
            scan(src),
            vec![
                (WRITE_ALL_TITLE.to_string(), 2),
                (SECRETS_DUMP_TITLE.to_string(), 10),
            ]
        );
    }
}
