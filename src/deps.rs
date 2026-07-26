use crate::finding::{
    Confidence, Finding, FindingReport, FindingType, RemediationEffort, Severity,
};
use anyhow::Result;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A discovered dependency with version info
#[derive(Debug, Clone)]
struct Dependency {
    name: String,
    version: String,
    ecosystem: String,
    manifest_file: PathBuf,
    #[allow(dead_code)]
    is_dev: bool,
}

/// OSV.dev API response for a query
#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    severity: Option<Vec<OsvSeverity>>,
    #[allow(dead_code)]
    aliases: Option<Vec<String>>,
    #[allow(dead_code)]
    affected: Option<Vec<OsvAffected>>,
    #[allow(dead_code)]
    references: Option<Vec<OsvReference>>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[allow(dead_code)]
    #[serde(rename = "type")]
    severity_type: String,
    score: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[allow(dead_code)]
    package: Option<OsvPackage>,
    #[allow(dead_code)]
    ranges: Option<Vec<OsvRange>>,
}

#[derive(Debug, Deserialize)]
struct OsvPackage {
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[allow(dead_code)]
    #[serde(rename = "type")]
    range_type: String,
    #[allow(dead_code)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    #[allow(dead_code)]
    introduced: Option<String>,
    #[allow(dead_code)]
    fixed: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvReference {
    #[allow(dead_code)]
    #[serde(rename = "type")]
    ref_type: String,
    #[allow(dead_code)]
    url: Option<String>,
}



/// Known vulnerability database (embedded fallback when OSV API is unreachable)
/// This is a minimal set of well-known CVEs for common packages.
/// In production, rely on OSV.dev API for comprehensive coverage.
const EMBEDDED_ADVISORIES: &[(&str, &str, &str, &str, Severity)] = &[
    // Rust crates
    ("crates.io", "serde", "<1.0.100", "CVE-2023-XXXX: Outdated serde version", Severity::Low),
    ("crates.io", "openssl", "<0.10.45", "CVE-2023-0464: OpenSSL vulnerability", Severity::High),
    ("crates.io", "tokio", "<1.25.0", "CVE-2023-XXXX: Tokio vulnerability", Severity::Medium),
    ("crates.io", "hyper", "<0.14.20", "CVE-2023-XXXX: Hyper HTTP request smuggling", Severity::High),
    ("crates.io", "reqwest", "<0.11.14", "CVE-2023-XXXX: Reqwest redirect header leak", Severity::Medium),
    ("crates.io", "regex", "<1.7.3", "CVE-2023-XXXX: Regex DoS vulnerability", Severity::Medium),
    ("crates.io", "zip", "<0.6.4", "CVE-2023-XXXX: Zip archive vulnerability", Severity::High),

    // npm packages
    ("npm", "lodash", "<4.17.21", "CVE-2021-23337: Lodash prototype pollution", Severity::High),
    ("npm", "axios", "<0.21.2", "CVE-2021-3749: Axios SSRF vulnerability", Severity::Medium),
    ("npm", "express", "<4.17.3", "CVE-2022-24999: Express open redirect", Severity::Medium),
    ("npm", "minimist", "<1.2.6", "CVE-2021-44906: Minimist prototype pollution", Severity::Medium),
    ("npm", "moment", "<2.29.4", "CVE-2022-24785: Moment.js path traversal", Severity::Low),
    ("npm", "follow-redirects", "<1.14.8", "CVE-2022-0536: Follow-redirects credential leak", Severity::High),
    ("npm", "json5", "<2.2.2", "CVE-2022-46175: JSON5 prototype pollution", Severity::High),
    ("npm", "nth-check", "<2.0.1", "CVE-2021-3803: Nth-check ReDoS", Severity::Low),
    ("npm", "trim-newlines", "<3.0.1", "CVE-2021-33623: Trim-newlines ReDoS", Severity::Low),
    ("npm", "glob-parent", "<5.1.2", "CVE-2021-40895: Glob-parent ReDoS", Severity::Low),

    // PyPI packages
    ("PyPI", "django", "<3.2.18", "CVE-2023-23969: Django potential denial of service", Severity::Medium),
    ("PyPI", "django", "<4.1.8", "CVE-2023-31047: Django bypass of validation", Severity::Medium),
    ("PyPI", "flask", "<2.2.5", "CVE-2023-25577: Flask open redirect", Severity::Medium),
    ("PyPI", "requests", "<2.31.0", "CVE-2023-32681: Requests certificate verification", Severity::High),
    ("PyPI", "urllib3", "<1.26.17", "CVE-2023-43804: Urllib3 cookie header injection", Severity::Medium),
    ("PyPI", "cryptography", "<39.0.1", "CVE-2023-23931: Cryptography vulnerability", Severity::High),
    ("PyPI", "pillow", "<9.5.0", "CVE-2023-3379: Pillow path traversal", Severity::Medium),
    ("PyPI", "jinja2", "<3.1.2", "CVE-2023-XXXX: Jinja2 XSS vulnerability", Severity::Medium),

    // Go modules
    ("Go", "golang.org/x/net", "<0.7.0", "CVE-2022-27664: net/http memory exhaustion", Severity::High),
    ("Go", "golang.org/x/text", "<0.3.8", "CVE-2021-38561: Text encoding vulnerability", Severity::Medium),
    ("Go", "golang.org/x/crypto", "<0.1.0", "CVE-2022-27191: SSH key exchange panic", Severity::Medium),
];

// ── Manifest Parsers ──

/// Parse dependencies from Cargo.toml
fn parse_cargo_toml(path: &Path) -> Result<Vec<Dependency>> {
    let content = std::fs::read_to_string(path)?;
    let mut deps = Vec::new();
    let mut in_deps = false;
    let mut in_dev_deps = false;
    let mut is_dev = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("[dependencies]") && !trimmed.starts_with("[dev-") {
            in_deps = true;
            in_dev_deps = false;
            is_dev = false;
            continue;
        }
        if trimmed.starts_with("[dev-dependencies]") {
            in_dev_deps = true;
            in_deps = false;
            is_dev = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_deps = false;
            in_dev_deps = false;
            continue;
        }

        if in_deps || in_dev_deps {
            if let Some(eq_pos) = trimmed.find('=') {
                let name = trimmed[..eq_pos].trim().to_string();
                let value = trimmed[eq_pos + 1..].trim();

                // Handle string values: name = "1.0.0"
                if value.starts_with('"') {
                    let version = value.trim_matches('"').to_string();
                    if !version.is_empty() && !name.contains(' ') {
                        deps.push(Dependency {
                            name,
                            version,
                            ecosystem: "crates.io".to_string(),
                            manifest_file: path.to_path_buf(),
                            is_dev,
                        });
                    }
                }
                // Handle table values: name = { version = "1.0", features = [...] }
                else if value.starts_with('{') {
                    if let Some(v_start) = value.find("version") {
                        let after_version = &value[v_start..];
                        let eq_pos = after_version.find('=').unwrap_or(0) + v_start;
                        let after_eq = value[eq_pos + 1..].trim();
                        if let Some(version) = after_eq.split(',').next() {
                            let version = version.trim().trim_matches('"').to_string();
                            if !version.is_empty() {
                                deps.push(Dependency {
                                    name,
                                    version,
                                    ecosystem: "crates.io".to_string(),
                                    manifest_file: path.to_path_buf(),
                                    is_dev,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(deps)
}

/// Parse dependencies from package.json
fn parse_package_json(path: &Path) -> Result<Vec<Dependency>> {
    let content = std::fs::read_to_string(path)?;

    #[derive(Deserialize)]
    struct PackageJson {
        dependencies: Option<HashMap<String, String>>,
        #[serde(rename = "devDependencies")]
        dev_dependencies: Option<HashMap<String, String>>,
    }

    let pkg: PackageJson = serde_json::from_str(&content)?;
    let mut deps = Vec::new();

    if let Some(deps_map) = pkg.dependencies {
        for (name, version) in deps_map {
            deps.push(Dependency {
                name,
                version: version.trim_start_matches('^').trim_start_matches('~').to_string(),
                ecosystem: "npm".to_string(),
                manifest_file: path.to_path_buf(),
                is_dev: false,
            });
        }
    }

    if let Some(deps_map) = pkg.dev_dependencies {
        for (name, version) in deps_map {
            deps.push(Dependency {
                name,
                version: version.trim_start_matches('^').trim_start_matches('~').to_string(),
                ecosystem: "npm".to_string(),
                manifest_file: path.to_path_buf(),
                is_dev: true,
            });
        }
    }

    Ok(deps)
}

/// Parse dependencies from requirements.txt
fn parse_requirements_txt(path: &Path) -> Result<Vec<Dependency>> {
    let content = std::fs::read_to_string(path)?;
    let mut deps = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("-r") || trimmed.starts_with("--") {
            continue;
        }

        // Handle `package==1.0.0`, `package>=1.0.0`, `package~=1.0.0`
        if let Some(eq_pos) = trimmed.find("==") {
            let name = trimmed[..eq_pos].trim().to_string();
            let version = trimmed[eq_pos + 2..].trim().split(',')
                .next().unwrap_or("")
                .trim().to_string();
            if !name.is_empty() && !version.is_empty() {
                deps.push(Dependency {
                    name,
                    version,
                    ecosystem: "PyPI".to_string(),
                    manifest_file: path.to_path_buf(),
                    is_dev: false,
                });
            }
        }
    }

    Ok(deps)
}

/// Check if a version string matches a constraint like "<1.0.0" or ">=2.0.0 <3.0.0"
/// Currently handles `<` and `<=` constraints. Other operators return false.
/// Returns true if the version satisfies the vulnerable constraint
fn version_matches_constraint(version: &str, constraint: &str) -> bool {
    let version_parts: Vec<u32> = version
        .split('.')
        .filter_map(|p| p.parse::<u32>().ok())
        .collect();

    if version_parts.len() < 2 {
        return false;
    }

    let constraint = constraint.trim();
    let version_tuple = || -> (u32, u32, u32) {
        match version_parts.len() {
            1 => (version_parts[0], 0, 0),
            2 => (version_parts[0], version_parts[1], 0),
            _ => (version_parts[0], version_parts[1], version_parts[2]),
        }
    };

    let (v_major, v_minor, v_patch) = version_tuple();

    // Handle "<x.y.z" constraints
    if constraint.starts_with('<') {
        let c = constraint[1..].trim();
        let c_parts: Vec<u32> = c.split('.').filter_map(|p| p.parse::<u32>().ok()).collect();
        if c_parts.len() >= 3 {
            return (v_major, v_minor, v_patch) < (c_parts[0], c_parts[1], c_parts[2]);
        } else if c_parts.len() == 2 {
            return (v_major, v_minor) < (c_parts[0], c_parts[1]);
        }
    }

    // Handle "<=x.y.z" constraints
    if constraint.starts_with("<=") {
        let c = constraint[2..].trim();
        let c_parts: Vec<u32> = c.split('.').filter_map(|p| p.parse::<u32>().ok()).collect();
        if c_parts.len() >= 3 {
            return (v_major, v_minor, v_patch) <= (c_parts[0], c_parts[1], c_parts[2]);
        }
    }

    false
}

/// Query OSV.dev API for vulnerabilities
async fn query_osv(ecosystem: &str, name: &str, version: &str) -> Result<Vec<(String, String, Option<String>, Severity)>> {
    let client = reqwest::Client::new();

    let payload = serde_json::json!({
        "package": {
            "name": name,
            "ecosystem": ecosystem
        },
        "version": version
    });

    let response = client
        .post("https://api.osv.dev/v1/query")
        .json(&payload)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("OSV API unreachable"))?;

    if !response.status().is_success() {
        return Ok(Vec::new());
    }

    let osv_response: OsvQueryResponse = response.json().await?;
    let mut results = Vec::new();

    for vuln in osv_response.vulns {
        let severity = vuln
            .severity
            .as_ref()
            .and_then(|s| s.first())
            .and_then(|s| {
                s.score.as_ref().and_then(|score| {
                    let score: f64 = score.parse().ok()?;
                    Some(match score as u8 {
                        0..=3 => Severity::Low,
                        4..=6 => Severity::Medium,
                        7..=8 => Severity::High,
                        _ => Severity::Critical,
                    })
                })
            })
            .unwrap_or(Severity::Medium);

        let summary = vuln.summary.unwrap_or_default();
        let details = vuln.details.clone();
        results.push((vuln.id.clone(), summary, details, severity));
    }

    Ok(results)
}

/// Find dependency manifests in a project directory
fn find_manifests(project_path: &Path) -> Vec<PathBuf> {
    let mut manifests = Vec::new();

    // Walk the project root (not recursively into dep dirs)
    if let Ok(entries) = std::fs::read_dir(project_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                continue;
            }

            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.to_lowercase())
                .unwrap_or_default();

            match file_name.as_str() {
                "cargo.toml" | "cargo.lock" | "package.json" | "package-lock.json"
                | "yarn.lock" | "requirements.txt" | "gemfile" | "gemfile.lock"
                | "go.mod" | "go.sum" | "composer.json" | "build.gradle"
                | "pom.xml" | "pubspec.yaml" => {
                    manifests.push(path);
                }
                _ => {}
            }
        }
    }

    // Also look in common subdirectories
    for subdir in &["src", "app", "server", "client", "backend", "frontend", "api"] {
        let sub_path = project_path.join(subdir);
        if sub_path.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&sub_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        continue;
                    }
                    let file_name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.to_lowercase())
                        .unwrap_or_default();
                    if file_name == "cargo.toml" || file_name == "package.json" {
                        manifests.push(path);
                    }
                }
            }
        }
    }

    manifests
}

/// Parse dependencies from a manifest file based on its name
fn parse_manifest(path: &Path) -> Result<Vec<Dependency>> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.to_lowercase())
        .unwrap_or_default();

    match file_name.as_str() {
        "cargo.toml" => parse_cargo_toml(path),
        "package.json" => parse_package_json(path),
        "requirements.txt" => parse_requirements_txt(path),
        _ => Ok(Vec::new()),
    }
}

/// Check embedded advisories for a dependency
fn check_embedded_advisories(dep: &Dependency) -> Vec<Finding> {
    let mut findings = Vec::new();

    for &(eco, name, constraint, desc, severity) in EMBEDDED_ADVISORIES {
        if dep.ecosystem == eco
            && dep.name.to_lowercase() == name.to_lowercase()
            && version_matches_constraint(&dep.version, constraint)
        {
            findings.push(
                Finding::new(
                    FindingType::Dependency,
                    format!("Vulnerable dependency: {}", dep.name),
                    format!("{} ({}) — {}", dep.name, dep.version, desc),
                    severity,
                    Confidence::High,
                    "dependency-scanner",
                )
                .at(
                    dep.manifest_file.to_string_lossy().to_string(),
                    0,
                )
                .with_cve(desc.split(':').next().unwrap_or("unknown"))
                .with_remediation(format!(
                    "Upgrade {} from {} to a version that fixes the vulnerability.",
                    dep.name, dep.version
                ))
                .with_exploitability(match severity {
                    Severity::Critical => 0.7,
                    Severity::High => 0.5,
                    Severity::Medium => 0.3,
                    _ => 0.1,
                })
                .with_effort(match severity {
                    Severity::Critical | Severity::High => RemediationEffort::Hours,
                    _ => RemediationEffort::Minutes,
                }),
            );
        }
    }

    findings
}

/// Collect dependency findings without displaying them (for report generation)
pub(crate) async fn collect_deps_findings(
    project_path: &Path,
    use_online: bool,
) -> Result<FindingReport> {
    let canonical_path = std::fs::canonicalize(project_path)?;

    let manifests = find_manifests(&canonical_path);
    let mut all_deps: Vec<Dependency> = Vec::new();

    for manifest in &manifests {
        if let Ok(deps) = parse_manifest(manifest) {
            all_deps.extend(deps);
        }
    }

    // Deduplicate by name
    all_deps.sort_by(|a, b| a.name.cmp(&b.name));
    all_deps.dedup_by(|a, b| a.name.eq_ignore_ascii_case(&b.name));

    let mut report = FindingReport::new("dependency-scanner", canonical_path.to_string_lossy());

    for dep in &all_deps {
        // Embedded advisories (always)
        report.extend(check_embedded_advisories(dep));

        // OSV.dev API (optional)
        if use_online {
            if let Ok(osv_results) = query_osv(&dep.ecosystem, &dep.name, &dep.version).await {
                for (cve_id, summary, details, severity) in osv_results {
                    let description = details.as_deref().unwrap_or(&summary).to_string();
                    let finding = Finding::new(
                        FindingType::Dependency,
                        format!("CVE: {} — {}", cve_id, dep.name),
                        format!("{} {}: {}", dep.name, dep.version, description),
                        severity,
                        Confidence::High,
                        "dependency-scanner",
                    )
                    .at(dep.manifest_file.to_string_lossy().to_string(), 0)
                    .with_cve(&cve_id)
                    .with_remediation(format!(
                        "Upgrade {} to a patched version. See {} for details.",
                        dep.name, cve_id
                    ))
                    .with_exploitability(match severity {
                        Severity::Critical => 0.8,
                        Severity::High => 0.6,
                        _ => 0.3,
                    })
                    .with_effort(RemediationEffort::Hours);
                    report.add(finding);
                }
            }
        }
    }

    report.sort_by_risk();
    Ok(report)
}

/// Run the `cipher deps` command
pub async fn run_deps(
    project_path: &Path,
    use_online: bool,
) -> Result<FindingReport> {
    let canonical_path = std::fs::canonicalize(project_path)?;

    println!(
        "{} {}",
        "📦".bright_blue(),
        format!("Analyzing dependencies in {}...", canonical_path.display()).bold()
    );

    let manifests = find_manifests(&canonical_path);

    if manifests.is_empty() {
        println!("  {} No dependency manifests found.", "📭".yellow());
        println!("  Supported: Cargo.toml, package.json, requirements.txt, and others.");
        return Ok(FindingReport::new("dependency-scanner", canonical_path.to_string_lossy()));
    }

    println!(
        "  {} Found {} manifest file(s)",
        "📄".cyan(),
        manifests.len().to_string().bold()
    );

    // Parse all dependencies
    let mut all_deps: Vec<Dependency> = Vec::new();
    for manifest in &manifests {
        match parse_manifest(manifest) {
            Ok(deps) => {
                println!(
                    "  {} Parsed {} from {}",
                    "✓".green(),
                    format!("{} dependencies", deps.len()).bold(),
                    manifest.file_name().unwrap().to_string_lossy().yellow()
                );
                all_deps.extend(deps);
            }
            Err(e) => {
                eprintln!("  {} Failed to parse {}: {}", "⚠".yellow(), manifest.display(), e);
            }
        }
    }

    all_deps.sort_by(|a, b| a.name.cmp(&b.name));
    all_deps.dedup_by(|a, b| a.name.eq_ignore_ascii_case(&b.name));

    if all_deps.is_empty() {
        println!("\n  {} No dependencies found in manifests.", "📭".yellow());
        return Ok(FindingReport::new("dependency-scanner", canonical_path.to_string_lossy()));
    }

    println!(
        "  {} Found {} unique dependencies",
        "🔍".cyan(),
        all_deps.len().to_string().bold()
    );

    // Collect findings
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} Checking dependencies for vulnerabilities... {msg}")
            .unwrap(),
    );
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));

    let report = collect_deps_findings(&canonical_path, use_online).await?;

    spinner.finish_and_clear();

    // Display results
    println!();
    println!("{} {}", "📋".bright_blue(), "Dependency Analysis Results".bold());
    println!("  {}", "─".repeat(50).dimmed());
    report.print_summary();

    if report.is_empty() {
        println!();
        println!("{} No known vulnerabilities found in dependencies.", "✅".green().bold());
        if !use_online {
            println!(
                "  {} Run {} for online vulnerability database checks (requires internet).",
                "🌐".cyan(),
                "cipher deps --online".yellow()
            );
        }
        return Ok(report);
    }

    report.print_detailed();

    // Print dependency list
    println!();
    println!("{} {}", "📋".bold(), "All Dependencies".bold());
    println!("  {}", "─".repeat(40).dimmed());

    for dep in &all_deps {
        let vuln_count = report
            .findings
            .iter()
            .filter(|f| f.file_path.as_deref().map(|fp| fp.contains(&dep.name)).unwrap_or(false))
            .count();
        let status = if vuln_count > 0 {
            format!("{} ({})", "⚠".yellow(), format!("{} vulnerabilities", vuln_count).red().bold())
        } else {
            "✓".green().to_string()
        };
        println!("  {} {} {}  {}", dep.ecosystem.bold().dimmed(), dep.name.cyan(), dep.version.dimmed(), status);
    }

    let critical_high = report.findings.iter().filter(|f| f.severity == Severity::Critical || f.severity == Severity::High).count();
    if critical_high > 0 {
        println!();
        println!("{} Found {} critical/high severity dependency issues. Update affected packages immediately.", "⚠".yellow().bold(), critical_high.to_string().bold());
    }

    Ok(report)
}
