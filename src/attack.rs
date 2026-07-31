use crate::finding::{dedup_findings, Finding};
use crate::groq::GroqClient;
use crate::{deps, review, secrets};
use anyhow::Result;
use colored::*;
use serde::Serialize;
use std::path::Path;

/// Types of attack chains the analyzer can discover
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AttackChainType {
    PrivilegeEscalation,
    DataExfiltration,
    CredentialTheft,
    RemoteCodeExecution,
    SupplyChainAttack,
    CryptographicBreach,
    AuthenticationBypass,
    InformationDisclosure,
}

impl AttackChainType {
    pub fn icon(&self) -> &'static str {
        match self {
            AttackChainType::PrivilegeEscalation => "[UP]",
            AttackChainType::DataExfiltration => "[OUT]",
            AttackChainType::CredentialTheft => "[USER]",
            AttackChainType::RemoteCodeExecution => "[!]",
            AttackChainType::SupplyChainAttack => "[CHAIN]",
            AttackChainType::CryptographicBreach => "[*]",
            AttackChainType::AuthenticationBypass => "[DOOR]",
            AttackChainType::InformationDisclosure => "[ALERT]",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            AttackChainType::PrivilegeEscalation => "Privilege Escalation",
            AttackChainType::DataExfiltration => "Data Exfiltration",
            AttackChainType::CredentialTheft => "Credential Theft",
            AttackChainType::RemoteCodeExecution => "Remote Code Execution",
            AttackChainType::SupplyChainAttack => "Supply Chain Attack",
            AttackChainType::CryptographicBreach => "Cryptographic Breach",
            AttackChainType::AuthenticationBypass => "Authentication Bypass",
            AttackChainType::InformationDisclosure => "Information Disclosure",
        }
    }

    /// Risk multiplier: how dangerous this chain type is (0.0–1.0)
    pub fn severity_multiplier(&self) -> f64 {
        match self {
            AttackChainType::RemoteCodeExecution => 1.0,
            AttackChainType::CredentialTheft => 0.95,
            AttackChainType::PrivilegeEscalation => 0.9,
            AttackChainType::AuthenticationBypass => 0.85,
            AttackChainType::DataExfiltration => 0.8,
            AttackChainType::SupplyChainAttack => 0.75,
            AttackChainType::CryptographicBreach => 0.7,
            AttackChainType::InformationDisclosure => 0.5,
        }
    }


}

/// An attack chain connecting multiple findings into a realistic attack scenario
#[derive(Debug, Clone, Serialize)]
pub struct AttackChain {
    /// Type of attack
    pub chain_type: AttackChainType,
    /// Human-readable name
    pub name: String,
    /// Detailed description of the attack scenario
    pub description: String,
    /// Combined risk score 0–10
    pub risk_score: f64,
    /// The findings in this chain (ordered by occurrence)
    pub findings: Vec<Finding>,
    /// Entry point finding (the first step)
    pub entry_point: String,
    /// Impact finding (the final consequence)
    pub impact: String,
    /// Number of steps in the chain
    pub steps: usize,
}

/// Run the `cipher-ai attack` command
pub async fn run_attack(
    project_path: &Path,
    chain_filter: Option<&str>,
    depth: usize,
    json_output: bool,
    use_ai: bool,
) -> Result<()> {
    let canonical_path = std::fs::canonicalize(project_path)?;

    println!(
        "{} {}\n",
        "[*]".bright_blue().bold(),
        "CipherAI Attack Path Analysis".bold()
    );

    // Step 1: Collect all findings
    println!("  {} Gathering findings from all scanners...", "[*]".cyan());
    let all_findings = collect_all_findings(&canonical_path).await?;

    if all_findings.is_empty() {
        println!("  {} No findings to analyze.", "[-]".yellow());
        return Ok(());
    }
    println!(
        "  {} Collected {} findings\n",
        "[OK]".green(),
        all_findings.len().to_string().bold()
    );

    // Step 2: Discover attack chains using pattern matching
    println!("  {} Analyzing attack paths (depth: {})...", "[*]".cyan(), depth);
    let mut chains = discover_chains(&all_findings, depth);

    // Step 3: Filter by chain type if requested
    if let Some(filter) = chain_filter {
        let filter_lower = filter.to_lowercase();
        chains.retain(|c| {
            c.chain_type.name().to_lowercase().contains(&filter_lower)
                || format!("{:?}", c.chain_type).to_lowercase().contains(&filter_lower)
        });
    }

    // Sort chains by risk score (highest first)
    chains.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if chains.is_empty() {
        println!(
            "  {} No attack chains discovered. Your findings are isolated (not chained).",
            "[OK]".green()
        );
        println!("  This is good — it means weaknesses don't compound.");
        return Ok(());
    }

    // Step 4: AI enrichment (optional)
    if use_ai {
        println!("  {} Enriching chains with AI analysis...", "[AI]".cyan());
        if let Err(e) = enrich_chains_ai(&mut chains, &canonical_path).await {
            eprintln!(
                "  {} AI enrichment failed: {} (continuing with pattern-based results)",
                "[!]".yellow(),
                e
            );
        }
    }

    // Step 5: Output
    if json_output {
        display_chains_json(&chains);
    } else {
        display_chains(&chains);
    }

    // Summary
    println!();
    println!("  {}", "-".repeat(50).dimmed());
    println!(
        "  {} Discovered {} attack chain(s) from {} findings",
        "[*]".bold(),
        chains.len().to_string().bold().red(),
        all_findings.len().to_string().bold()
    );

    // Top recommendation
    if let Some(top) = chains.first() {
        println!();
        println!("  {} Priority chain:", "[TARGET]".bold());
        println!(
            "    {} {} (risk: {:.1}/10)",
            top.chain_type.icon(),
            top.name.bold(),
            top.risk_score
        );
        println!(
            "    {} Chain: {}",
            "->".bold(),
            format!(
                "{}  ->  {}",
                top.entry_point.yellow(),
                top.impact.red().bold()
            )
        );
        println!(
            "    {} {} steps — {} findings involved",
            "[STATS]".bold(),
            top.steps.to_string().cyan(),
            top.findings.len().to_string().cyan()
        );
    }

    println!();
    println!(
        "  [IDEA] Run {} to fix the most critical issues and break these chains.",
        "cipher-ai fix --risk critical".yellow()
    );

    Ok(())
}

/// Collect all findings from every analysis module
async fn collect_all_findings(project_path: &Path) -> Result<Vec<Finding>> {
    let mut all = Vec::new();

    if let Ok(report) = review::collect_review_findings(project_path, false, None).await {
        all.extend(report.findings);
    }
    if let Ok(report) = deps::collect_deps_findings(project_path, false).await {
        all.extend(report.findings);
    }
    if let Ok(report) = secrets::collect_secrets_findings(project_path) {
        all.extend(report.findings);
    }

    // Remove duplicates reported by multiple scanners (e.g. review's
    // "Hardcoded Credentials" and secrets' "Password in Code")
    Ok(dedup_findings(all))
}

/// Collect attack chain summary (count only, no output)
pub async fn collect_attack_summary(project_path: &Path) -> Result<usize> {
    let findings = collect_all_findings(project_path).await?;
    if findings.is_empty() {
        return Ok(0);
    }
    let chains = discover_chains(&findings, 3);
    Ok(chains.len())
}

/// Chain discovery rule: describes what finding types/severities form a chain
struct ChainRule {
    chain_type: AttackChainType,
    /// Keywords/titles that identify the entry point finding
    entry_keywords: &'static [&'static str],
    /// Keywords/titles that identify the follow-up finding
    target_keywords: &'static [&'static str],
    /// Description template
    description: &'static str,
}

/// The chain discovery ruleset
fn build_chain_rules() -> Vec<ChainRule> {
    vec![
        ChainRule {
            chain_type: AttackChainType::PrivilegeEscalation,
            entry_keywords: &["password", "credential", "jwt_secret", "jwt", "hardcoded"],
            target_keywords: &["idor", "access control", "authorization", "mass assignment", "autobinding"],
            description: "Exposed credentials + missing authorization checks = privilege escalation",
        },
        ChainRule {
            chain_type: AttackChainType::DataExfiltration,
            entry_keywords: &["sql injection", "command injection", "injection"],
            target_keywords: &["cors", "access-control", "wildcard", "debug"],
            description: "Injection vulnerability + permissive CORS/debug mode = data exfiltration",
        },
        ChainRule {
            chain_type: AttackChainType::RemoteCodeExecution,
            entry_keywords: &["command injection", "shell_exec", "exec", "popen", "eval"],
            target_keywords: &["insecure deserialization", "no auth", "authentication", "authorization"],
            description: "Command execution + missing security controls = remote code execution",
        },
        ChainRule {
            chain_type: AttackChainType::AuthenticationBypass,
            entry_keywords: &["jwt_secret", "jwt", "token_secret", "signing_key", "cookie"],
            target_keywords: &["cors", "access-control", "wildcard", "debug"],
            description: "Weak authentication secrets + permissive CORS = authentication bypass",
        },
        ChainRule {
            chain_type: AttackChainType::CryptographicBreach,
            entry_keywords: &["md5", "sha1", "des", "ecb", "weak hash", "weak encryption"],
            target_keywords: &["encryption_key", "secret_key", "cipher_key", "aes_key", "hardcoded key"],
            description: "Weak cryptography + exposed keys = cryptographic breach",
        },
        ChainRule {
            chain_type: AttackChainType::InformationDisclosure,
            entry_keywords: &["debug", "debug mode", "verbose"],
            target_keywords: &["logging", "log.", "sensitive data", "pii", "console.log"],
            description: "Debug mode + sensitive logging = information disclosure",
        },
        ChainRule {
            chain_type: AttackChainType::SupplyChainAttack,
            entry_keywords: &["vulnerable dependency", "cve", "dependency"],
            target_keywords: &["mass assignment", "autobinding", "insecure deserialization", "update_attributes"],
            description: "Vulnerable dependencies + insecure data patterns = supply chain attack",
        },
        ChainRule {
            chain_type: AttackChainType::CredentialTheft,
            entry_keywords: &["github", "token", "secret", "api_key", "aws_access", "private key"],
            target_keywords: &["ssrf", "debug", "path traversal", "open redirect"],
            description: "Exposed credentials + server-side access = credential theft",
        },
    ]
}

/// Discover attack chains by matching findings against chain rules.
///
/// `depth` controls how many intermediate findings are pulled into a chain:
/// - depth 2 (default): entry + target only
/// - depth >= 3: intermediate findings from the same file (between the entry
///   and target lines) are added to make the chain longer and more realistic
fn discover_chains(findings: &[Finding], depth: usize) -> Vec<AttackChain> {
    let rules = build_chain_rules();
    let mut chains = Vec::new();
    let depth = depth.max(2);

    for rule in &rules {
        // Find entry findings (seeds)
        let entries: Vec<&Finding> = findings
            .iter()
            .filter(|f| title_contains_any(&f.title, rule.entry_keywords))
            .collect();

        // Find target findings
        let targets: Vec<&Finding> = findings
            .iter()
            .filter(|f| title_contains_any(&f.title, rule.target_keywords))
            .collect();

        if entries.is_empty() || targets.is_empty() {
            continue;
        }

        // Build chains: each entry + each target (same file preferred)
        for entry in &entries {
            for target in &targets {
                // Skip if it's the same finding
                if entry.id == target.id {
                    continue;
                }

                // Prefer findings in the same file or nearby
                let same_file = entry.file_path.is_some()
                    && target.file_path.is_some()
                    && entry.file_path == target.file_path;

                // Calculate risk score for this chain
                let entry_risk = entry.risk_score();
                let target_risk = target.risk_score();
                let base_risk = (entry_risk + target_risk) / 2.0;
                let multiplier = rule.chain_type.severity_multiplier();
                let proximity_bonus = if same_file { 1.5 } else { 1.0 };
                let risk_score = (base_risk * multiplier * proximity_bonus).min(10.0);

                let entry_point = entry.title.clone();
                let impact = target.title.clone();

                // Build the finding list: entry -> intermediates -> target
                let mut chain_findings = Vec::new();
                chain_findings.push((*entry).clone());
                if depth > 2 && same_file {
                    let intermediates = collect_intermediates(findings, entry, target, depth - 2);
                    chain_findings.extend(intermediates.into_iter().cloned());
                }
                chain_findings.push((*target).clone());

                // Preserve display semantics: cross-file chains count one extra
                // hop between files, same-file chains equal the finding count.
                let steps = if same_file {
                    chain_findings.len()
                } else {
                    chain_findings.len() + 1
                };

                let description = if same_file {
                    format!(
                        "{} — Both issues exist in the same file, making exploitation significantly easier.",
                        rule.description
                    )
                } else {
                    format!(
                        "{} — Issues are in different locations but could be chained.",
                        rule.description
                    )
                };

                let name = format!("{} -> {}", entry_point, impact);

                chains.push(AttackChain {
                    chain_type: rule.chain_type,
                    name,
                    description,
                    risk_score,
                    findings: chain_findings,
                    entry_point,
                    impact,
                    steps,
                });
            }
        }
    }

    // Deduplicate chains with same type and same entry+impact
    chains.dedup_by(|a, b| {
        a.chain_type == b.chain_type && a.entry_point == b.entry_point && a.impact == b.impact
    });

    // Merge findings for chains of the same type in the same file
    let mut merged: Vec<AttackChain> = Vec::new();
    for chain in chains {
        if let Some(existing) = merged
            .iter_mut()
            .find(|c: &&mut AttackChain| c.chain_type == chain.chain_type && c.entry_point == chain.entry_point && c.impact == chain.impact)
        {
            // Merge unique findings
            for f in chain.findings {
                if !existing.findings.iter().any(|ef| ef.id == f.id) {
                    existing.findings.push(f);
                }
            }
            existing.steps = existing.findings.len();
            existing.risk_score = existing.risk_score.max(chain.risk_score);
        } else {
            merged.push(chain);
        }
    }

    // Sort by risk
    merged.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    merged
}

/// Collect intermediate findings located in the same file, between the entry
/// and target lines, up to `max_count` of them. Ordered by line number.
fn collect_intermediates<'a>(
    findings: &'a [Finding],
    entry: &Finding,
    target: &Finding,
    max_count: usize,
) -> Vec<&'a Finding> {
    if max_count == 0 {
        return Vec::new();
    }

    let entry_file = match &entry.file_path {
        Some(fp) => fp,
        None => return Vec::new(),
    };
    let (entry_line, target_line) = match (entry.line_number, target.line_number) {
        (Some(e), Some(t)) => (e, t),
        _ => return Vec::new(),
    };
    let (lo, hi) = if entry_line < target_line {
        (entry_line, target_line)
    } else {
        (target_line, entry_line)
    };

    let mut in_between: Vec<&Finding> = findings
        .iter()
        .filter(|f| {
            f.id != entry.id
                && f.id != target.id
                && f.file_path.as_deref() == Some(entry_file.as_str())
                && f.line_number.map(|l| l > lo && l < hi).unwrap_or(false)
        })
        .collect();

    // Prefer findings that belong to this chain's theme (match entry or
    // target keywords) so the intermediate steps stay on-topic.
    in_between.sort_by_key(|f| {
        let themed = title_contains_any(&f.title, &["sql", "inject", "exec", "token", "secret"]);
        (std::cmp::Reverse(themed), f.line_number.unwrap_or(0))
    });

    in_between.truncate(max_count);
    in_between
}

/// Enrich chain descriptions using AI
async fn enrich_chains_ai(
    chains: &mut [AttackChain],
    _project_path: &Path,
) -> Result<()> {
    let client = match GroqClient::from_env() {
        Ok(c) => c,
        Err(_) => {
            // No API key — skip enrichment, default descriptions are fine
            return Ok(());
        }
    };

    // Only enrich the top 5 chains (most impactful)
    let to_enrich = chains.len().min(5);

    for i in 0..to_enrich {
        let chain = &chains[i];

        let findings_summary: Vec<String> = chain
            .findings
            .iter()
            .map(|f| {
                format!(
                    "- [{}] {} in {} (line {})",
                    f.severity,
                    f.title,
                    f.file_path.as_deref().unwrap_or("<unknown>"),
                    f.line_number.map(|l| l.to_string()).unwrap_or_else(|| "?".to_string())
                )
            })
            .collect();
        let findings_text = findings_summary.join("\n");

        let system_prompt = "You are CipherAI, an expert application security engineer. Your job is to analyze how multiple security weaknesses can be combined into realistic attack scenarios.\n\nGiven a set of findings that form an attack chain, generate:\n1. A realistic attack scenario description (2-3 sentences)\n2. The entry point (what an attacker would exploit first)\n3. The impact (what the attacker could achieve)\n\nReturn JSON only: {\"scenario\": \"...\", \"entry_point\": \"...\", \"impact\": \"...\"}";

        let user_prompt = format!(
            r#"Attack chain type: {chain_name}
Findings in this chain:
{findings_text}

Describe how these findings could be chained in a real attack. Return JSON only.
"#,
            chain_name = chain.chain_type.name(),
            findings_text = findings_text,
        );

        if let Ok(response) = client.chat(system_prompt, &user_prompt, None).await {
            if let Ok((scenario, entry_point, impact)) = parse_ai_enrichment(&response) {
                chains[i].description = scenario;
                chains[i].entry_point = entry_point;
                chains[i].impact = impact;
            }
        }
    }

    Ok(())
}

/// Parse AI enrichment response
fn parse_ai_enrichment(response: &str) -> Result<(String, String, String)> {
    let json_str = if let Some(start) = response.find('{') {
        let end = response[start..]
            .rfind('}')
            .map(|i| start + i + 1)
            .unwrap_or(response.len());
        &response[start..end]
    } else {
        anyhow::bail!("No JSON found");
    };

    #[derive(serde::Deserialize)]
    struct Enrichment {
        scenario: Option<String>,
        entry_point: Option<String>,
        impact: Option<String>,
    }

    let parsed: Enrichment = serde_json::from_str(json_str)
        .map_err(|e| anyhow::anyhow!("Parse error: {}", e))?;

    Ok((
        parsed.scenario.unwrap_or_else(|| "Attack scenario".to_string()),
        parsed.entry_point.unwrap_or_else(|| "Unknown entry".to_string()),
        parsed.impact.unwrap_or_else(|| "Unknown impact".to_string()),
    ))
}

/// Display chains in pretty terminal format
fn display_chains(chains: &[AttackChain]) {
    println!();
    println!(
        "{} {}\n",
        "[*]".bold(),
        "Attack Paths Discovered".bold().red()
    );

    for (i, chain) in chains.iter().enumerate() {
        // Chain header
        let risk_color = if chain.risk_score >= 8.0 {
            "red"
        } else if chain.risk_score >= 5.0 {
            "yellow"
        } else {
            "green"
        };

        println!("  {}", "=".repeat(60).dimmed());
        println!(
            "  {} {} {}  {}",
            "#".bold().dimmed(),
            (i + 1).to_string().bold(),
            chain.chain_type.icon(),
            chain.chain_type.name().bold().color(risk_color)
        );
        println!(
            "  {} Risk: {:.1}/10     {} Steps: {}     {} Findings: {}",
            "  ".dimmed(),
            chain.risk_score,
            "  ".dimmed(),
            chain.steps.to_string().cyan(),
            "  ".dimmed(),
            chain.findings.len().to_string().cyan(),
        );

        // Attack chain diagram
        println!();
        println!("    {} Attack Chain:", "[SYNC]".bold());
        let step_labels = [
            ("Entry", chain.entry_point.as_str()),
            ("Impact", chain.impact.as_str()),
        ];
        for (idx, (label, value)) in step_labels.iter().enumerate() {
            if idx == 0 {
                println!("      {} {}  [TARGET] {}", "+-".cyan(), label.bold(), value.yellow());
            } else if idx == step_labels.len() - 1 {
                println!("      {} {}  [!] {}", "+->".cyan(), label.bold(), value.red().bold());
            } else {
                println!("      {} {}  ⚡ {}", "+->".cyan(), label.bold(), value);
            }
        }

        // Description
        println!();
        println!("    {} Description:", "[NOTE]".bold());
        for line in chain.description.lines() {
            println!("      {}", line);
        }

        // Finding details
        println!();
        println!("    {} Findings involved:", "[LIST]".bold());
        for finding in &chain.findings {
            let fp = finding
                .file_path
                .as_deref()
                .unwrap_or("<unknown>")
                .split('/')
                .last()
                .unwrap_or("<unknown>");
            let line = finding
                .line_number
                .map(|l| format!(":{}", l))
                .unwrap_or_default();
            println!(
                "      {} {} {}  {}{}",
                finding.severity.badge(),
                finding.finding_type.icon(),
                finding.title.dimmed(),
                fp.yellow(),
                line
            );
        }
        println!();
    }
}

/// Display chains as JSON
fn display_chains_json(chains: &[AttackChain]) {
    #[derive(Serialize)]
    struct ChainsOutput<'a> {
        total_chains: usize,
        chains: &'a [AttackChain],
    }

    let output = ChainsOutput {
        total_chains: chains.len(),
        chains,
    };

    match serde_json::to_string_pretty(&output) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("{} JSON serialization failed: {}", "[ERR]".red(), e),
    }
}

/// Check if a title contains any of the given keywords (case-insensitive)
fn title_contains_any(title: &str, keywords: &[&str]) -> bool {
    let title_lower = title.to_lowercase();
    keywords
        .iter()
        .any(|kw| title_lower.contains(&kw.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Confidence, FindingType, Severity};

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
    fn test_title_contains_any_case_insensitive() {
        assert!(title_contains_any("Hardcoded Password", &["password"]));
        assert!(!title_contains_any("SQL Injection", &["password"]));
    }

    #[test]
    fn test_discover_chains_basic() {
        let findings = vec![
            mk("Hardcoded password in config", "/proj/app.py", 10),
            mk("Mass assignment risk", "/proj/app.py", 30),
        ];
        let chains = discover_chains(&findings, 2);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].chain_type, AttackChainType::PrivilegeEscalation);
        assert_eq!(chains[0].steps, 2);
    }

    #[test]
    fn test_discover_chains_no_match() {
        let findings = vec![
            mk("Weak MD5 hash", "/proj/a.py", 10),
            mk("Debug mode enabled", "/proj/b.py", 20),
        ];
        let chains = discover_chains(&findings, 2);
        assert!(chains.is_empty());
    }

    #[test]
    fn test_discover_chains_depth_adds_intermediates() {
        let findings = vec![
            mk("Hardcoded password in config", "/proj/app.py", 10),
            mk("SQL injection in query", "/proj/app.py", 20),
            mk("Mass assignment risk", "/proj/app.py", 30),
        ];
        let shallow = discover_chains(&findings, 2);
        assert_eq!(shallow[0].steps, 2);

        let deep = discover_chains(&findings, 5);
        assert!(deep[0].steps >= 3, "depth should pull in intermediates");
    }
}
