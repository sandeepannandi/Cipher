//! Repository policy for classifying and gating stable security findings.

use crate::finding::{stable_fingerprints, Confidence, Finding, Severity};
use anyhow::{bail, Context, Result};
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

fn default_version() -> u64 {
    1
}
fn default_severity() -> String {
    "high".into()
}
fn default_confidence() -> String {
    "medium".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default = "default_version")]
    pub version: u64,
    #[serde(default)]
    pub baseline: Baseline,
    #[serde(default)]
    pub suppressions: Vec<Suppression>,
    #[serde(default)]
    pub gate: Gate,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    #[serde(default)]
    pub fingerprints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suppression {
    pub fingerprint: String,
    pub reason: String,
    #[serde(default)]
    pub expires: Option<NaiveDate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gate {
    #[serde(default = "default_severity")]
    pub min_severity: String,
    #[serde(default = "default_confidence")]
    pub min_confidence: String,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            min_severity: default_severity(),
            min_confidence: default_confidence(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingState {
    New,
    Baseline,
    Suppressed,
    Expired,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyFinding {
    pub fingerprint: String,
    pub state: FindingState,
    pub gate_eligible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<NaiveDate>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyEvaluation {
    pub policy_version: u64,
    pub as_of: NaiveDate,
    pub min_severity: String,
    pub min_confidence: String,
    pub gate_failed: bool,
    pub new: usize,
    pub baseline: usize,
    pub suppressed: usize,
    pub expired: usize,
    pub below_threshold: usize,
    pub findings: Vec<PolicyFinding>,
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self> {
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("read policy {}", path.display()))?;
        let policy: Self = serde_yaml::from_str(&body)
            .with_context(|| format!("invalid policy {}", path.display()))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!("unsupported policy version {} (expected 1)", self.version);
        }
        parse_severity(&self.gate.min_severity)
            .with_context(|| format!("invalid gate.min_severity {:?}", self.gate.min_severity))?;
        parse_confidence(&self.gate.min_confidence).with_context(|| {
            format!("invalid gate.min_confidence {:?}", self.gate.min_confidence)
        })?;
        let mut seen = BTreeSet::new();
        for fp in &self.baseline.fingerprints {
            validate_fingerprint(fp)?;
            if !seen.insert(fp) {
                bail!("duplicate baseline fingerprint {fp}");
            }
        }
        let mut suppression_seen = BTreeSet::new();
        for suppression in &self.suppressions {
            validate_fingerprint(&suppression.fingerprint)?;
            if suppression.reason.trim().is_empty() {
                bail!(
                    "suppression {} requires a non-empty reason",
                    suppression.fingerprint
                );
            }
            if !suppression_seen.insert(&suppression.fingerprint) {
                bail!(
                    "duplicate suppression fingerprint {}",
                    suppression.fingerprint
                );
            }
        }
        Ok(())
    }

    pub fn evaluate(&self, findings: &[Finding]) -> Result<PolicyEvaluation> {
        self.evaluate_at(findings, Utc::now().date_naive())
    }

    pub fn evaluate_at(&self, findings: &[Finding], as_of: NaiveDate) -> Result<PolicyEvaluation> {
        self.validate()?;
        let min_severity = parse_severity(&self.gate.min_severity)?;
        let min_confidence = parse_confidence(&self.gate.min_confidence)?;
        let baseline: BTreeSet<&str> = self
            .baseline
            .fingerprints
            .iter()
            .map(String::as_str)
            .collect();
        let suppressions: BTreeMap<&str, &Suppression> = self
            .suppressions
            .iter()
            .map(|s| (s.fingerprint.as_str(), s))
            .collect();
        let mut result = PolicyEvaluation {
            policy_version: self.version,
            as_of,
            min_severity: self.gate.min_severity.to_lowercase(),
            min_confidence: self.gate.min_confidence.to_lowercase(),
            gate_failed: false,
            new: 0,
            baseline: 0,
            suppressed: 0,
            expired: 0,
            below_threshold: 0,
            findings: Vec::with_capacity(findings.len()),
        };
        let fingerprints = stable_fingerprints(findings);
        for (finding, fingerprint) in findings.iter().zip(fingerprints) {
            let threshold = finding.severity.score() >= min_severity.score()
                && finding.confidence.score() >= min_confidence.score();
            let (state, reason, expires) = match suppressions.get(fingerprint.as_str()) {
                Some(s) if s.expires.is_none_or(|date| date >= as_of) => {
                    (FindingState::Suppressed, Some(s.reason.clone()), s.expires)
                }
                Some(s) => (FindingState::Expired, Some(s.reason.clone()), s.expires),
                None if baseline.contains(fingerprint.as_str()) => {
                    (FindingState::Baseline, None, None)
                }
                None => (FindingState::New, None, None),
            };
            match state {
                FindingState::New => result.new += 1,
                FindingState::Baseline => result.baseline += 1,
                FindingState::Suppressed => result.suppressed += 1,
                FindingState::Expired => result.expired += 1,
            }
            let gate_eligible =
                threshold && matches!(state, FindingState::New | FindingState::Expired);
            if !threshold {
                result.below_threshold += 1;
            }
            result.gate_failed |= gate_eligible;
            result.findings.push(PolicyFinding {
                fingerprint,
                state,
                gate_eligible,
                reason,
                expires,
            });
        }
        Ok(result)
    }

    pub fn baseline_from(findings: &[Finding]) -> Self {
        let mut fingerprints: Vec<String> = stable_fingerprints(findings);
        fingerprints.sort();
        fingerprints.dedup();
        Self {
            version: 1,
            baseline: Baseline { fingerprints },
            suppressions: vec![],
            gate: Gate::default(),
        }
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let body = serde_yaml::to_string(self)?;
        std::fs::write(path, body).with_context(|| format!("write policy {}", path.display()))
    }
}

fn validate_fingerprint(fp: &str) -> Result<()> {
    if fp.len() != 71
        || !fp.starts_with("sha256:")
        || !fp[7..].chars().all(|c| c.is_ascii_hexdigit())
    {
        bail!("invalid fingerprint {fp:?}; expected sha256:<64 hex characters>");
    }
    Ok(())
}

fn parse_severity(value: &str) -> Result<Severity> {
    match value.to_ascii_lowercase().as_str() {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        "info" => Ok(Severity::Info),
        _ => bail!("expected critical, high, medium, low, or info"),
    }
}
fn parse_confidence(value: &str) -> Result<Confidence> {
    match value.to_ascii_lowercase().as_str() {
        "high" => Ok(Confidence::High),
        "medium" => Ok(Confidence::Medium),
        "low" => Ok(Confidence::Low),
        _ => bail!("expected high, medium, or low"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{stable_fingerprint, FindingType, Severity};

    fn finding(severity: Severity, confidence: Confidence, line: usize) -> Finding {
        Finding::new(
            FindingType::Injection,
            "SQL Injection",
            "test",
            severity,
            confidence,
            "test",
        )
        .at("src/app.rs", line)
    }

    #[test]
    fn new_baseline_suppressed_and_expired_are_deterministic() {
        let findings = vec![
            finding(Severity::High, Confidence::High, 1),
            finding(Severity::High, Confidence::High, 2),
            finding(Severity::High, Confidence::High, 3),
            finding(Severity::High, Confidence::High, 4),
        ];
        let fps: Vec<_> = findings.iter().map(stable_fingerprint).collect();
        let policy = Policy {
            version: 1,
            baseline: Baseline {
                fingerprints: vec![fps[1].clone()],
            },
            suppressions: vec![
                Suppression {
                    fingerprint: fps[2].clone(),
                    reason: "risk accepted".into(),
                    expires: None,
                },
                Suppression {
                    fingerprint: fps[3].clone(),
                    reason: "temporary".into(),
                    expires: Some(NaiveDate::from_ymd_opt(2026, 9, 19).unwrap()),
                },
            ],
            gate: Gate::default(),
        };
        let result = policy
            .evaluate_at(&findings, NaiveDate::from_ymd_opt(2026, 9, 20).unwrap())
            .unwrap();
        assert_eq!(
            (
                result.new,
                result.baseline,
                result.suppressed,
                result.expired
            ),
            (1, 1, 1, 1)
        );
        assert!(result.gate_failed);
        assert_eq!(
            result.findings.iter().map(|f| f.state).collect::<Vec<_>>(),
            vec![
                FindingState::New,
                FindingState::Baseline,
                FindingState::Suppressed,
                FindingState::Expired
            ]
        );
    }

    fn pattern_finding(line: usize, code: &str) -> Finding {
        Finding::new(
            FindingType::Vulnerability,
            "Path Traversal",
            "test",
            Severity::High,
            Confidence::High,
            "security-review",
        )
        .at("src/files.rs", line)
        .with_code(code)
        .with_cwe("CWE-22")
    }

    #[test]
    fn baseline_survives_line_shift_and_still_gates_new_copies() {
        let accepted = vec![pattern_finding(10, "fs::read(dir + &name)")];
        let policy = Policy::baseline_from(&accepted);
        let today = NaiveDate::from_ymd_opt(2026, 9, 23).unwrap();

        // Code inserted above moves the finding; it stays accepted.
        let shifted = vec![pattern_finding(57, "fs::read(dir + &name)")];
        let result = policy.evaluate_at(&shifted, today).unwrap();
        assert_eq!((result.new, result.baseline), (0, 1));
        assert!(!result.gate_failed);

        // A second identical vulnerable line in the same file is new.
        let duplicated = vec![
            pattern_finding(57, "fs::read(dir + &name)"),
            pattern_finding(90, "fs::read(dir + &name)"),
        ];
        let result = policy.evaluate_at(&duplicated, today).unwrap();
        assert_eq!((result.new, result.baseline), (1, 1));
        assert!(result.gate_failed);

        // Changing the flagged line itself is new.
        let edited = vec![pattern_finding(57, "fs::read(dir + &other)")];
        let result = policy.evaluate_at(&edited, today).unwrap();
        assert_eq!((result.new, result.baseline), (1, 0));
        assert!(result.gate_failed);
    }

    #[test]
    fn thresholds_do_not_hide_findings_but_control_gate() {
        let findings = vec![finding(Severity::Medium, Confidence::High, 1)];
        let result = Policy {
            version: 1,
            baseline: Baseline::default(),
            suppressions: vec![],
            gate: Gate::default(),
        }
        .evaluate_at(&findings, NaiveDate::from_ymd_opt(2026, 9, 20).unwrap())
        .unwrap();
        assert_eq!(result.new, 1);
        assert_eq!(result.below_threshold, 1);
        assert!(!result.gate_failed);
    }

    #[test]
    fn suppression_requires_reason_and_valid_expiry_is_inclusive() {
        let f = finding(Severity::High, Confidence::High, 1);
        let fp = stable_fingerprint(&f);
        let mut policy = Policy {
            version: 1,
            baseline: Baseline::default(),
            suppressions: vec![Suppression {
                fingerprint: fp,
                reason: "ticket SEC-42".into(),
                expires: Some(NaiveDate::from_ymd_opt(2026, 9, 20).unwrap()),
            }],
            gate: Gate::default(),
        };
        assert_eq!(
            policy
                .evaluate_at(&[f], NaiveDate::from_ymd_opt(2026, 9, 20).unwrap())
                .unwrap()
                .suppressed,
            1
        );
        policy.suppressions[0].reason.clear();
        assert!(policy
            .validate()
            .unwrap_err()
            .to_string()
            .contains("non-empty reason"));
    }
}
