use crate::finding::{Confidence, Finding, Severity};
use crate::groq::GroqClient;
use anyhow::{Context, Result};

/// Maximum findings sent to the AI in a single request (keeps prompts bounded).
const VERIFY_BATCH_SIZE: usize = 15;

const VERIFY_SYSTEM_PROMPT: &str = r#"You are Cipher, an expert application security engineer performing triage.

A static-analysis scanner produced the findings below. For each one, decide whether it is a REAL vulnerability or a FALSE POSITIVE, and give your confidence in that decision.

Respond with ONLY a JSON object:
{
  "verdicts": [
    {
      "index": 0,
      "is_real": true,
      "severity": "HIGH",           // adjust if the scanner got it wrong: CRITICAL|HIGH|MEDIUM|LOW|INFO
      "confidence": "MEDIUM",       // your confidence the finding is real: HIGH|MEDIUM|LOW
      "reason": "One short sentence justifying the verdict"
    }
  ]
}

Rules:
- is_real must be false for clear false positives (e.g. safe usage, test scaffolding, example code, or code that is not reachable from untrusted input)
- When unsure, prefer is_real: true with LOW confidence
- Keep the scanner's severity unless you have strong evidence it is wrong
- If a finding cannot be mapped to a real risk, set is_real to false
- Return ONLY valid JSON"#;

/// Run AI verification over a set of scanner findings.
///
/// Returns the findings the AI confirmed as real, with severity/confidence
/// adjusted per the AI's verdicts. False positives are dropped.
///
/// Graceful degradation: if the AI is unavailable or the response cannot be
/// parsed, the original findings are returned unchanged so scanning still works
/// without an API key.
pub async fn verify_findings(findings: Vec<Finding>, model: Option<&str>) -> Vec<Finding> {
    if findings.is_empty() {
        return findings;
    }

    let client = match GroqClient::from_env() {
        Ok(c) => c,
        Err(_) => return findings, // no API key configured — skip verification
    };

    let mut verified: Vec<Finding> = Vec::with_capacity(findings.len());

    for chunk in findings.chunks(VERIFY_BATCH_SIZE) {
        let user_prompt = build_verify_prompt(chunk);
        let response = match client.chat(VERIFY_SYSTEM_PROMPT, &user_prompt, model).await {
            Ok(r) => r,
            Err(_) => {
                // Verification is best-effort — keep the findings unverified.
                verified.extend(chunk.iter().cloned());
                continue;
            }
        };

        match parse_verdicts(&response, chunk) {
            Ok(verdicts) => {
                for (i, finding) in chunk.iter().enumerate() {
                    let verdict = verdicts.get(&i);
                    match verdict {
                        Some(v) if v.is_real => {
                            let mut f = finding.clone();
                            if let Some(sev) = v.severity {
                                f.severity = sev;
                            }
                            if let Some(conf) = v.confidence {
                                f.confidence = conf;
                            }
                            verified.push(f);
                        }
                        Some(_) => {
                            // is_real == false → false positive, drop it
                        }
                        None => verified.push(finding.clone()),
                    }
                }
            }
            Err(_) => verified.extend(chunk.iter().cloned()),
        }
    }

    verified
}

/// Build the user prompt describing a chunk of findings for AI triage.
fn build_verify_prompt(chunk: &[Finding]) -> String {
    let mut prompt = String::from("Triage these scanner findings:\n\n");

    for (i, f) in chunk.iter().enumerate() {
        let file = f.file_path.as_deref().unwrap_or("<unknown>");
        let line = f
            .line_number
            .map(|l| l.to_string())
            .unwrap_or_default();
        let code = f
            .code_snippet
            .as_deref()
            .map(|c| {
                let lines: Vec<&str> = c.lines().collect();
                let snippet: String = lines
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n");
                if lines.len() > 5 {
                    format!("{}\n...", snippet)
                } else {
                    snippet
                }
            })
            .unwrap_or_default();

        prompt.push_str(&format!(
            "[{}] Title: {}\n    Type: {}\n    Scanner severity: {} (confidence {})\n    Location: {}:{}\n    Code:\n{}\n    Description: {}\n\n",
            i,
            f.title,
            f.finding_type,
            f.severity,
            f.confidence,
            file,
            line,
            if code.is_empty() { "(no snippet)" } else { &code },
            f.description,
        ));
    }

    prompt.push_str(
        "Return your verdicts as JSON — one object per finding, indexed by the [N] number above.",
    );

    prompt
}

/// A single AI verdict for one finding.
struct Verdict {
    is_real: bool,
    severity: Option<Severity>,
    confidence: Option<Confidence>,
}

/// Parse the AI's JSON verdicts into a map of finding-index → verdict.
fn parse_verdicts(response: &str, chunk: &[Finding]) -> Result<std::collections::HashMap<usize, Verdict>> {
    // Extract the JSON object (handles markdown fences / trailing prose).
    let json_str = if let Some(start) = response.find('{') {
        let end = response[start..]
            .rfind('}')
            .map(|i| start + i + 1)
            .unwrap_or(response.len());
        &response[start..end]
    } else {
        anyhow::bail!("No JSON object found in AI verification response");
    };

    #[derive(serde::Deserialize)]
    struct RawVerdict {
        index: usize,
        #[serde(default)]
        is_real: bool,
        severity: Option<String>,
        confidence: Option<String>,
        #[allow(dead_code)]
        reason: Option<String>,
    }

    #[derive(serde::Deserialize)]
    struct RawResponse {
        #[serde(default)]
        verdicts: Vec<RawVerdict>,
    }

    let parsed: RawResponse = serde_json::from_str(json_str)
        .context("Failed to parse AI verification response")?;

    let mut verdicts = std::collections::HashMap::new();
    for raw in parsed.verdicts {
        if raw.index >= chunk.len() {
            continue;
        }
        verdicts.insert(
            raw.index,
            Verdict {
                is_real: raw.is_real,
                severity: raw.severity.as_deref().and_then(parse_severity),
                confidence: raw.confidence.as_deref().and_then(parse_confidence),
            },
        );
    }

    if verdicts.is_empty() {
        anyhow::bail!("AI returned no verdicts");
    }

    Ok(verdicts)
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Some(Severity::Critical),
        "HIGH" => Some(Severity::High),
        "MEDIUM" => Some(Severity::Medium),
        "LOW" => Some(Severity::Low),
        "INFO" => Some(Severity::Info),
        _ => None,
    }
}

fn parse_confidence(s: &str) -> Option<Confidence> {
    match s.to_uppercase().as_str() {
        "HIGH" => Some(Confidence::High),
        "MEDIUM" => Some(Confidence::Medium),
        "LOW" => Some(Confidence::Low),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::FindingType;

    fn mk(title: &str) -> Finding {
        Finding::new(
            FindingType::Vulnerability,
            title,
            "desc",
            Severity::High,
            Confidence::High,
            "security-review",
        )
    }

    #[test]
    fn test_parse_verdicts_ok() {
        let response = r#"{
            "verdicts": [
                {"index": 0, "is_real": true, "severity": "CRITICAL", "confidence": "HIGH", "reason": "reachable"},
                {"index": 1, "is_real": false, "severity": "HIGH", "confidence": "HIGH", "reason": "safe usage"}
            ]
        }"#;
        let chunk = vec![mk("SQL Injection"), mk("MD5 Hash")];
        let verdicts = parse_verdicts(response, &chunk).unwrap();
        assert_eq!(verdicts.len(), 2);
        assert!(verdicts[&0].is_real);
        assert_eq!(verdicts[&0].severity, Some(Severity::Critical));
        assert!(!verdicts[&1].is_real);
    }

    #[test]
    fn test_parse_verdicts_skips_out_of_range() {
        let response = r#"{"verdicts": [{"index": 99, "is_real": true}]}"#;
        let chunk = vec![mk("A")];
        assert!(parse_verdicts(response, &chunk).is_err());
    }

    #[test]
    fn test_parse_verdicts_no_json_errors() {
        let chunk = vec![mk("A")];
        assert!(parse_verdicts("no json", &chunk).is_err());
    }

    #[tokio::test]
    async fn test_verify_findings_empty_is_noop() {
        assert!(verify_findings(vec![], None).await.is_empty());
    }

    #[tokio::test]
    async fn test_verify_findings_no_api_key_keeps_findings() {
        // If a real API key is configured (env or config file), this test would
        // hit the live Groq API — skip the network path in that case.
        if std::env::var("GROQ_API_KEY").is_ok()
            || crate::config::stored_api_key().is_some()
        {
            return;
        }
        // Without a GROQ_API_KEY (or config), verification degrades gracefully
        // and returns everything unchanged.
        let findings = vec![mk("SQL Injection")];
        let result = verify_findings(findings, None).await;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].title, "SQL Injection");
    }
}
