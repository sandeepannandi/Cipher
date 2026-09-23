use std::fs;

fn workflow(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

#[test]
fn pr_sarif_upload_keeps_untrusted_forks_read_only() {
    let yaml = workflow(".github/workflows/pr-review.yml");

    assert!(yaml.contains("pull_request:"));
    assert!(!yaml
        .lines()
        .any(|line| line.trim_start().starts_with("pull_request_target:")));
    assert!(yaml.contains("security-events: write"));
    assert!(yaml.contains("if: github.event.pull_request.head.repo.full_name == github.repository"));
    assert!(yaml.contains("uses: github/codeql-action/upload-sarif@v4"));
    assert!(yaml.contains("category: cipher-ai/pr-review"));
    assert!(yaml.contains("sarif_file: .cipher-ai-results/pr-review.sarif"));
    assert!(yaml.contains("if-no-files-found: error"));
    assert!(yaml.contains("retention-days: 14"));
    assert!(yaml.contains("./target/x86_64-unknown-linux-gnu/release/cipher-ai pr --diff --path ."));
}

#[test]
fn scheduled_sarif_upload_has_a_separate_stable_category() {
    let yaml = workflow(".github/workflows/security-watch.yml");

    assert!(yaml.contains("schedule:"));
    assert!(yaml.contains("security-events: write"));
    assert!(yaml.contains("uses: github/codeql-action/upload-sarif@v4"));
    assert!(yaml.contains("category: cipher-ai/security-watch"));
    assert!(yaml.contains("sarif_file: .cipher-ai-results/security-watch.sarif"));
    assert!(yaml.contains("if-no-files-found: error"));
    assert!(yaml.contains("retention-days: 30"));
    assert!(yaml.contains("cipher-ai watch --once --risk high --pr --path ."));
}

#[test]
fn both_workflows_generate_untruncated_deterministic_sarif() {
    for path in [
        ".github/workflows/pr-review.yml",
        ".github/workflows/security-watch.yml",
    ] {
        let yaml = workflow(path);
        assert!(yaml.contains("--format sarif"), "{path}");
        assert!(yaml.contains("--max-findings 0"), "{path}");
        assert!(yaml.contains("wait-for-processing: true"), "{path}");
    }
}

#[test]
fn both_workflows_enforce_repository_policy_without_truncating_sarif() {
    for path in [
        ".github/workflows/pr-review.yml",
        ".github/workflows/security-watch.yml",
    ] {
        let yaml = workflow(path);
        assert!(yaml.contains("--fail-on-policy"), "{path}");
        assert!(yaml.contains("--max-findings 0"), "{path}");
    }
}

#[test]
fn committed_policy_is_a_unique_versioned_baseline() {
    let body = std::fs::read_to_string(".cipher-ai-policy.yml").unwrap();
    let value: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
    assert_eq!(value["version"].as_u64(), Some(1));
    let fingerprints = value["baseline"]["fingerprints"].as_sequence().unwrap();
    let unique: std::collections::BTreeSet<_> =
        fingerprints.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(fingerprints.len(), 72);
    assert_eq!(unique.len(), fingerprints.len());
}
