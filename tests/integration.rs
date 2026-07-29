// ── Integration Tests for CipherAI ──────────────────────────────────
//
// These tests verify the core detection, parsing, and analysis logic.
// They are designed to be fast — no actual filesystem scanning of
// large directories, just targeted tests with temporary files.

use cipher_ai::{deps, scan, zeroday, sbom, finding};

// ═════════════════════════════════════════════════════════════════════
// scan.rs — Exclusion & Binary Detection
// ═════════════════════════════════════════════════════════════════════

#[test]
fn test_should_exclude_git() {
    assert!(scan::should_exclude(std::path::Path::new("/project/.git/config")));
}

#[test]
fn test_should_exclude_node_modules() {
    assert!(scan::should_exclude(std::path::Path::new("/project/node_modules/express/index.js")));
}

#[test]
fn test_should_not_exclude_source() {
    assert!(!scan::should_exclude(std::path::Path::new("/project/src/main.rs")));
}

#[test]
fn test_should_exclude_minified() {
    assert!(scan::should_exclude(std::path::Path::new("/project/app.min.js")));
}

#[test]
fn test_should_exclude_image() {
    assert!(scan::should_exclude(std::path::Path::new("/project/logo.svg")));
    assert!(scan::should_exclude(std::path::Path::new("/project/photo.png")));
}

#[test]
fn test_should_exclude_cipher_ai_dir() {
    assert!(scan::should_exclude(std::path::Path::new("/project/.cipher-ai/index.json")));
}

#[test]
fn test_should_exclude_build_dir() {
    assert!(scan::should_exclude(std::path::Path::new("/project/build/output.o")));
}

// ═════════════════════════════════════════════════════════════════════
// zeroday.rs — Helper Function Tests
// ═════════════════════════════════════════════════════════════════════

#[test]
fn test_is_function_signature_rust() {
    assert!(zeroday::is_function_signature("fn hello()", "rs"));
    assert!(zeroday::is_function_signature("fn main() {", "rs"));
    assert!(!zeroday::is_function_signature("let x = 5;", "rs"));
}

#[test]
fn test_is_function_signature_python() {
    assert!(zeroday::is_function_signature("def hello():", "py"));
    assert!(zeroday::is_function_signature("def main(args):", "py"));
    assert!(!zeroday::is_function_signature("print('hello')", "py"));
}

#[test]
fn test_is_function_signature_javascript() {
    assert!(zeroday::is_function_signature("function hello() {", "js"));
    assert!(zeroday::is_function_signature("async function fetch() {", "js"));
    assert!(!zeroday::is_function_signature("const x = 5;", "js"));
}

#[test]
fn test_is_function_signature_go() {
    assert!(zeroday::is_function_signature("func main() {", "go"));
    assert!(zeroday::is_function_signature("func hello(w http.ResponseWriter, r *http.Request) {", "go"));
    assert!(!zeroday::is_function_signature("import \"fmt\"", "go"));
}

#[test]
fn test_is_function_signature_java() {
    assert!(zeroday::is_function_signature("public void doSomething() {", "java"));
    assert!(zeroday::is_function_signature("private String getName() {", "java"));
    assert!(!zeroday::is_function_signature("import java.util.List;", "java"));
}

#[test]
fn test_is_function_signature_php() {
    assert!(zeroday::is_function_signature("function hello() {", "php"));
    assert!(!zeroday::is_function_signature("echo 'hello';", "php"));
}

#[test]
fn test_is_function_signature_ruby() {
    assert!(zeroday::is_function_signature("def hello()", "rb"));
    assert!(!zeroday::is_function_signature("puts 'hello'", "rb"));
}

#[test]
fn test_extract_function_name_rust() {
    assert_eq!(zeroday::extract_function_name("fn hello() {"), "hello");
    assert_eq!(zeroday::extract_function_name("fn main()"), "main");
    assert_eq!(zeroday::extract_function_name("fn process_data<T>()"), "process_data");
}

#[test]
fn test_extract_function_name_python() {
    assert_eq!(zeroday::extract_function_name("def hello():"), "hello");
    assert_eq!(zeroday::extract_function_name("def process_data(args):"), "process_data");
}

#[test]
fn test_extract_function_name_javascript() {
    assert_eq!(zeroday::extract_function_name("function hello() {"), "hello");
    assert_eq!(zeroday::extract_function_name("function processData() {"), "processData");
}

#[test]
fn test_extract_function_name_go() {
    assert_eq!(zeroday::extract_function_name("func main() {"), "main");
    assert_eq!(zeroday::extract_function_name("func ServeHTTP(w ResponseWriter, r *Request) {"), "ServeHTTP");
}

#[test]
fn test_extract_assigned_var_let() {
    assert_eq!(zeroday::extract_assigned_var("let x = user_input"), Some("x".to_string()));
    assert_eq!(zeroday::extract_assigned_var("let mut data = request.body()"), Some("data".to_string()));
    assert_eq!(zeroday::extract_assigned_var("let name: String = get_name()"), Some("name".to_string()));
}

#[test]
fn test_extract_assigned_var_js() {
    assert_eq!(zeroday::extract_assigned_var("var input = req.body"), Some("input".to_string()));
    assert_eq!(zeroday::extract_assigned_var("const query = params.id"), Some("query".to_string()));
}

#[test]
fn test_extract_assigned_var_simple() {
    assert_eq!(zeroday::extract_assigned_var("x = get_input()"), Some("x".to_string()));
    assert_eq!(zeroday::extract_assigned_var("data = req.body"), Some("data".to_string()));
}

#[test]
fn test_extract_assigned_var_skips_comparisons() {
    assert_eq!(zeroday::extract_assigned_var("if x == 5 {"), None);
    assert_eq!(zeroday::extract_assigned_var("while x != 0 {"), None);
}

#[test]
fn test_extract_assigned_var_destructuring() {
    assert_eq!(zeroday::extract_assigned_var("let {a, b} = get_pair()"), None);
    assert_eq!(zeroday::extract_assigned_var("let (x, y) = get_tuple()"), None);
}

#[test]
fn test_is_comment_rust() {
    assert!(zeroday::is_comment("// this is a comment", "rs"));
    assert!(zeroday::is_comment("/* block comment */", "rs"));
    assert!(!zeroday::is_comment("let x = 5;", "rs"));
}

#[test]
fn test_is_comment_python() {
    assert!(zeroday::is_comment("# this is a comment", "py"));
    assert!(!zeroday::is_comment("print('hello')", "py"));
}

#[test]
fn test_is_comment_empty_line() {
    assert!(zeroday::is_comment("", "rs"));
    assert!(zeroday::is_comment("   ", "rs"));
}

// ═════════════════════════════════════════════════════════════════════
// Zeroday Report & Finding Tests
// ═════════════════════════════════════════════════════════════════════

#[test]
fn test_zeroday_report_new_is_empty() {
    let report = zeroday::ZerodayReport::new("/test/project");
    assert!(report.is_empty());
    assert_eq!(report.total(), 0);
    assert_eq!(report.scanned_files, 0);
}

#[test]
fn test_zeroday_report_total() {
    let mut report = zeroday::ZerodayReport::new("/test/project");
    report.scanned_files = 42;

    let finding_obj = zeroday::ZerodayFinding::new(
        zeroday::AnomalyType::FunctionComplexity,
        "Test finding",
        "Test description",
        finding::Severity::Medium,
        finding::Confidence::Medium,
        "/test/file.rs", 10, "fn test() {}", "Fix it",
    );
    report.anomalies.push(finding_obj);
    assert_eq!(report.total(), 1);
}

#[test]
fn test_zeroday_finding_creation() {
    let f = zeroday::ZerodayFinding::new(
        zeroday::AnomalyType::FunctionComplexity,
        "Overly complex function: 'foo' (120 lines)",
        "Function spans too many lines",
        finding::Severity::Medium,
        finding::Confidence::Medium,
        "/test/file.rs", 10,
        "fn complex() {\n  // lots of code\n}",
        "Refactor into smaller functions",
    );
    assert_eq!(f.anomaly_type, zeroday::AnomalyType::FunctionComplexity);
    assert!(f.finding.title.contains("Overly complex function"));
    assert_eq!(f.risk_score, 5.0);
}

#[test]
fn test_zeroday_severity_mapping() {
    let critical = zeroday::ZerodayFinding::new(
        zeroday::AnomalyType::TypeConfusionRisk,
        "test", "", finding::Severity::Critical,
        finding::Confidence::High, "/f.rs", 1, "", "",
    );
    let low = zeroday::ZerodayFinding::new(
        zeroday::AnomalyType::SuspiciousErrorHandling,
        "test", "", finding::Severity::Low,
        finding::Confidence::Low, "/f.rs", 1, "", "",
    );
    assert_eq!(critical.risk_score, 9.0);
    assert_eq!(low.risk_score, 3.0);
}

#[test]
fn test_anomaly_type_names() {
    use zeroday::AnomalyType::*;
    assert_eq!(FunctionComplexity.name(), "Function Complexity Anomaly");
    assert_eq!(DangerousApiProximity.name(), "Dangerous API Proximity");
    assert_eq!(MissingBoundaryCheck.name(), "Missing Boundary Check");
    assert_eq!(TypeConfusionRisk.name(), "Type Confusion Risk");
    assert_eq!(SuspiciousErrorHandling.name(), "Suspicious Error Handling");
    assert_eq!(TaintedPath.name(), "Tainted Path Traversal");
    assert_eq!(UntrustedToSink.name(), "Untrusted Data to Sink");
    assert_eq!(BusinessLogicFlaw.name(), "Business Logic Flaw");
    assert_eq!(RaceCondition.name(), "Potential Race Condition");
}

#[test]
fn test_anomaly_type_categories() {
    use zeroday::AnomalyType::*;
    assert_eq!(FunctionComplexity.category(), "anomaly");
    assert_eq!(DangerousApiProximity.category(), "anomaly");
    assert_eq!(MissingBoundaryCheck.category(), "anomaly");
    assert_eq!(TypeConfusionRisk.category(), "anomaly");
    assert_eq!(SuspiciousErrorHandling.category(), "anomaly");
    assert_eq!(TaintedPath.category(), "flow");
    assert_eq!(UntrustedToSink.category(), "flow");
    assert_eq!(BusinessLogicFlaw.category(), "ai");
    assert_eq!(RaceCondition.category(), "ai");
}

// ═════════════════════════════════════════════════════════════════════
// deps.rs — Manifest Parsing Tests (temporary files)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn test_parse_cargo_toml_basic() {
    let dir = std::env::temp_dir();
    let path = dir.join("Cargo_test_basic.toml");
    std::fs::write(&path, r#"
[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }

[dev-dependencies]
tempfile = "3.0"
"#).unwrap();

    let deps = deps::parse_cargo_toml(&path).unwrap();
    assert_eq!(deps.len(), 3);
    assert!(deps.iter().any(|d| d.name == "serde" && d.version == "1.0" && !d.is_dev));
    assert!(deps.iter().any(|d| d.name == "tokio" && d.version == "1.0" && !d.is_dev));
    assert!(deps.iter().any(|d| d.name == "tempfile" && d.version == "3.0" && d.is_dev));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_parse_cargo_toml_empty() {
    let dir = std::env::temp_dir();
    let path = dir.join("Cargo_test_empty.toml");
    std::fs::write(&path, "[package]\nname = \"test\"\nversion = \"0.1.0\"\n").unwrap();
    let deps = deps::parse_cargo_toml(&path).unwrap();
    assert!(deps.is_empty());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_parse_package_json_basic() {
    let dir = std::env::temp_dir();
    let path = dir.join("package_test.json");
    std::fs::write(&path, r#"{
  "name": "test",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "~4.17.21"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}"#).unwrap();

    let deps = deps::parse_package_json(&path).unwrap();
    assert_eq!(deps.len(), 3);
    assert!(deps.iter().any(|d| d.name == "express" && d.version == "4.18.0" && !d.is_dev));
    assert!(deps.iter().any(|d| d.name == "jest" && d.version == "29.0.0" && d.is_dev));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_parse_package_json_no_deps() {
    let dir = std::env::temp_dir();
    let path = dir.join("package_test_no_deps.json");
    std::fs::write(&path, r#"{"name": "test"}"#).unwrap();
    let deps = deps::parse_package_json(&path).unwrap();
    assert!(deps.is_empty());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_parse_requirements_txt_basic() {
    let dir = std::env::temp_dir();
    let path = dir.join("requirements_test.txt");
    std::fs::write(&path, "# Requirements\nflask==2.3.0\ndjango==4.2.0\n").unwrap();

    let deps = deps::parse_requirements_txt(&path).unwrap();
    assert_eq!(deps.len(), 2);
    assert!(deps.iter().any(|d| d.name == "flask" && d.version == "2.3.0"));
    assert!(deps.iter().any(|d| d.name == "django" && d.version == "4.2.0"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_parse_go_mod_block() {
    let dir = std::env::temp_dir();
    let path = dir.join("go_test.mod");
    std::fs::write(&path, r#"module example.com/project

go 1.21

require (
    github.com/gin-gonic/gin v1.9.0
    golang.org/x/net v0.14.0
)
"#).unwrap();

    let deps = deps::parse_go_mod(&path).unwrap();
    assert_eq!(deps.len(), 2);
    assert!(deps.iter().any(|d| d.name == "github.com/gin-gonic/gin" && d.version == "v1.9.0"));
    assert!(deps.iter().any(|d| d.name == "golang.org/x/net" && d.version == "v0.14.0"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_parse_go_mod_single_line() {
    let dir = std::env::temp_dir();
    let path = dir.join("go_test_single.mod");
    std::fs::write(&path, r#"module example.com/project

go 1.21

require github.com/gin-gonic/gin v1.9.0
"#).unwrap();

    let deps = deps::parse_go_mod(&path).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "github.com/gin-gonic/gin");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_parse_gemfile_basic() {
    let dir = std::env::temp_dir();
    let path = dir.join("Gemfile_test");
    std::fs::write(&path, r#"source 'https://rubygems.org'

gem 'rails', '~> 7.0.0'
gem 'pg', '>= 1.5.0'
gem 'puma'
"#).unwrap();

    let deps = deps::parse_gemfile(&path).unwrap();
    assert_eq!(deps.len(), 3);
    assert!(deps.iter().any(|d| d.name == "rails" && d.version == "7.0.0"));
    assert!(deps.iter().any(|d| d.name == "pg" && d.version == "1.5.0"));
    assert_eq!(
        deps.iter().find(|d| d.name == "puma").unwrap().version,
        "*"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_parse_composer_json_basic() {
    let dir = std::env::temp_dir();
    let path = dir.join("composer_test.json");
    std::fs::write(&path, r#"{
  "require": {
    "php": "^8.0",
    "laravel/framework": "^10.0",
    "monolog/monolog": "^3.0"
  },
  "require-dev": {
    "phpunit/phpunit": "^10.0"
  }
}"#).unwrap();

    let deps = deps::parse_composer_json(&path).unwrap();
    assert_eq!(deps.len(), 3); // php is skipped
    assert!(deps.iter().any(|d| d.name == "laravel/framework" && !d.is_dev));
    assert!(deps.iter().any(|d| d.name == "phpunit/phpunit" && d.is_dev));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_parse_pubspec_yaml_basic() {
    let dir = std::env::temp_dir();
    let path = dir.join("pubspec_test.yaml");
    std::fs::write(&path, r#"name: test_app
dependencies:
  flutter:
    sdk: flutter
  http: ^1.0.0
  path: ^2.0.0
dev_dependencies:
  flutter_test:
    sdk: flutter
  mockito: ^5.0.0
"#).unwrap();

    let deps = deps::parse_pubspec_yaml(&path).unwrap();
    assert_eq!(deps.len(), 3); // flutter/flutter_test are SDK deps, skipped
    assert!(deps.iter().any(|d| d.name == "http" && d.version == "1.0.0" && !d.is_dev));
    assert!(deps.iter().any(|d| d.name == "path" && d.version == "2.0.0" && !d.is_dev));
    assert!(deps.iter().any(|d| d.name == "mockito" && d.version == "5.0.0" && d.is_dev));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_parse_pubspec_yaml_version_map() {
    let dir = std::env::temp_dir();
    let path = dir.join("pubspec_test_map.yaml");
    std::fs::write(&path, r#"name: test_app
dependencies:
  awesome_package:
    version: ^3.0.0
"#).unwrap();

    let deps = deps::parse_pubspec_yaml(&path).unwrap();
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].name, "awesome_package");
    assert_eq!(deps[0].version, "3.0.0");
    let _ = std::fs::remove_file(&path);
}

// ═════════════════════════════════════════════════════════════════════
// deps.rs — Version Matching Tests
// ═════════════════════════════════════════════════════════════════════

#[test]
fn test_version_match_less_than() {
    assert!(deps::version_matches_constraint("1.0.0", "<1.0.1"));
    assert!(deps::version_matches_constraint("0.9.0", "<1.0.0"));
    assert!(deps::version_matches_constraint("1.0.0", "<1.1.0"));
}

#[test]
fn test_version_match_not_less_than() {
    assert!(!deps::version_matches_constraint("1.0.1", "<1.0.0"));
    assert!(!deps::version_matches_constraint("2.0.0", "<1.0.0"));
    assert!(!deps::version_matches_constraint("1.0.0", "<1.0.0"));
}

#[test]
fn test_version_match_less_or_equal() {
    assert!(deps::version_matches_constraint("1.0.0", "<=1.0.0"));
    assert!(deps::version_matches_constraint("0.9.0", "<=1.0.0"));
    assert!(deps::version_matches_constraint("1.0.0", "<=1.0.1"));
}

#[test]
fn test_version_match_not_less_or_equal() {
    assert!(!deps::version_matches_constraint("1.0.1", "<=1.0.0"));
    assert!(!deps::version_matches_constraint("2.0.0", "<=1.9.9"));
}

#[test]
fn test_version_match_edge_cases() {
    // Invalid/parseable versions
    assert!(!deps::version_matches_constraint("abc", "<1.0.0"));
    // Single-number versions (like "1")
    assert!(deps::version_matches_constraint("1", "<2.0.0"));
    // Two-number versions (like "1.0")
    assert!(deps::version_matches_constraint("1.0", "<1.1.0"));
}

// ═════════════════════════════════════════════════════════════════════
// deps.rs — Manifest Discovery Tests
// ═════════════════════════════════════════════════════════════════════

#[test]
fn test_find_manifests_in_project() {
    // Use the actual project root — should find Cargo.toml
    let project_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifests = deps::find_manifests(project_root);
    assert!(!manifests.is_empty(), "Should find at least Cargo.toml");
    assert!(
        manifests.iter().any(|m| m.file_name().and_then(|n| n.to_str()) == Some("Cargo.toml")),
        "Should find Cargo.toml"
    );
}

#[test]
fn test_find_manifests_empty_dir() {
    let dir = std::env::temp_dir().join("cipher_test_empty_manifests");
    let _ = std::fs::create_dir_all(&dir);
    let manifests = deps::find_manifests(&dir);
    assert!(manifests.is_empty());
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn test_parse_manifest_cargo_toml() {
    let project_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let cargo_toml = project_root.join("Cargo.toml");
    let deps = deps::parse_manifest(&cargo_toml).unwrap();
    assert!(!deps.is_empty(), "Should find dependencies in Cargo.toml");
    assert!(deps.iter().any(|d| d.name == "clap"));
    assert!(deps.iter().any(|d| d.name == "tokio"));
    assert!(deps.iter().any(|d| d.name == "serde"));
}

#[test]
fn test_parse_manifest_unknown_file() {
    let dir = std::env::temp_dir();
    let path = dir.join("unknown_test_file.txt");
    std::fs::write(&path, "some content").unwrap();
    let deps = deps::parse_manifest(&path).unwrap();
    assert!(deps.is_empty());
    let _ = std::fs::remove_file(&path);
}

// ═════════════════════════════════════════════════════════════════════
// sbom.rs — PURL Mapping Tests
// ═════════════════════════════════════════════════════════════════════

#[test]
fn test_ecosystem_to_purl_crates_io() {
    assert_eq!(sbom::ecosystem_to_purl_type("crates.io"), "cargo");
}

#[test]
fn test_ecosystem_to_purl_npm() {
    assert_eq!(sbom::ecosystem_to_purl_type("npm"), "npm");
}

#[test]
fn test_ecosystem_to_purl_pypi() {
    assert_eq!(sbom::ecosystem_to_purl_type("PyPI"), "pypi");
}

#[test]
fn test_ecosystem_to_purl_go() {
    assert_eq!(sbom::ecosystem_to_purl_type("Go"), "golang");
}

#[test]
fn test_ecosystem_to_purl_rubygems() {
    assert_eq!(sbom::ecosystem_to_purl_type("RubyGems"), "gem");
}

#[test]
fn test_ecosystem_to_purl_packagist() {
    assert_eq!(sbom::ecosystem_to_purl_type("Packagist"), "composer");
}

#[test]
fn test_ecosystem_to_purl_pub() {
    assert_eq!(sbom::ecosystem_to_purl_type("Pub"), "pub");
}

#[test]
fn test_ecosystem_to_purl_unknown() {
    assert_eq!(sbom::ecosystem_to_purl_type("Maven"), "Maven");
    assert_eq!(sbom::ecosystem_to_purl_type("NuGet"), "NuGet");
}
