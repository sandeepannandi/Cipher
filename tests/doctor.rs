use serde_json::Value;
use std::process::Command;

#[test]
fn doctor_json_output_is_secret_safe_and_deterministic() {
    let output = Command::new(env!("CARGO_BIN_EXE_cipher-ai"))
        .args(["doctor", "--format", "json"])
        .env("CIPHER_AI_PROVIDER", "openai")
        .env_remove("OPENAI_API_KEY")
        .env_remove("GROQ_API_KEY")
        .env_remove("ANTHROPIC_API_KEY")
        .output()
        .expect("doctor command should run");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let parsed: Value = serde_json::from_str(&stdout).expect("stdout should contain valid JSON");

    assert_eq!(parsed["provider"], "openai");
    assert_eq!(parsed["action"], "needs-setup");
    assert_eq!(parsed["active_key_status"]["env_var"], "OPENAI_API_KEY");
    assert!(!parsed.to_string().contains("sk-"));
    assert!(!stderr.contains("sk-"));
    assert!(!stdout.contains("OPENAI_API_KEY=\""));
    assert!(!stdout.contains("GROQ_API_KEY=\""));
    assert!(
        stderr.contains("Missing active key for openai")
            || parsed["active_key_status"]["configured"].as_bool() == Some(false)
    );
}
