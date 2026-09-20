//! End-to-end tests for `cipher-ai setup` and secret hygiene in `config`.
//! Each test gets an isolated HOME so the real user config is never touched.

use std::path::PathBuf;
use std::process::{Command, Stdio};

const KEY: &str = "gsk_testsecret_abcd1234";

fn fresh_home(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("cipher-ai-setup-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cipher(home: &PathBuf) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cipher-ai"));
    cmd.env("HOME", home)
        .env_remove("GROQ_API_KEY")
        .env_remove("OPENAI_API_KEY")
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("CIPHER_AI_PROVIDER");
    cmd
}

#[test]
fn setup_key_stdin_persists_owner_only_and_never_prints_secret() {
    let home = fresh_home("persist");

    let mut child = cipher(&home)
        .args(["setup", "--provider", "groq", "--key-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(KEY.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();

    assert!(
        out.status.success(),
        "setup failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stdout.contains(KEY), "secret leaked to stdout: {stdout}");
    assert!(!stderr.contains(KEY), "secret leaked to stderr: {stderr}");
    assert!(stdout.contains("doctor check passed"), "{stdout}");

    // Config file holds the key and is owner-only (0600) on unix.
    let config = home.join(".cipher-ai").join("config.json");
    let body = std::fs::read_to_string(&config).unwrap();
    assert!(body.contains(KEY), "key not persisted: {body}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            0o600,
            "config file must be owner-only"
        );
    }

    // doctor confirms the setup without any env var.
    let doctor = cipher(&home).args(["doctor"]).output().unwrap();
    assert!(
        doctor.status.success(),
        "doctor should pass after setup: {}",
        String::from_utf8_lossy(&doctor.stderr)
    );

    // `config get` masks the stored key instead of printing it raw.
    let get = cipher(&home)
        .args(["config", "get", "groq-api-key"])
        .output()
        .unwrap();
    let get_out = String::from_utf8_lossy(&get.stdout);
    assert!(
        !get_out.contains(KEY),
        "config get leaked the key: {get_out}"
    );
    assert!(get_out.contains("gsk_...1234"), "expected mask: {get_out}");
}

#[test]
fn setup_without_key_and_no_tty_fails_with_guidance() {
    let home = fresh_home("notty");
    let out = cipher(&home)
        .args(["setup", "--provider", "groq"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success(), "must fail without a key source");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--key-stdin"),
        "actionable guidance: {stderr}"
    );
}

#[test]
fn setup_rejects_unknown_provider() {
    let home = fresh_home("badprovider");
    let out = cipher(&home)
        .args(["setup", "--provider", "bogus"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Unknown provider"), "{stderr}");
}

#[test]
fn setup_with_env_key_writes_nothing() {
    let home = fresh_home("envkey");
    let out = cipher(&home)
        .args(["setup", "--provider", "groq"])
        .env("GROQ_API_KEY", "gsk_env_only_key")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "env key should satisfy setup: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("nothing written"), "{stdout}");
    assert!(
        !home.join(".cipher-ai").join("config.json").exists(),
        "env-based setup must not persist the key"
    );
}
