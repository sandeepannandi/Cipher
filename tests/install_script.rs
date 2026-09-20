//! Deterministic checks for install.sh: it must parse, map every release
//! target, reject unknown platforms, and stay wired to the release
//! workflow's SHA256SUMS contract. No network access.

use std::process::Command;

fn install_sh() -> String {
    format!("{}/install.sh", env!("CARGO_MANIFEST_DIR"))
}

fn resolve(os: &str, arch: &str) -> (bool, String) {
    let out = Command::new("sh")
        .arg(install_sh())
        .args(["--resolve-target", os, arch])
        .output()
        .expect("install.sh should run under sh");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
    )
}

#[test]
fn install_script_parses_as_posix_sh() {
    let status = Command::new("sh")
        .args(["-n", &install_sh()])
        .status()
        .unwrap();
    assert!(status.success(), "sh -n must accept install.sh");
}

#[test]
fn resolve_target_covers_every_release_artifact() {
    // Must match the target matrix in .github/workflows/release.yml.
    let cases = [
        ("Linux", "x86_64", "x86_64-unknown-linux-gnu"),
        ("Linux", "amd64", "x86_64-unknown-linux-gnu"),
        ("Linux", "aarch64", "aarch64-unknown-linux-gnu"),
        ("Linux", "arm64", "aarch64-unknown-linux-gnu"),
        ("Darwin", "x86_64", "x86_64-apple-darwin"),
        ("Darwin", "arm64", "aarch64-apple-darwin"),
        ("MINGW64_NT", "x86_64", "x86_64-pc-windows-msvc"),
        ("MSYS_NT", "x86_64", "x86_64-pc-windows-msvc"),
    ];
    for (os, arch, want) in cases {
        let (ok, got) = resolve(os, arch);
        assert!(ok, "{os}/{arch} should resolve");
        assert_eq!(got, want, "{os}/{arch}");
    }
}

#[test]
fn resolve_target_rejects_unknown_platforms() {
    for (os, arch) in [("Linux", "mips"), ("Darwin", "ppc"), ("Plan9", "x86_64")] {
        let (ok, _) = resolve(os, arch);
        assert!(!ok, "{os}/{arch} must be rejected, not guessed");
    }
}

#[test]
fn release_workflow_publishes_sha256sums() {
    // The installer's integrity check depends on this contract.
    let wf = std::fs::read_to_string(format!(
        "{}/.github/workflows/release.yml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert!(
        wf.contains("SHA256SUMS.txt"),
        "release.yml must publish SHA256SUMS.txt for install.sh to verify"
    );
}

#[test]
fn install_script_verifies_before_installing() {
    let body = std::fs::read_to_string(install_sh()).unwrap();
    assert!(body.contains("sha256sum -c"), "checksum verify step");
    assert!(
        body.contains("refusing to install"),
        "mismatch must be a hard failure"
    );
}
