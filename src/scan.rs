use std::path::Path;

/// Directories/files to always exclude from scanning to prevent hangs
/// on large dependency directories or build artifacts.
pub const ALWAYS_EXCLUDE: &[&str] = &[
    ".git", "node_modules", "vendor", "target", "build", "dist",
    "__pycache__", ".tox", ".venv", "venv", ".env", ".env.example",
    "*.min.js", "*.min.css", "*.map", "*.bundle.js",
    "*.svg", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico",
    "*.woff", "*.woff2", "*.ttf", "*.eot",
    "*.lock", "package-lock.json", "yarn.lock", "Cargo.lock",
    ".cargo", ".cipher-ai", ".secagent",
];

/// Max directory depth for walking (prevents infinite descent)
pub const MAX_WALK_DEPTH: usize = 30;

/// Max files to scan when running review or secrets commands
pub const MAX_SCAN_FILES: usize = 10_000;

/// Check if a path should be excluded from scanning/indexing
pub fn should_exclude(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    for exclude in ALWAYS_EXCLUDE {
        if exclude.starts_with("*.") {
            let ext = &exclude[1..];
            if path_str.ends_with(ext) {
                return true;
            }
        } else if path_str.contains(&exclude.to_lowercase()) {
            return true;
        }
    }
    false
}

/// Quick check if a file is binary by looking for null bytes.
/// Skips very large files (>10MB) and empty files without reading them.
pub fn is_binary(path: &Path) -> bool {
    // Quick size check before opening
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > 10 * 1024 * 1024 {
            return true;
        }
        if meta.len() == 0 {
            return true;
        }
    }

    use std::io::Read;
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return true,
    };
    let mut buf = [0u8; 512];
    let n = match file.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return true,
    };
    buf[..n].contains(&0u8)
}
