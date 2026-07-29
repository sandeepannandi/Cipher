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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_should_exclude_git() {
        assert!(should_exclude(Path::new("/project/.git/config")));
    }

    #[test]
    fn test_should_exclude_node_modules() {
        assert!(should_exclude(Path::new("/project/node_modules/express/index.js")));
    }

    #[test]
    fn test_should_exclude_target() {
        assert!(should_exclude(Path::new("/project/target/debug/build")));
    }

    #[test]
    fn test_should_exclude_vendor() {
        assert!(should_exclude(Path::new("/project/vendor/autoload.php")));
    }

    #[test]
    fn test_should_exclude_lock_files() {
        assert!(should_exclude(Path::new("/project/Cargo.lock")));
    }

    #[test]
    fn test_should_not_exclude_source() {
        assert!(!should_exclude(Path::new("/project/src/main.rs")));
    }

    #[test]
    fn test_should_not_exclude_config() {
        assert!(!should_exclude(Path::new("/project/Cargo.toml")));
    }

    #[test]
    fn test_should_exclude_minified_js() {
        assert!(should_exclude(Path::new("/project/app.min.js")));
    }

    #[test]
    fn test_should_exclude_pycache() {
        assert!(should_exclude(Path::new("/project/__pycache__/main.pyc")));
    }

    #[test]
    fn test_is_binary_empty_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_empty.bin");
        std::fs::write(&path, "").unwrap();
        assert!(is_binary(&path));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_is_binary_text_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_text.txt");
        std::fs::write(&path, "Hello, world!\nThis is text.").unwrap();
        assert!(!is_binary(&path));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_is_binary_with_null_bytes() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_binary.bin");
        let data: Vec<u8> = vec![0x00, 0x01, 0x02, 0xFF];
        std::fs::write(&path, &data).unwrap();
        assert!(is_binary(&path));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_is_binary_large_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_large.bin");
        // Create file > 10 MB
        let data = vec![0x41u8; 11 * 1024 * 1024];
        std::fs::write(&path, &data).unwrap();
        assert!(is_binary(&path));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_should_exclude_cipher_ai_dir() {
        assert!(should_exclude(Path::new("/project/.cipher-ai/index.json")));
    }

    #[test]
    fn test_should_exclude_image_files() {
        assert!(should_exclude(Path::new("/project/logo.svg")));
        assert!(should_exclude(Path::new("/project/photo.png")));
        assert!(should_exclude(Path::new("/project/photo.jpg")));
    }
}
