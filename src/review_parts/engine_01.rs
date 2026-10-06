use crate::finding::{
    stable_fingerprints, stable_rule_id, Confidence, Finding, FindingReport, FindingType,
    OwaspCategory, RemediationEffort, Severity,
};
use crate::groq::GroqClient;
use crate::indexer;
use crate::output;
use crate::scan;
use anyhow::Result;
use colored::*;
use ignore::WalkBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use serde::Serialize;
use std::path::Path;

/// A single vulnerability detection pattern
struct VulnPattern {
    name: &'static str,
    description: &'static str,
    severity: Severity,
    confidence: Confidence,
    owasp: Option<OwaspCategory>,
    /// Regex pattern to match in code
    pattern: Regex,
    /// Optional regex: when the matched line also matches this, the finding is
    /// suppressed (e.g. a cookie call that already sets the security flags).
    ///
    /// Exists because the `regex` crate has no look-around, so "match X unless
    /// Y" cannot be expressed in a single pattern. This is a whole-line check:
    /// a cookie literally named "Secure" is therefore treated as flagged.
    negative: Option<Regex>,
    /// File extensions to target (empty = all supported)
    target_extensions: &'static [&'static str],
    /// Remediation suggestion template
    remediation: &'static str,
}

/// Build all vulnerability detection patterns
/// Protocol-mandated and non-security weak-hash contexts: the hash is
/// dictated by a protocol (HTTP Digest, S3 ETag, repository metadata), is
/// explicitly flagged non-security (`usedforsecurity=False`), names a cache
/// key / mutex / throttle / checksum / fingerprint rather than protecting a
/// secret, is compared inside the framework's own signed-URL design, or is
/// the definition of a hashing API offered to callers.
const WEAK_HASH_PROTOCOL_NEGATIVE: &str = r#"(?i)usedforsecurity\s*=\s*False|\betag\b|contentmd5|md5hash|\bmutex|throttle|limiter|checksum|fingerprint|cache/|shouldHashKeys|getEmailForVerification|sha1\(\s*static::class|hash_equals\s*\(\s*sha1|metadata\[['"]sha1['"]\]|def\s+\w*(?:md5|sha1)|func\s*\([^)]*\)\s*(?:MD5|SHA1)\s*\(|class\s+(?:MD5|SHA1)\b|function\s+\w*(?:md5|sha1)\s*\(|\bhashfunction\s+\w+\s*=|\.(?:md5|sha1)\(\s*\)|['"][^'"]*[:_\-/]['"]\s*\.\s*(?:md5|sha1)\s*\(|(?:md5|sha1)\s*\((?:[^()]|\([^()]*\))*\)\s*\.\s*['"][^'"]*[:_\-/]['"]|str_split\(\s*\$\w+\s*=\s*(?:md5|sha1)|strtoupper\(\s*sha1|(?:md5|sha1)\s*\(\s*(?:implode\(|["']\|["']\s*\.\s*join\()"#;

fn build_vuln_patterns() -> Vec<VulnPattern> {
    let mut patterns = Vec::new();

    // Helper macro
    macro_rules! add_vuln {
        ($name:expr, $desc:expr, $sev:expr, $conf:expr, $owasp:expr, $re:expr, $exts:expr, $fix:expr) => {
            add_vuln!($name, $desc, $sev, $conf, $owasp, $re, None, $exts, $fix)
        };
        ($name:expr, $desc:expr, $sev:expr, $conf:expr, $owasp:expr, $re:expr, $neg:expr, $exts:expr, $fix:expr) => {
            if let (Ok(re), Ok(negative)) = (Regex::new($re), $neg.map(Regex::new).transpose()) {
                patterns.push(VulnPattern {
                    name: $name,
                    description: $desc,
                    severity: $sev,
                    confidence: $conf,
                    owasp: $owasp,
                    pattern: re,
                    negative,
                    target_extensions: $exts,
                    remediation: $fix,
                });
            }
        };
    }

    // -- Injection --

    add_vuln!(
        "SQL Injection — String Concatenation",
        "SQL queries built with string concatenation or interpolation are vulnerable to SQL injection. Use parameterized queries or an ORM instead.",
        Severity::Critical, Confidence::High, Some(OwaspCategory::A03Injection),
        // Require SQL syntax in the interpolated string, not just a method
        // named `delete`/`query`: HTTP clients use those names too.
        concat!(r#"(?i)\b(?:execute|query|raw|select|insert|update|delete|createNative"#, r#"Query|executeQuery|executeUpdate|\$queryRaw)\s*\(\s*['\"]\s*(?:select|insert|update|delete|with|merge|replace)\b[^'\"]*(?:\$\{|\{[A-Za-z_])"#),
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Replace string concatenation with parameterized queries. Use prepared statements or an ORM's query builder."
    );

    add_vuln!(
        "SQL Injection — ORM Raw Queries",
        "Raw SQL queries bypass ORM protections. Review for potential injection vectors.",
        Severity::High, Confidence::Medium, Some(OwaspCategory::A03Injection),
        // Real sink shapes only: call sites with a SQL string (or any argument
        // for the dedicated raw-query APIs), not identifier collisions such as
        // RawQuerySet names, `execute_sql_flush`, `def execute_sql`, comments
        // mentioning raw(), or config/body-parser `.raw()` methods.
        r#"(?i:execute_sql)\s*\(|(?i:nativequery)\s*\(|(?i:createnativequery)\s*\(|\brawQuery\s*\(|\braw\s*\(\s*[furbFURB]{0,2}['\"]\s*(?i:select|insert|update|delete|replace|with)\b|(?i:raw_sql)\s*\(\s*['\"]|\.sql\("#,
        // Arel.sql is Rails' intentional literal-SQL escape API (used
        // internally on constants and quoted names), `def ...` lines define
        // rather than call these APIs, and an ALL-CAPS constant argument is
        // framework-internal result plumbing (compiler.execute_sql(SINGLE)).
        Some(r#"(?i)\bArel\.sql\s*\(|(?:^|\s)def\s+(?:self\.)?(?:execute_sql|sql|raw)\s*\(|execute_sql\s*\(\s*[A-Z_][A-Z_0-9]*\s*[),]|execute_sql\s*\(\s*\)"#),
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Use the ORM's query builder instead of raw SQL. If raw SQL is required, use parameterized queries."
    );

    add_vuln!(
        "Code Injection",
        "Untrusted request data is evaluated as JavaScript code.",
        Severity::Critical,
        Confidence::High,
        Some(OwaspCategory::A03Injection),
        r#"(?i)(?:eval|Function)\s*\([^)]*(?:req|request)\.(?:params|query|body|headers|cookies)"#,
        &["js", "ts"],
        "Avoid eval/new Function on request data; use safe data parsing and validation."
    );

    add_vuln!(
        "Command Injection",
        "User input is passed to a shell command, which could allow command injection attacks.",
        Severity::Critical, Confidence::High, Some(OwaspCategory::A03Injection),
        // Require evidence of shell evaluation or string composition. Merely
        // constructing a process with a fixed executable and argument vector is safe.
        r#"(?i)(?:(?:exec|system|popen|shell_exec|subprocess\.\w+)\s*\([^)]*\$\{|Command::new\(\s*["'](?:sh|bash|zsh|cmd|powershell)(?:\.exe)?["']\s*\).*\.arg\(\s*["'](?:-c|/c)["']\s*\)|Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+)"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php"],
        "Avoid shell execution with user input. Use safer APIs that don't invoke a shell, and validate/sanitize all input."
    );

    add_vuln!(
        "Path Traversal",
        "File operations using user-controlled paths can allow directory traversal attacks.",
        Severity::High, Confidence::Medium, Some(OwaspCategory::A01BrokenAccessControl),
        r#"(?i)(?:read_to_string|read_file|File::open|fs::read|fs::write|file_get_contents)\s*\([^)]*\$\{|(?:readFile|writeFile)\s*\([^)]*\+"#,
        &["rs", "py", "js", "ts", "go", "rb", "php", "java"],
        "Validate and sanitize file paths. Use allowlists for permitted paths and reject '..' sequences."
    );

    add_vuln!(
        "Server-Side Template Injection (SSTI)",
        "User input is passed directly to a template engine, enabling SSTI attacks.",
        Severity::Critical, Confidence::Medium, Some(OwaspCategory::A03Injection),
        // A template sink is reported only when its name/source receives
        // request-controlled data; render context is not a template source.
        r"(?i)\b(?:res|response)\s*\.\s*render\s*\(\s*(?:req|request)\s*\.\s*(?:params|query|body)\s*\.",
        &["py", "js", "ts", "rb", "php", "go"],
        "Never pass user input directly to template engines. Use context-aware escaping and sandboxed templates."
    );

    add_vuln!(
        "Server-Side Request Forgery (SSRF)",
        "An outbound HTTP request uses a URL taken from user input, letting an attacker reach internal services or cloud metadata endpoints.",
        Severity::High, Confidence::Medium, Some(OwaspCategory::A10SSRF),
        // Same-line shape only: request input passed straight into an HTTP
        // client call. Multi-line flows are found by `ssrf_sink_lines`.
        r#"(?i)\b(?:requests\s*\.\s*(?:get|post|put|delete|head|patch)|urlopen|fetch|axios\s*\.\s*(?:get|post|put|delete)|http\s*\.\s*Get)\s*\(\s*(?:request\s*\.\s*(?:args|form|values|GET|POST|getParameter)|req\s*\.\s*(?:query|body|params)|r\s*\.\s*URL\s*\.\s*Query)"#,
        &["py", "js", "ts", "java", "go", "rs"],
        "Validate outbound URLs against an allowlist of hosts and schemes, block private and metadata addresses, and never pass user input directly as the request URL."
    );

    add_vuln!(
        "Open Redirect",
        "A redirect target taken from request input can send users to an attacker-controlled site.",
        Severity::High, Confidence::High, Some(OwaspCategory::A01BrokenAccessControl),
        // Require request-to-target flow, not every Express or Go redirect.
        r"\x00",
        &["js", "ts", "go", "py"],
        "Allow only known local redirect destinations, or validate the destination against an allowlist."
    );

    add_vuln!(
        "Regular Expression Denial of Service (ReDoS)",
        "A nested repeating regular expression is tested against request-controlled input and can cause excessive backtracking.",
        Severity::High, Confidence::High, Some(OwaspCategory::A04InsecureDesign),
        r"\x00",
        &["js", "ts"],
        "Avoid nested or ambiguous quantifiers, limit input length, or use a linear-time regex engine."
    );

    add_vuln!(
        "Plaintext Password Storage",
        "A password is written to persistent storage without a one-way password hash.",
        Severity::Critical,
        Confidence::High,
        Some(OwaspCategory::A02CryptographicFailures),
        r"\x00",
        &["js", "ts"],
        "Hash passwords with a slow password-hashing algorithm and a unique salt before storage."
    );

    add_vuln!(
        "Plaintext Password Comparison",
        "A stored password is compared directly instead of using a password hash verifier.",
        Severity::High,
        Confidence::High,
        Some(OwaspCategory::A02CryptographicFailures),
        r"\x00",
        &["js", "ts"],
        "Compare a password using the password-hashing library's verification function."
    );

    add_vuln!(
        "Raw Sensitive Profile Storage",
        "Sensitive identity or banking fields are copied into a profile document and written to persistent storage without active encryption.",
        Severity::High, Confidence::High, Some(OwaspCategory::A02CryptographicFailures),
        r"\x00", &["js", "ts", "rb"],
        "Encrypt sensitive profile fields before persistence with managed keys; protect reads and rotate exposed data as appropriate."
    );

    // -- Cryptography --

    add_vuln!(
        "Weak Hash Algorithm — MD5",
        "MD5 is cryptographically broken and unsuitable for security purposes. Use bcrypt, argon2, or SHA-256/512.",
        Severity::High, Confidence::High, Some(OwaspCategory::A02CryptographicFailures),
        r#"(?i)(?:\bmd5\s*\(|MessageDigest\.getInstance\(\s*"MD5"\s*\))"#,
        Some(WEAK_HASH_PROTOCOL_NEGATIVE),
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Replace MD5 with a secure hash function like SHA-256, SHA-512, or bcrypt/argon2 for passwords."
    );

    add_vuln!(
        "Custom Weak Message Digest",
        "A hand-rolled message digest (summed byte values reduced into the printable range) is trivially reversible and collision-prone.",
        Severity::High, Confidence::High, Some(OwaspCategory::A02CryptographicFailures),
        r"\x00", &["cs"],
        "Replace hand-rolled digests with a vetted hash such as SHA-256, or a password KDF where appropriate."
    );

    add_vuln!(
        "Predictable Random Generator",
        "A deterministic hand-rolled recurrence generates 'random' values that are fully predictable from the seed.",
        Severity::Medium, Confidence::High, Some(OwaspCategory::A02CryptographicFailures),
        r"\x00", &["cs"],
        "Use a cryptographically secure generator (RandomNumberGenerator) for security-relevant values."
    );

    add_vuln!(
        "Unbounded Unsafe Pointer Write",
        "User-controlled input is written through an unsafe pointer into a fixed-size buffer with no length check, corrupting memory past the buffer.",
        Severity::High, Confidence::High, Some(OwaspCategory::A03Injection),
        r"\x00", &["cs"],
        "Bound the copy to the buffer length or avoid unsafe pointer writes for user-controlled data."
    );

    add_vuln!(
        "Fast Password Hash (MD5)",
        "A password is stored with fast, unsalted MD5 instead of a password KDF.",
        Severity::High,
        Confidence::High,
        Some(OwaspCategory::A02CryptographicFailures),
        r"\x00",
        &["rb", "go", "py"],
        "Hash passwords with a salted, memory-hard password KDF such as Argon2id."
    );

    add_vuln!(
        "Client-Side Session Storage",
        "Session data is stored in signed client-side cookies: users can read session contents, and a leaked signing key enables forgery.",
        Severity::Medium,
        Confidence::High,
        Some(OwaspCategory::A02CryptographicFailures),
        r"\x00",
        &["py"],
        "Store sessions server-side (database or cache backend) and pass only an opaque session token to the client."
    );
    add_vuln!(
        "Pickle Session Serializer",
        "The Pickle session serializer enables remote code execution if the signing key is compromised.",
        Severity::High,
        Confidence::High,
        Some(OwaspCategory::A08IntegrityFailures),
        r"\x00",
        &["py"],
        "Use the JSON session serializer; reserve Pickle for trusted, signed payloads."
    );
    add_vuln!(
        "CSRF Protection Disabled",
        "A Django view opts out of CSRF validation with the csrf_exempt decorator: state-changing requests can be forged cross-site.",
        Severity::Medium,
        Confidence::High,
        Some(OwaspCategory::A01BrokenAccessControl),
        r"\x00",
        &["py"],
        "Remove the csrf_exempt decorator and rely on CsrfViewMiddleware; exempt only endpoints that genuinely cannot carry a nonce."
    );
    add_vuln!(
        "Django ModelForm Mass Assignment",
        "A ModelForm over the User model uses an exclude blacklist that omits a privilege flag, so a crafted form submission can set it.",
        Severity::High,
        Confidence::High,
        Some(OwaspCategory::A01BrokenAccessControl),
        r"\x00",
        &["py"],
        "Replace the exclude blacklist with a fields whitelist naming only user-editable attributes."
    );
    add_vuln!(
        "Missing Function Level Access Control",
        "A Django view checks only authentication, then mutates group or permission membership without any role check.",
        Severity::High,
        Confidence::High,
        Some(OwaspCategory::A01BrokenAccessControl),
        r"\x00",
        &["py"],
        "Require an appropriate role or permission (is_staff, has_perm, permission_required) before changing group or permission membership."
    );
    add_vuln!(
        "Predictable Session Token",
        "A security token or session cookie is derived from a predictable random or counter value.",
        Severity::High,
        Confidence::High,
        Some(OwaspCategory::A07AuthFailures),
        r"\x00",
        &["go", "php"],
        "Generate unpredictable session identifiers using a cryptographic random source."
    );
    add_vuln!(
        "Weak RSA Key Size",
        "A new RSA key is generated with a key size below modern minimums.",
        Severity::High,
        Confidence::High,
        Some(OwaspCategory::A02CryptographicFailures),
        r"\x00",
        &["go"],
        "Use RSA keys of at least 2048 bits, or a suitable modern elliptic-curve key."
    );
    add_vuln!(
        "Deprecated TLS Minimum Version",
        "A TLS server allows TLS 1.0 or 1.1 connections.",
        Severity::High,
        Confidence::High,
        Some(OwaspCategory::A02CryptographicFailures),
        r"\x00",
        &["go"],
        "Require TLS 1.2 or later; prefer TLS 1.3 when supported."
    );

    add_vuln!(
        "Weak Hash Algorithm — SHA1",
        "SHA-1 is cryptographically weakened and should not be used for security contexts. Use SHA-256/512 or argon2.",
        Severity::Medium, Confidence::High, Some(OwaspCategory::A02CryptographicFailures),
        r#"(?i)\b(sha1)\s*\("#,
        Some(WEAK_HASH_PROTOCOL_NEGATIVE),
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Replace SHA-1 with SHA-256 or SHA-512. For password hashing, use bcrypt or argon2."
    );

    add_vuln!(
        "Weak Encryption — DES",
        "DES is a weak encryption algorithm that can be brute-forced. Use AES-256-GCM or ChaCha20-Poly1305.",
        Severity::High, Confidence::High, Some(OwaspCategory::A02CryptographicFailures),
        // Case-sensitive DES: lowercase `des` is a common identifier
        // (directory entries, French prose). Keep the Go crypto/des
        // constructor shapes, which are how Go code actually invokes DES.
        r#"(?-i:\bDES\b)|(?i:\bdes_ede3\b|\bTripleDES\b|\b3DES\b)|\bdes\.New(?:TripleDESCipher|Cipher)\s*\("#,
        // OpenSSL cipher-suite exclusion tokens ('!DES', '!3DES',
        // '!EDH-DSS-DES-CBC3-SHA') disable DES; they do not use it.
        Some(r#"['"]\s*!\S*(?:3DES|DES)"#),
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Replace DES/TripleDES with AES-256-GCM (authenticated encryption)."
    );

    add_vuln!(
        "Weak Encryption — ECB Mode",
        "ECB mode encryption leaks patterns in the plaintext. Use authenticated encryption like AES-GCM.",
        Severity::High, Confidence::High, Some(OwaspCategory::A02CryptographicFailures),
        r#"(?i)(?:AES|DES|Blowfish)\s*/\s*ECB|ecb_encrypt"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Replace ECB mode with AES-GCM (authenticated encryption with IV/nonce)."
    );

    add_vuln!(
        "Hardcoded Cryptographic Key",
        "Hardcoded encryption keys can be extracted from source code. Use a key management system.",
        Severity::Critical,
        Confidence::Medium,
        Some(OwaspCategory::A02CryptographicFailures),
        r#"(?i)(?:encryption_key|secret_key|cipher_key|aes_key|crypto_key)\s*[=:]\s*['\"][A-Za-z0-9+/=]{16,}['\"]"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Move the key to environment variables or a secret manager. Never hardcode keys in source."
    );

    // -- Authentication & Authorization --

    add_vuln!(
        "Hardcoded Credentials",
        "Hardcoded usernames, passwords, or API keys are a security risk. Use environment variables.",
        Severity::Critical, Confidence::Medium, Some(OwaspCategory::A07AuthFailures),
        // Only match actual hardcoded string literals, not variable assignments from env/functions
        r#"(?i)(?:password|passwd|pwd|secret|api_key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9!@#$%^&*()_+-=]{4,}['\"]"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Remove hardcoded credentials and use environment variables or a secret manager."
    );

    add_vuln!(
        "JWT Secret Hardcoded",
        "JWT signing secrets in source code allow token forgery if exposed.",
        Severity::Critical,
        Confidence::High,
        Some(OwaspCategory::A07AuthFailures),
        r#"(?i)(?:jwt_secret|jwt_key|token_secret|signing_key)\s*[=:]\s*['\"][^'\"]{8,}['\"]"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Use environment variables for JWT secrets. Rotate immediately if exposed."
    );

    add_vuln!(
        "Insecure Cookie Configuration",
        "Cookies missing Secure, HttpOnly, or SameSite flags can be exploited via XSS or MITM.",
        Severity::High,
        Confidence::Medium,
        Some(OwaspCategory::A05SecurityMisconfiguration),
        r#"(?i)(?:cookie|Cookie|set_cookie)\s*\(\s*['\"]\w+['\"]\s*,\s*['\"]\w+['\"]"#,
        Some(r#"(?i)(?:HttpOnly|Secure|SameSite)"#),
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs"],
        "Set Secure, HttpOnly, and SameSite=Lax/Strict flags on all cookies."
    );

    add_vuln!(
        "Unsafe Rails Parameter Assignment",
        "A Rails controller passes unrestricted or privilege-bearing request parameters into a model write.",
        Severity::High,
        Confidence::High,
        Some(OwaspCategory::A01BrokenAccessControl),
        r"\x00",
        &["rb"],
        "Permit only intended fields, exclude role fields, and use an explicit authorization check."
    );

    add_vuln!(
        "Conditional Admin Gate Bypass",
        "An administrator-only Rails action skips its admin check for a request-controlled route parameter.",
        Severity::High, Confidence::High, Some(OwaspCategory::A01BrokenAccessControl),
        r"\x00", &["rb"],
        "Apply the administrator check unconditionally to privileged actions; do not let route parameters decide whether the check runs."
    );

    add_vuln!(
        "SSN Rendered Before Client Masking",
        "A Rails view sends the full SSN in its HTML response and masks it only after the browser receives it.",
        Severity::High, Confidence::High, Some(OwaspCategory::A02CryptographicFailures),
        r"\x00", &["erb"],
        "Render only a server-side masked value or last four digits; never place the full SSN in the response."
    );

    add_vuln!(
        "CSRF on Password Change",
        "A cookie-authenticated PHP password-change form accepts GET parameters and writes the new password without request-token verification.",
        Severity::High, Confidence::High, Some(OwaspCategory::A01BrokenAccessControl),
        r"\x00", &["php"],
        "Require a validated anti-CSRF token and a state-changing POST request for password changes."
    );

    add_vuln!(
        "Level-Conditional Authorization Check",
        "A user-management endpoint reads or writes account data while its administrator role check runs only at specific security levels, leaving the remaining levels with no authorisation check.",
        Severity::High, Confidence::High, Some(OwaspCategory::A01BrokenAccessControl),
        r"\x00", &["php"],
        "Enforce the administrator role check unconditionally before reading or modifying user accounts."
    );

    // -- Security Misconfiguration --

    add_vuln!(
        "Debug Mode Enabled",
        "Debug or development mode in production can leak sensitive information.",
        Severity::High, Confidence::High, Some(OwaspCategory::A05SecurityMisconfiguration),
        r#"(?i)(?:debug\s*[=:]\s*true|DEBUG\s*=\s*True|debug=True|DEBUG=true|app\.debug)"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "yaml", "yml", "json", "toml"],
        "Disable debug/development mode in production. Set debug=False and configure proper logging."
    );

    add_vuln!(
        "Verbose Server Errors",
        "Server error details are exposed to clients, leaking internals useful for attacks.",
        Severity::Medium,
        Confidence::High,
        Some(OwaspCategory::A05SecurityMisconfiguration),
        r"\x00",
        &["config"],
        "Enable custom error pages in production and log detailed errors server-side only."
    );

    add_vuln!(
        "CORS Misconfiguration",
        "Permissive CORS policy allows any origin to access your API. Restrict to trusted origins.",
        Severity::High,
        Confidence::High,
        Some(OwaspCategory::A05SecurityMisconfiguration),
        r#"(?i)(?:Access-Control-Allow-Origin\s*:\s*\*|allow_origins.*\['\''*|cors.*allow_all)"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs"],
        "Replace wildcard CORS origin with specific allowed origins. Never use '*' in production."
    );

    add_vuln!(
        "Log Forging from Login Input",
        "An untrusted login name reaches a line-oriented log without CR/LF removal, allowing forged log entries.",
        Severity::Medium, Confidence::High, Some(OwaspCategory::A09LoggingFailures),
        r"\x00", &["js", "ts"],
        "Remove CR and LF from user-controlled values before logging, and use structured logging with a safe encoder."
    );

    // -- General Security --

    add_vuln!(
        "Insecure Direct Object Reference (IDOR)",
        "User-controlled IDs in API endpoints without authorization checks can lead to unauthorized access.",
        Severity::High, Confidence::Low, Some(OwaspCategory::A01BrokenAccessControl),
        // An ORM lookup alone is not evidence of an authorization flaw.
        // The handler model below requires request-tainted object selection,
        // exposure or mutation, and no ownership/authorization guard.
        r"\x00",
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs", "kt"],
        "Always verify that the authenticated user has permission to access the requested resource."
    );

    add_vuln!(
        "Missing Privileged Route Authorization",
        "A route for an administrator-only operation accepts logged-in users without its available admin gate.",
        Severity::High, Confidence::High, Some(OwaspCategory::A01BrokenAccessControl),
        r"\x00",
        &["js", "ts"],
        "Apply the available administrator middleware to this privileged route before the handler."
    );

    add_vuln!(
        "Unescaped Template Output (XSS)",
        "A stored profile field is interpolated into an HTML template while the configured template engine disables escaping.",
        Severity::High, Confidence::High, Some(OwaspCategory::A03Injection),
        r"\x00", &["html"],
        "Enable template autoescaping and use context-appropriate HTML/attribute encoding for user data."
    );

    add_vuln!(
        "Unsafe HTML Response (XSS)",
        "An outbound response body reaches an HTML response without HTML escaping.",
        Severity::High,
        Confidence::High,
        Some(OwaspCategory::A03Injection),
        r"\x00",
        &["js", "ts", "go"],
        "Encode untrusted response data for HTML output or serve it as plain text."
    );

    add_vuln!(
        "File Inclusion",
        "A request-selected path reaches a PHP include without a fixed allowlist.",
        Severity::Critical,
        Confidence::High,
        Some(OwaspCategory::A03Injection),
        r"\x00",
        &["php"],
        "Map user choices to fixed local files; never include a request-derived path."
    );
    add_vuln!(
        "Single-Pass Path Traversal Filter",
        "A path traversal strip runs once over a request-selected include target, so doubled sequences such as ..././ collapse back into a traversal payload after filtering.",
        Severity::High, Confidence::High, Some(OwaspCategory::A01BrokenAccessControl),
        r"\x00", &["php"],
        "Apply the filter until the value stops changing, or replace filtering with a fixed allowlist of includable files."
    );
    add_vuln!(
        "Unrestricted File Upload",
        "A user-named upload is moved into a web-accessible directory without server-side content validation.",
        Severity::High, Confidence::High, Some(OwaspCategory::A04InsecureDesign),
        r"\x00", &["php"],
        "Validate file contents, generate server-side names, and store uploads outside the web root."
    );
    add_vuln!(
        "Reflected XSS",
        "Request input is appended to an HTML response without HTML encoding.",
        Severity::High,
        Confidence::High,
        Some(OwaspCategory::A03Injection),
        r"\x00",
        &["php"],
        "HTML-encode untrusted output in its rendering context."
    );
    add_vuln!(
        "Stored XSS",
        "A stored guestbook value reaches HTML without output encoding.",
        Severity::High,
        Confidence::High,
        Some(OwaspCategory::A03Injection),
        r"\x00",
        &["php"],
        "Encode database values for HTML at output."
    );
    add_vuln!(
        "Unescaped Rails Output (XSS)",
        "A user-editable profile field is marked html_safe in an ERB view.",
        Severity::High,
        Confidence::High,
        Some(OwaspCategory::A03Injection),
        r"\x00",
        &["erb"],
        "Let ERB escape user values and remove html_safe from profile data."
    );

    add_vuln!(
        "Unescaped Django Output (XSS)",
        "A template value is rendered through the safe filter, disabling Django's autoescaping for user-influenced data.",
        Severity::High, Confidence::High, Some(OwaspCategory::A03Injection),
        r"\x00", &["html"],
        "Let Django autoescape template values and remove the safe filter from user-influenced data."
    );

    add_vuln!(
        "XPath Injection",
        "Request data is concatenated into an XPath expression passed to an XML query engine.",
        Severity::High, Confidence::High, Some(OwaspCategory::A03Injection),
        r"\x00", &["go"],
        "Use fixed XPath expressions and compare values outside the query, or validate against a strict allowlist."
    );

    add_vuln!(
        "Email Header Injection",
        "Request data is concatenated into raw SMTP headers without CR/LF filtering.",
        Severity::High,
        Confidence::High,
        Some(OwaspCategory::A03Injection),
        r"\x00",
        &["go"],
        "Reject CR and LF in mail header fields and use structured header APIs."
    );

    add_vuln!(
        "JWT Algorithm Not Pinned",
        "JWT parsing does not restrict the accepted signing algorithm, so a forged alg=none or algorithm-confusion token verifies.",
        Severity::High, Confidence::High, Some(OwaspCategory::A07AuthFailures),
        r"\x00", &["go"],
        "Pin the expected signing method in the key function, for example token.Method.(*jwt.SigningMethodHMAC), or pass jwt.WithValidMethods."
    );

    add_vuln!(
        "JWT Signature Verification Disabled",
        "JWT decoding skips signature verification, so any forged token is accepted as authentic.",
        Severity::High,
        Confidence::High,
        Some(OwaspCategory::A07AuthFailures),
        r"\x00",
        &["py"],
        "Keep JWT signature verification enabled and pin the expected algorithm."
    );

    add_vuln!(
        "Missing CSRF Protection",
        "A cookie-session application exposes a state-changing route without active CSRF request verification.",
        Severity::High, Confidence::Medium, Some(OwaspCategory::A01BrokenAccessControl),
        r"\x00", &["js", "ts"],
        "Install and apply CSRF protection before state-changing routes and issue valid tokens in forms."
    );

    add_vuln!(
        "Login Username Enumeration",
        "The login handler renders distinct public errors for an unknown username and a wrong password, disclosing whether the account exists.",
        Severity::Medium, Confidence::High, Some(OwaspCategory::A07AuthFailures),
        r"\x00", &["js", "ts"],
        "Return the same public error for unknown usernames and incorrect passwords."
    );

    add_vuln!(
        "Session Fixation on Login",
        "Successful login assigns an authenticated user to a pre-existing cookie session without regenerating its identifier.",
        Severity::High, Confidence::High, Some(OwaspCategory::A07AuthFailures),
        r"\x00", &["js", "ts"],
        "Regenerate the session ID after credential validation and before assigning authenticated state."
    );

    add_vuln!(
        "Insecure Deserialization",
        "Deserializing untrusted data can lead to remote code execution.",
        Severity::Critical, Confidence::Medium, Some(OwaspCategory::A08IntegrityFailures),
        // `yaml.load\b` already excludes `yaml.load_safe` (no word boundary
        // before `_`), so no look-around is needed here. `from_string` was
        // dropped: its hits are template compilation and config parsing
        // (documented design), never deserialization.
        r#"(?i)(?:pickle\.loads?\b|marshal\.load|yaml\.load\b|\bunserialize\s*\()"#,
        // Safe loader spellings and PHP class allowlists are the mitigations
        // this rule asks for, not the vulnerability.
        Some(r#"(?i)SafeLoader|safe_load|SafeYAML|allowed_classes"#),
        &["py", "rb", "php"],
        "Avoid deserializing untrusted data. If necessary, use safe deserialization and validate the result against a schema."
    );

    add_vuln!(
        "Sensitive Data in Logging",
        "Logging potentially sensitive data (passwords, tokens, PII) can lead to data exposure.",
        Severity::Medium, Confidence::Low, Some(OwaspCategory::A09LoggingFailures),
        r#"(?i)(?:log\.(?:info|debug|warn|error)|console\.log|log\.(?:Printf|Println|Print|Fatalf|Fatal|Panicf))\s*\([^)]*(?:password|token|secret|credit|ssn)\b[^)]*\)"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs"],
        "Sanitize logs to remove sensitive data. Use structured logging with sensitive field redaction."
    );

    add_vuln!(
        "Mass Assignment / Autobinding",
        "Automatic binding of request parameters to model attributes can allow property tampering.",
        Severity::High,
        Confidence::Medium,
        Some(OwaspCategory::A01BrokenAccessControl),
        // `mass_assignment` as a standalone word only: protection APIs such
        // as sanitize_for_mass_assignment and
        // value_constructed_by_mass_assignment? carry it as a suffix.
        r#"(?i)(?:update_attributes|(?:^|[^A-Za-z0-9_])mass_assignment\b|fillable\s*=\s*\[\s*\*\s*\]|guard\s*=\s*\[\s*\]|@ModelAttribute)"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs"],
        "Use allowlists (fillable/guarded) to restrict which attributes can be mass-assigned."
    );

    add_vuln!(
        "Disabled SSL/TLS Verification",
        "Disabling SSL certificate verification defeats HTTPS protection and enables MITM attacks.",
        Severity::Critical,
        Confidence::High,
        Some(OwaspCategory::A02CryptographicFailures),
        r#"(?i)(?:verify\s*(?:=>|=)\s*false\b|tls_verify\s*[=:]\s*false|dangerous_accept|no_verify)"#,
        &["rs", "py", "js", "ts", "java", "rb", "go", "php", "cs"],
        "Enable SSL/TLS certificate verification. Never disable it in production."
    );

    patterns
}

/// Detect the language for a file based on extension
fn file_extension(path: &Path) -> String {
    path.extension()
        .map(|e| e.to_str().unwrap_or("").to_lowercase())
        .unwrap_or_default()
}

/// Check if a file extension matches the target list
fn matches_extensions(ext: &str, targets: &[&str]) -> bool {
    targets.is_empty() || targets.contains(&ext)
}

/// Parse severity filter string from CLI
pub fn parse_severity_filter(s: &str) -> Option<Severity> {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Some(Severity::Critical),
        "HIGH" => Some(Severity::High),
        "MEDIUM" => Some(Severity::Medium),
        "LOW" => Some(Severity::Low),
        _ => None,
    }
}

/// Parse confidence filter string from CLI
pub fn parse_confidence_filter(s: &str) -> Option<Confidence> {
    match s.to_uppercase().as_str() {
        "HIGH" => Some(Confidence::High),
        "MEDIUM" => Some(Confidence::Medium),
        "LOW" => Some(Confidence::Low),
        _ => None,
    }
}

/// Check if a finding meets the minimum severity threshold
fn meets_severity_threshold(finding: &Finding, min_severity: Option<Severity>) -> bool {
    match min_severity {
        Some(threshold) => finding.severity.score() >= threshold.score(),
        None => true,
    }
}

/// Check if a finding meets the minimum confidence threshold
fn meets_confidence_threshold(finding: &Finding, min_confidence: Option<Confidence>) -> bool {
    match min_confidence {
        Some(threshold) => finding.confidence.score() >= threshold.score(),
        None => true,
    }
}

/// Filter findings by severity and confidence thresholds
pub(crate) fn filter_findings(
    findings: Vec<Finding>,
    min_severity: Option<Severity>,
    min_confidence: Option<Confidence>,
    max_findings: usize,
) -> Vec<Finding> {
    let mut filtered: Vec<Finding> = findings
        .into_iter()
        .filter(|f| meets_severity_threshold(f, min_severity))
        .filter(|f| meets_confidence_threshold(f, min_confidence))
        .collect();

    if filtered.len() > max_findings {
        filtered.truncate(max_findings);
    }

    filtered
}

/// Return true when a generic `secret` binding is used as JWT signing material.
///
/// The generic credential rule still owns unrelated `secret = "..."` bindings.
/// This narrow context check only promotes a binding when the same identifier is
/// interpolated on a non-comment line that also names a JWT or token.
fn is_contextual_jwt_secret(content: &str, assignment_line: &str) -> bool {
    let Ok(binding) = Regex::new(
        r#"(?i)\b(?:const|let|var|static|final)?\s*([a-z_][a-z0-9_]*)\s*[=:]\s*['\"][^'\"]{8,}['\"]"#,
    ) else {
        return false;
    };
    let Some(captures) = binding.captures(assignment_line) else {
        return false;
    };
    let Some(identifier) = captures.get(1).map(|capture| capture.as_str()) else {
        return false;
    };
    if identifier.to_ascii_lowercase().contains("jwt")
        || ["token_secret", "signing_key"].contains(&identifier.to_ascii_lowercase().as_str())
    {
        return true;
    }
    if !matches!(identifier.to_ascii_lowercase().as_str(), "secret" | "key") {
        return false;
    }

    let reference = Regex::new(&format!(r"(?i)\b{}\b", regex::escape(identifier))).ok();
    content.lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with("//")
            && !trimmed.starts_with('#')
            && (line.to_ascii_lowercase().contains("jwt")
                || line.to_ascii_lowercase().contains("token"))
            && reference.as_ref().is_some_and(|re| re.is_match(line))
    })
}
