/// Narrow, active signing-secret forms. Generic literal passwords in test files are
/// intentionally not promoted: this rule requires an authentication key name
/// plus a fallback expression, or a runtime properties key. `properties` is
/// admitted by the review walker below but not by the general code patterns.
fn signing_secret_sink_lines(
    path: &Path,
    content: &str,
    ext: &str,
) -> std::collections::HashSet<usize> {
    let mut lines = std::collections::HashSet::new();
    // The new rule is production-facing. Test/fixture credentials are not
    // signing keys for the deployed app, even when they use the same syntax.
    if path.components().any(|part| {
        matches!(
            part.as_os_str()
                .to_string_lossy()
                .to_ascii_lowercase()
                .as_str(),
            "test" | "tests" | "__tests__" | "fixtures" | "fixture" | "spec" | "specs"
        )
    }) || path.file_name().is_some_and(|name| {
        let name = name.to_string_lossy().to_ascii_lowercase();
        name.starts_with("test_")
            || name.contains("_test.")
            || name.contains(".test.")
            || name.contains(".spec.")
    }) {
        return lines;
    }
    let js_fallback = Regex::new(
        r#"(?i)(?:\bsecret\s*:\s*|\bjwt\s*\.\s*sign\s*\(.*|\b(?:jwt_secret|session_secret|cookie_secret|signing_key)\s*[=:].*)?(?:process\s*\.\s*env\s*\.\s*(?:jwt_secret|session_secret|cookie_secret|signing_key)|process\s*\.\s*env\s*\[\s*['\"](?:jwt_secret|session_secret|cookie_secret|signing_key)['\"]\s*\])\s*\|\|\s*['\"][^'\"]{4,}['\"]"#
    ).expect("JS signing secret fallback regex");
    let py_fallback = Regex::new(
        r#"(?i)\b(?:SECRET_KEY|JWT_SECRET_KEY|JWT_SECRET|SESSION_SECRET|SIGNING_KEY)\s*=\s*os\s*\.\s*(?:environ\s*\.\s*get|getenv)\s*\(\s*['\"][^'\"]+['\"]\s*,\s*['\"][^'\"]{4,}['\"]\s*\)"#
    ).expect("Python signing secret fallback regex");
    let properties_key = Regex::new(
        r#"(?i)^\s*(?:jwt[._-]secret|jwt[._-]key|session[._-]secret|cookie[._-]secret|signing[._-]key)\s*[=:]\s*([^\s#]+)"#
    ).expect("properties signing secret regex");
    // Go: a var/const whose name marks signing material holds a fixed string
    // or []byte literal, and the same file passes that identifier to
    // SignedString. Environment-derived values do not match the literal.
    if ext == "go" {
        let decl = Regex::new(
            r#"(?i)^\s*(?:var|const)\s+([A-Za-z_]\w*(?:secret|signing)\w*)\s*=\s*(?:\[\]byte\s*\(\s*)?["'][^"']{4,}["']\s*\)?"#
        )
        .expect("Go signing secret declaration regex");
        for (index, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
                continue;
            }
            let Some(caps) = decl.captures(line) else {
                continue;
            };
            let identifier = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let usage = format!(".SignedString({identifier})");
            if content.contains(&usage) {
                lines.insert(index + 1);
            }
        }
        return lines;
    }
    for (index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
        {
            continue;
        }
        let found = match ext {
            "js" | "jsx" | "ts" | "tsx" => {
                js_fallback.is_match(line)
                    && (line.contains("secret")
                        || line.contains("SECRET")
                        || line.contains("sign")
                        || line.contains("SIGN"))
            }
            "py" => py_fallback.is_match(line),
            "properties" => properties_key.captures(line).is_some_and(|caps| {
                let value = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                value.len() >= 8 && !value.starts_with("${") && !value.starts_with("#{")
            }),
            _ => false,
        };
        if found {
            lines.insert(index + 1);
        }
    }
    lines
}

/// Scan a single file for vulnerability patterns
#[cfg(test)]
fn scan_file_for_vulns(path: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    scan_file_for_vulns_with(path, patterns, None, None)
}

/// Path-based context rules (test directories, trusted-store names) must
/// look only at the part of the path below the scan root. The directories
/// above the root are where the user happened to check the project out and
/// say nothing about the project (a checkout under `.../cache/` or
/// `.../tests/` must not change which rules fire).
fn below_scan_root<'a>(path: &'a Path, root: Option<&Path>) -> &'a Path {
    root.and_then(|root| path.strip_prefix(root).ok())
        .unwrap_or(path)
}

/// Build the finding one pattern produces for a matched line.
fn pattern_finding(pattern: &VulnPattern, path: &Path, line_number: usize, line: &str) -> Finding {
    let exploitability = match pattern.severity {
        Severity::Critical => 0.8,
        Severity::High => 0.6,
        Severity::Medium => 0.4,
        Severity::Low => 0.2,
        Severity::Info => 0.1,
    };

    let effort = match pattern.severity {
        Severity::Critical => RemediationEffort::Hours,
        Severity::High => RemediationEffort::Hours,
        Severity::Medium => RemediationEffort::Minutes,
        Severity::Low => RemediationEffort::Minutes,
        Severity::Info => RemediationEffort::Minutes,
    };

    let mut finding = Finding::new(
        FindingType::Vulnerability,
        pattern.name,
        pattern.description,
        pattern.severity,
        pattern.confidence,
        "security-review",
    )
    .at(path.to_string_lossy().to_string(), line_number)
    .with_code(line.to_string())
    .with_remediation(pattern.remediation)
    .with_exploitability(exploitability)
    .with_effort(effort);

    if let Some(owasp) = pattern.owasp {
        finding = finding.with_owasp(owasp);
    }

    // Attach a stable CWE identifier derived from the pattern title
    if let Some(cwe) = crate::finding::cwe_for_title(pattern.name, FindingType::Vulnerability) {
        finding = finding.with_cwe(cwe);
    }

    finding
}

/// SQL strings with a variable password column are query construction, not a
/// literal password. Keep actual `password = 'fixed value'` assignments visible.
/// Reading the debug setting from configuration - Laravel's
/// config('app.debug') or ->get('app.debug') - inspects the flag; it does
/// not enable it. Only assignments (= true) are findings.
fn debug_flag_is_config_read(line: &str) -> bool {
    line.contains("config('app.debug")
        || line.contains("config(\"app.debug")
        || line.contains("->get('app.debug")
        || line.contains("->get(\"app.debug")
}

/// "DEBUG=True" inside a quoted sentence (a help or error message telling
/// users to enable debug for more detail) is prose, not a flag assignment.
/// Suppress only when at least one character sits between the opening quote
/// and the flag; a value that starts with DEBUG=True still fires.
fn debug_flag_in_prose(line: &str) -> bool {
    for (pos, _) in line.match_indices("DEBUG=True") {
        let before = &line[..pos];
        if let Some(q) = before.rfind(['\'', '"']) {
            if !before[q + 1..].is_empty() {
                return true;
            }
        }
    }
    false
}

/// An Algolia DocSearch client configuration keeps app_id, api_key and the
/// search index together; that api_key is a public search-only key shipped
/// to browsers by design, not a secret.
fn is_algolia_docsearch_client_key(line: &str, content: &str) -> bool {
    if !line.contains("api_key") {
        return false;
    }
    // The key must sit inside the DocSearch client config object: app_id
    // and the search index within a few lines of it.
    let lines: Vec<&str> = content.lines().collect();
    for (i, l) in lines.iter().enumerate() {
        if l.trim() == line {
            let lo = i.saturating_sub(6);
            let hi = (i + 7).min(lines.len());
            let window = lines[lo..hi].join("\n");
            return window.contains("app_id") && window.contains("index");
        }
    }
    false
}

/// True when the line interpolates values into SQL and every interpolation
/// is a quoting call: `#{quote_table_name(...)}`, `#{quote_column_name(...)}`
/// or `#{quote(...)}` (Rails ActiveRecord). Any other interpolation - or no
/// interpolation at all - returns false.
fn sql_interpolations_all_quoted(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut found = false;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if (bytes[i] == b'#' || bytes[i] == b'$') && bytes[i + 1] == b'{' {
            found = true;
            let inner = line[i + 2..].trim_start();
            if !(inner.starts_with("quote_table_name(")
                || inner.starts_with("quote_column_name(")
                || inner.starts_with("quote("))
            {
                return false;
            }
        }
        i += 1;
    }
    found
}

fn is_sql_interpolation_not_credential(line: &str, ext: &str) -> bool {
    if ext != "php" {
        return false;
    }
    let upper = line.to_ascii_uppercase();
    let sql = (upper.contains("SELECT ") && upper.contains(" FROM "))
        || (upper.contains("UPDATE ") && upper.contains(" SET "))
        || (upper.contains("INSERT ") && upper.contains(" INTO "));
    if !sql {
        return false;
    }
    let lower = line.to_ascii_lowercase();
    ["password", "passwd", "pwd", "secret"].iter().any(|name| {
        ["'$", "\"$"].iter().any(|prefix| {
            lower.contains(&format!("{name} = {prefix}"))
                || lower.contains(&format!("{name}={prefix}"))
        })
    })
}

/// An XML record inside Go's raw sample-data literal is not a configured
/// credential. A Go assignment or a credential in application code still is.
fn is_embedded_sample_credential(line: &str, ext: &str) -> bool {
    ext == "go"
        && line.starts_with("<user ")
        && line.ends_with("/>")
        && line.contains(" password=\"")
}

/// DEBUG = True inside a development/test configuration class is not a
/// production debug flag. Suppress only when the same file also sets
/// DEBUG = False in another class, which shows the file separates
/// production from non-production configuration.
/// Documented-design deserialization: the data being loaded comes from a
/// store the application itself writes (a bidirectional codec), is integrity
/// protected (MAC/HMAC verification in the same file), or lives in a
/// framework trusted-store component (cache, session, queue, credentials,
/// encryption). A controller doing `Marshal.load(params[:user])` has none of
/// these signals and still reports.
fn deserialization_in_trusted_store(content: &str, path: &str) -> bool {
    if content.contains("hash_equals")
        || content.contains("hash_hmac")
        || content.contains("MessageVerifier")
        || content.contains("MessageEncryptor")
        || content.contains("OpenSSL::HMAC")
    {
        return true;
    }
    // `\bserialize` must not match inside `unserialize`: a boundary check
    // keeps read-only files from looking like bidirectional codecs.
    let php_pair = regex::Regex::new(r"\bserialize\s*\(")
        .map(|write| write.is_match(content) && content.contains("unserialize("))
        .unwrap_or(false);
    let pairs: [(&str, &str); 3] = [
        ("Marshal.dump", "Marshal.load"),
        ("pickle.dumps", "pickle.loads"),
        ("YAML.dump", "YAML.load"),
    ];
    if php_pair
        || pairs
            .iter()
            .any(|(write, read)| content.contains(write) && content.contains(read))
    {
        return true;
    }
    let lower = path.to_ascii_lowercase();
    lower.split(['/', '\\', '_', '-', '.']).any(|part| {
        matches!(
            part,
            "cache" | "session" | "queue" | "bus" | "ractor" | "credentials" | "encryption"
        )
    })
}

fn python_debug_in_nonprod_config(content: &str, line_number: usize) -> bool {
    let lines: Vec<&str> = content.lines().collect();
    let Some(index) = line_number.checked_sub(1).filter(|&i| i < lines.len()) else {
        return false;
    };
    let mut nonprod_class = false;
    for line in lines[..=index].iter().rev() {
        if let Some(rest) = line.strip_prefix("class ") {
            let name = rest
                .split(['(', ':'])
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            nonprod_class = name.contains("dev") || name.contains("test");
            break;
        }
        if !line.starts_with([' ', '\t']) && !line.trim().is_empty() {
            break;
        }
    }
    nonprod_class && lines.iter().any(|line| line.trim() == "DEBUG = False")
}

/// An import names an algorithm but does not use it. Report the cipher
/// construction instead, so a single DES site has one location.
fn is_crypto_import_only(line: &str, ext: &str) -> bool {
    ext == "go" && line == ["\"crypto/", "d", "es\""].concat()
}

/// A request value constrained to ASCII digits by a guard on the exact same
/// request expression cannot break out of a SQL string literal. The guard
/// must appear earlier in the same file and reference the same expression.
fn php_digits_guarded_request_source(
    lines: &[&str],
    assign_index: usize,
    source_expr: &str,
) -> bool {
    let compact_expr: String = source_expr.chars().filter(|c| !c.is_whitespace()).collect();
    lines[..assign_index].iter().any(|line| {
        let text = line.trim();
        if !text.contains("preg_match(") {
            return false;
        }
        if !text.contains(r"'/^\d+$/'") && !text.contains(r#""/^\d+$/""#) {
            return false;
        }
        let compact_line: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        compact_line.contains(&compact_expr)
    })
}

/// Narrow PHP/Ruby request-to-query and shell paths. Report the SQL string
/// construction (rather than the later query call) when that is the reviewed
/// location. Bind parameters and numeric coercions are not string composition.
fn ruby_php_injection_lines(
    content: &str,
    ext: &str,
) -> (
    std::collections::HashSet<usize>,
    std::collections::HashSet<usize>,
) {
    use std::collections::HashSet;
    let mut sql = HashSet::new();
    let mut command = HashSet::new();
    let lines: Vec<&str> = content.lines().collect();
    if ext == "rb" {
        for (index, line) in lines.iter().enumerate() {
            let text = line.trim();
            if text.starts_with('#') {
                continue;
            }
            if text.contains(".where(") && text.contains("#{params[") && text.contains('"') {
                sql.insert(index + 1);
            }
            // Uploaded filenames are controlled by the caller; interpolating
            // one into the shell-form system call executes shell metacharacters.
            if text.contains("system(\"")
                && text.contains("#{")
                && text.contains("file.original_filename")
            {
                command.insert(index + 1);
            }
        }
    } else if ext == "php" {
        let source = Regex::new(r"(?i)^\s*(\$[A-Za-z_][A-Za-z_0-9]*)\s*=\s*(?:trim\s*\(\s*)?\$_(?:GET|POST|REQUEST)\s*\[").expect("PHP request source regex");
        let assign =
            Regex::new(r"(?i)^\s*(\$[A-Za-z_][A-Za-z_0-9]*)\s*=").expect("PHP assignment regex");
        let query = Regex::new(r"(?i)\b(?:SELECT|INSERT|UPDATE|DELETE)\b").expect("SQL verb regex");
        let interpolate = Regex::new(r"\$[A-Za-z_][A-Za-z_0-9]*").expect("PHP interpolation regex");
        let request_expr = Regex::new(r"\$_(?:GET|POST|REQUEST)\s*\[[^\]]+\]")
            .expect("PHP request expression regex");
        let mut tainted = HashSet::<String>::new();
        // Escaping neutralizes a value only inside a quoted SQL string
        // context; track escaped variables separately so an unquoted
        // (numeric-context) interpolation still reports.
        let mut escaped_only = HashSet::<String>::new();
        let has_query_sink = lines
            .iter()
            .any(|line| line.contains("mysqli_query(") || line.contains("->query("));
        for (index, line) in lines.iter().enumerate() {
            let text = line.trim();
            if text.starts_with("//") || text.starts_with('#') {
                continue;
            }
            if let Some(capture) = source.captures(text) {
                // A digits-only preg_match guard on the exact same request
                // expression constrains the value to [0-9]+ before the
                // assignment, so it cannot break out of a SQL string.
                let guarded = request_expr.find(text).is_some_and(|hit| {
                    php_digits_guarded_request_source(&lines, index, hit.as_str())
                });
                if !guarded {
                    tainted.insert(capture[1].to_string());
                }
                escaped_only.remove(&capture[1]);
                continue;
            }
            if let Some(capture) = assign.captures(text) {
                let variable = capture[1].to_string();
                let numeric = text.contains("intval(")
                    || text.contains("(int)")
                    || text.contains("filter_var(");
                let validated_octets = text.contains("$octet[0]")
                    && text.contains("$octet[3]")
                    && (0..4)
                        .all(|octet| content.contains(&format!("is_numeric( $octet[{octet}] )")))
                    && content.contains("sizeof( $octet ) == 4");
                let escaped = text.contains("mysqli_real_escape_string(");
                let digested = text.contains(&["= m", "d5("].concat())
                    || text.contains(&["= sh", "a1("].concat());
                let pass_through = text.contains("str_replace(")
                    || text.contains("stripslashes(")
                    || text.contains("trim(")
                    || text.contains(&format!("({variable}"))
                    || text.contains(&format!(" {variable} "));
                if escaped && tainted.remove(&variable) {
                    // The value came from a request and passed only through
                    // the escape; it is neutralized solely in quoted context.
                    escaped_only.insert(variable);
                } else if numeric || validated_octets || escaped || digested || !pass_through {
                    tainted.remove(&variable);
                    escaped_only.remove(&variable);
                }
            }
            if !tainted.iter().any(|variable| text.contains(variable))
                && !escaped_only.iter().any(|variable| text.contains(variable))
            {
                continue;
            }
            // An escaped variable inside single quotes stays neutralized; the
            // same variable interpolated without quotes (a numeric context)
            // bypasses the escape, which only encodes string delimiters.
            let unquoted_escape = interpolate.find_iter(text).any(|hit| {
                escaped_only.contains(hit.as_str())
                    && text[..hit.start()]
                        .chars()
                        .next_back()
                        .is_none_or(|prev| prev != '\'')
            });
            if has_query_sink
                && text.contains("$query")
                && query.is_match(text)
                && text.contains('"')
                && !text.contains("->prepare(")
                && (interpolate
                    .find_iter(text)
                    .any(|hit| tainted.contains(hit.as_str()))
                    || unquoted_escape)
            {
                sql.insert(index + 1);
            }
            if text.contains("shell_exec(") && text.contains('.') {
                command.insert(index + 1);
            }
        }
    }
    (sql, command)
}

/// Scan one file, also reporting sink lines that other project files reach
/// through cross-file calls (see [`cross_file_flow_sinks`]).
fn scan_file_for_vulns_with(
    path: &Path,
    patterns: &[VulnPattern],
    cross_file: Option<&CrossFileSinkLines>,
    root: Option<&Path>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let ext = file_extension(path);
    let context_path = below_scan_root(path, root);

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return findings,
    };
    if crate::workflow::is_github_workflow(path, &content) {
        findings.extend(crate::workflow::scan_workflow(path, &content));
    }
    let js_path_traversal_sinks = js_path_traversal_sink_lines(&content, &ext);
    let python_path_traversal_sinks = python_path_traversal_sink_lines(&content, &ext);
    let java_path_traversal_sinks = java_path_traversal_sink_lines(&content, &ext);
    let mut go_path_traversal_sinks = go_path_traversal_sink_lines(&content, &ext);
    go_path_traversal_sinks.extend(go_archive_entry_join_lines(&content, &ext));
    let python_md5_alias_calls = python_md5_alias_call_lines(&content, &ext);
    let python_docstring_lines = python_docstring_line_numbers(&content, &ext);
    let wrapped_constant_calls = wrapped_constant_execute_sql_lines(&content);
    let template_engine_debug = django_template_engine_call_lines(&content, &ext);
    let mut sql_injection_sinks = sql_injection_sink_lines(&content, &ext);
    let mut command_injection_sinks = command_injection_sink_lines(&content, &ext);
    let (language_sql, language_command) = if context_path.components().any(|part| {
        matches!(
            part.as_os_str().to_str(),
            Some("test" | "tests" | "spec" | "specs" | "fixtures")
        )
    }) {
        (
            std::collections::HashSet::new(),
            std::collections::HashSet::new(),
        )
    } else {
        let (sql, mut command) = ruby_php_injection_lines(&content, &ext);
        command.extend(ruby_parameter_open_lines(&content, &ext));
        command.extend(ruby_parameter_shell_lines(&content, &ext));
        command.extend(python_git_option_injection_lines(&content, &ext));
        let mut sql = sql;
        sql.extend(java_sql_append_lines(&content, &ext));
        (sql, command)
    };
    sql_injection_sinks.extend(language_sql);
    command_injection_sinks.extend(language_command);
    let mut ssrf_sinks = ssrf_sink_lines(&content, &ext);
    let (php_upload_sinks, php_reflected_sinks, ruby_file_sinks) =
        php_ruby_file_xss_lines(&content, &ext);
    let go_xss_sinks = go_html_xss_lines(&content, &ext);
    let go_xpath_sinks = go_xpath_sink_lines(&content, &ext);
    let go_email_sinks = go_email_header_sink_lines(&content, &ext);
    let go_jwt_unpinned = go_jwt_unpinned_parse_lines(&content, &ext);
    let go_template_sinks = go_template_source_sink_lines(&content, &ext);
    let (password_hash_sinks, token_sinks, rsa_sinks, tls_sinks, cookie_sinks) =
        pilot_crypto_cookie_lines(&content, &ext);
    let (django_password_sinks, django_cookie_session_sinks, django_pickle_sinks) =
        django_settings_sink_lines(&content, &ext);
    let django_csrf_exempt_sinks = django_csrf_exempt_lines(&content, &ext);
    let django_idor_sinks = django_idor_sink_lines(&content, &ext);
    let django_modelform_sinks = django_modelform_exclude_lines(&content, &ext);
    let django_role_check_sinks = django_missing_role_check_lines(&content, &ext);
    let rails_assignment_sinks = rails_assignment_sink_lines(&content, &ext);
    let redirect_sinks = open_redirect_sink_lines(&content, &ext);
    let redos_sites = redos_sink_lines(&content, &ext);
    let (plaintext_stores, plaintext_compares) = plaintext_password_lines(&content, &ext);
    if let Some(cross_file) = cross_file {
        sql_injection_sinks.extend(cross_file.sql.iter().copied());
        command_injection_sinks.extend(cross_file.command.iter().copied());
        ssrf_sinks.extend(cross_file.ssrf.iter().copied());
    }
    let signing_secret_sites = signing_secret_sink_lines(context_path, &content, &ext);
    let ssti_sinks = ssti_sink_lines(&content, &ext);
    let idor_sinks = idor_sink_lines(&content, &ext);
    let mut code_injection_sinks = code_injection_sink_lines(&content, &ext);
    if let Some(cross_file) = cross_file {
        code_injection_sinks.extend(cross_file.code.iter().copied());
    }

    for (line_num, line) in content.lines().enumerate() {
        let line_number = line_num + 1;
        let trimmed = line.trim();

        // Skip comments
        if trimmed.is_empty()
            || trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
        {
            continue;
        }

        if signing_secret_sites.contains(&line_number) {
            let mut finding = Finding::new(
                FindingType::Vulnerability,
                "JWT Secret Hardcoded",
                "A JWT or session signing secret has a fixed source-code value or a known fallback. Tokens or cookies can be forged when this value is used.",
                Severity::Critical,
                Confidence::High,
                "security-review",
            )
            .at(path.to_string_lossy().to_string(), line_number)
            .with_code(line.to_string())
            .with_remediation("Require a deployment-specific secret from the environment or a secret manager; fail startup if absent, and rotate any exposed key.")
            .with_owasp(OwaspCategory::A07AuthFailures)
            .with_cwe("CWE-798");
            finding.remediation_effort = RemediationEffort::Hours;
            findings.push(finding);
        }

        let contextual_jwt_secret = is_contextual_jwt_secret(&content, line);

        for pattern in patterns {
            if !matches_extensions(&ext, pattern.target_extensions) {
                continue;
            }

            let pattern_matches = pattern.pattern.is_match(line)
                || (pattern.name == "Disabled SSL/TLS Verification"
                    && ext == "go"
                    && trimmed.contains("InsecureSkipVerify: true")
                    && content.contains("&http.Transport{")
                    && content.contains("TLSClientConfig:"))
                || (pattern.name == "JWT Secret Hardcoded" && contextual_jwt_secret)
                || (pattern.name == "Path Traversal"
                    && (js_path_traversal_sinks.contains(&line_number)
                        || python_path_traversal_sinks.contains(&line_number)
                        || java_path_traversal_sinks.contains(&line_number)
                        || go_path_traversal_sinks.contains(&line_number)))
                || (pattern.name == "Weak Hash Algorithm — MD5"
                    && python_md5_alias_calls.contains(&line_number))
                || (pattern.name == "Fast Password Hash (MD5)"
                    && (password_hash_sinks.contains(&line_number)
                        || django_password_sinks.contains(&line_number)))
                || (pattern.name == "Client-Side Session Storage"
                    && django_cookie_session_sinks.contains(&line_number))
                || (pattern.name == "Pickle Session Serializer"
                    && django_pickle_sinks.contains(&line_number))
                || (pattern.name == "CSRF Protection Disabled"
                    && django_csrf_exempt_sinks.contains(&line_number))
                || (pattern.name == "Django ModelForm Mass Assignment"
                    && django_modelform_sinks.contains(&line_number))
                || (pattern.name == "Missing Function Level Access Control"
                    && django_role_check_sinks.contains(&line_number))
                || (pattern.name == "Predictable Session Token"
                    && token_sinks.contains(&line_number))
                || (pattern.name == "Weak RSA Key Size" && rsa_sinks.contains(&line_number))
                || (pattern.name == "Deprecated TLS Minimum Version"
                    && tls_sinks.contains(&line_number))
                || (pattern.name == "Insecure Cookie Configuration"
                    && cookie_sinks.contains(&line_number))
                || (pattern.name == "Unsafe Rails Parameter Assignment"
                    && rails_assignment_sinks.contains(&line_number))
                || (pattern.name == "SQL Injection — String Concatenation"
                    && sql_injection_sinks.contains(&line_number))
                || (pattern.name == "Command Injection"
                    && command_injection_sinks.contains(&line_number))
                || (pattern.name == "Server-Side Request Forgery (SSRF)"
                    && ssrf_sinks.contains(&line_number))
                || (pattern.name == "Unsafe HTML Response (XSS)"
                    && go_xss_sinks.contains(&line_number))
                || (pattern.name == "Unrestricted File Upload"
                    && php_upload_sinks.contains(&line_number))
                || (pattern.name == "Reflected XSS" && php_reflected_sinks.contains(&line_number))
                || (pattern.name == "Path Traversal" && ruby_file_sinks.contains(&line_number))
                || (pattern.name == "XPath Injection" && go_xpath_sinks.contains(&line_number))
                || (pattern.name == "Email Header Injection"
                    && go_email_sinks.contains(&line_number))
                || (pattern.name == "JWT Algorithm Not Pinned"
                    && go_jwt_unpinned.contains(&line_number))
                || (pattern.name == "Open Redirect" && redirect_sinks.contains(&line_number))
                || (pattern.name == "Regular Expression Denial of Service (ReDoS)"
                    && redos_sites.contains(&line_number))
                || (pattern.name == "Plaintext Password Storage"
                    && plaintext_stores.contains(&line_number))
                || (pattern.name == "Plaintext Password Comparison"
                    && plaintext_compares.contains(&line_number))
                || (pattern.name == "Code Injection"
                    && code_injection_sinks.contains(&line_number))
                || (pattern.name == "Server-Side Template Injection (SSTI)"
                    && (ssti_sinks.contains(&line_number)
                        || go_template_sinks.contains(&line_number)))
                || (pattern.name == "Insecure Direct Object Reference (IDOR)"
                    && (idor_sinks.contains(&line_number)
                        || django_idor_sinks.contains(&line_number)));
            if !pattern_matches {
                continue;
            }

            // `execute_sql(` at the end of a line with an ALL-CAPS constant as
            // the first argument on the next line is the wrapped form of the
            // framework-internal result call the pattern already skips.
            if pattern.name == "SQL Injection — ORM Raw Queries"
                && wrapped_constant_calls.contains(&line_number)
            {
                continue;
            }

            // Prose inside a bare triple-quoted string (a docstring) that
            // mentions execute_sql() is documentation, not a call.
            if pattern.name == "SQL Injection — ORM Raw Queries"
                && python_docstring_lines.contains(&line_number)
            {
                continue;
            }

            // A credential that is specifically JWT signing material should be
            // reported once under the more precise rule, not again generically.
            if signing_secret_sites.contains(&line_number)
                && (pattern.name == "Hardcoded Credentials"
                    || pattern.name == "JWT Secret Hardcoded")
            {
                continue;
            }
            if pattern.name == "Hardcoded Credentials"
                && (contextual_jwt_secret
                    || is_sql_interpolation_not_credential(trimmed, &ext)
                    || is_embedded_sample_credential(trimmed, &ext))
            {
                continue;
            }

            // `debug=True` as an argument of Django's template `Engine(...)`
            // only adds context to template errors for the engine that
            // renders the debug page; it is not the DEBUG setting.
            if pattern.name == "Debug Mode Enabled" && template_engine_debug.contains(&line_number)
            {
                continue;
            }

            // The Rails asset pipeline's debug flag only expands how assets
            // are served in development; it is not the framework debug mode
            // this rule measures, and it carries no debug-mode exposure.
            if pattern.name == "Debug Mode Enabled" && trimmed.contains("assets.debug") {
                continue;
            }

            // Reading the debug flag from configuration
            // (config('app.debug'), ->get('app.debug')) inspects the
            // setting; it does not enable it. "DEBUG=True" inside a quoted
            // help message is prose, not an assignment.
            if pattern.name == "Debug Mode Enabled"
                && (debug_flag_is_config_read(trimmed) || debug_flag_in_prose(trimmed))
            {
                continue;
            }

            // An Algolia DocSearch client config (app_id + api_key + index
            // in one file) ships its search-only API key to browsers by
            // design; it is not a secret.
            if pattern.name == "Hardcoded Credentials"
                && is_algolia_docsearch_client_key(trimmed, &content)
            {
                continue;
            }

            // Rails-style fully quoted interpolation: every #{...}/${...}
            // in the statement is a quote_table_name/quote_column_name/
            // quote(...) call, so no user-controlled value reaches the SQL.
            if pattern.name == "SQL Injection — String Concatenation"
                && sql_interpolations_all_quoted(trimmed)
            {
                continue;
            }

            // Deserializing a store the application writes itself, a
            // MAC-verified payload, or a framework trusted-store component is
            // documented design, not an untrusted-data boundary.
            if pattern.name == "Insecure Deserialization"
                && deserialization_in_trusted_store(&content, &context_path.to_string_lossy())
            {
                continue;
            }

            // The vendored Google JS API loader ships with the literal
            // placeholder key 'notsupplied'; it is a placeholder string,
            // not a credential.
            if pattern.name == "Hardcoded Credentials"
                && (trimmed.contains("'notsupplied'") || trimmed.contains("\"notsupplied\""))
            {
                continue;
            }
            if pattern.name == ["Weak Encryption — ", "D", "ES"].concat()
                && is_crypto_import_only(trimmed, &ext)
            {
                continue;
            }

            // A zapApiKey value authenticates to a locally running OWASP
            // ZAP daemon driven by the app's own security test suite. It is
            // a development-tool credential in non-production environment
            // config, not an application credential.
            // A logging call whose only argument is a fixed string reports
            // a status; no secret value can reach the log.
            if pattern.name == "Sensitive Data in Logging" && is_literal_only_log_call(trimmed) {
                continue;
            }

            // A value that is itself a command-line flag name ("--password")
            // is an option map entry, not a credential.
            if pattern.name == "Hardcoded Credentials" && credential_value_is_cli_flag(trimmed) {
                continue;
            }

            if pattern.name == "Hardcoded Credentials" && trimmed.contains("zapApiKey") {
                continue;
            }

            // DEBUG = True scoped to a development/test config class in a
            // file that also defines DEBUG = False for production is not a
            // production debug flag.
            if pattern.name == "Debug Mode Enabled"
                && ext == "py"
                && python_debug_in_nonprod_config(&content, line_number)
            {
                continue;
            }

            // A weak-hash call inside a function whose own declaration already
            // reads as a non-security use (a hash wrapper, mutex or cache-key
            // name) is the same non-security context as the line-level cues,
            // seen from the enclosing function.
            if pattern.name.starts_with("Weak Hash Algorithm")
                && pattern.negative.as_ref().is_some_and(|neg| {
                    weak_hash_in_non_security_function(&content, line_number, neg)
                })
            {
                continue;
            }

            // Suppress matches that also hit the negative filter, e.g. a
            // cookie call that already sets HttpOnly/Secure/SameSite.
            if pattern
                .negative
                .as_ref()
                .is_some_and(|neg| neg.is_match(line))
            {
                continue;
            }

            let mut finding = pattern_finding(pattern, path, line_number, line);
            retitle_mongo_where(&mut finding, &ext);
            findings.push(finding);
        }
    }

    findings
}

/// True when the nearest enclosing function declaration above `line_number`
/// matches the weak-hash non-security cues (its name is a hash wrapper, mutex,
/// cache key, checksum and so on) and carries no security-named identifier.
/// Only a declaration indented less than the hash call counts, and only within
/// a short window, so unrelated functions never apply.
fn weak_hash_in_non_security_function(content: &str, line_number: usize, negative: &Regex) -> bool {
    static FN_DECL: std::sync::LazyLock<Option<Regex>> = std::sync::LazyLock::new(|| {
        Regex::new(
            r"^\s*(?:(?:public|private|protected|static|async|export|final|abstract)\s+)*(?:def|function|func|fn)\b",
        )
        .ok()
    });
    static SECURITY_NAME: std::sync::LazyLock<Option<Regex>> = std::sync::LazyLock::new(|| {
        Regex::new(r"(?i)password|passwd|secret|token|auth|sign|hmac|salt|credential|session|csrf|nonce|\bkey\b").ok()
    });
    let (Some(decl), Some(security)) = (FN_DECL.as_ref(), SECURITY_NAME.as_ref()) else {
        return false;
    };
    let lines: Vec<&str> = content.lines().collect();
    let Some(index) = line_number.checked_sub(1).filter(|i| *i < lines.len()) else {
        return false;
    };
    let indent = |text: &str| text.len() - text.trim_start().len();
    let call_indent = indent(lines[index]);
    for candidate in (index.saturating_sub(80)..index).rev() {
        let text = lines[candidate];
        if decl.is_match(text) && indent(text) < call_indent {
            return negative.is_match(text) && !security.is_match(text);
        }
    }
    false
}

