/// A log statement whose single argument is a quoted string with no
/// interpolation, concatenation or format arguments, such as
/// `console.log(`[TOKEN OK]`);`. Calls with a second argument, `+`, `${`,
/// `#{` or `{}` placeholders still count as logging a value.
fn is_literal_only_log_call(line: &str) -> bool {
    static LITERAL_LOG: std::sync::LazyLock<Option<Regex>> = std::sync::LazyLock::new(|| {
        Regex::new(
            r#"(?i)^(?:log\.(?:info|debug|warn|error|Printf|Println|Print|Fatalf|Fatal|Panicf)|console\.log)\s*\(\s*(?:'[^'\\$#{}%]*'|"[^"\\$#{}%]*"|`[^`\\$#{}%]*`)\s*\)\s*;?\s*$"#,
        )
        .ok()
    });
    LITERAL_LOG
        .as_ref()
        .is_some_and(|re| re.is_match(line.trim()))
}

/// `password: "--password"` style entries: the quoted value is a lowercase
/// long-option name (letters and dashes only), not a secret.
fn credential_value_is_cli_flag(line: &str) -> bool {
    static CLI_FLAG: std::sync::LazyLock<Option<Regex>> = std::sync::LazyLock::new(|| {
        Regex::new(
            r#"(?i)\b(?:password|passwd|pwd|secret|token|api_?key)\w*["']?\s*(?::|=>|=)\s*["']--[a-z]+(?:-[a-z]+)*["']\s*,?\s*$"#,
        )
        .ok()
    });
    CLI_FLAG.as_ref().is_some_and(|re| re.is_match(line.trim()))
}

/// Title of a JS/TS MongoDB `$where` injection. The sink is JavaScript run by
/// the database, not SQL, so it is reported as NoSQL injection (CWE-943).
const NOSQL_WHERE_TITLE: &str = "NoSQL Injection — $where Operator";

/// The flow engine treats a request value reaching a MongoDB `$where`
/// expression as an injection sink and reports it through the SQL pattern.
/// Correct the class on that one shape: a JS/TS line containing `$where`.
fn retitle_mongo_where(finding: &mut Finding, ext: &str) {
    if finding.title != "SQL Injection — String Concatenation"
        || !matches!(ext, "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs")
        || !finding
            .code_snippet
            .as_deref()
            .is_some_and(|code| code.contains("$where"))
    {
        return;
    }
    finding.title = NOSQL_WHERE_TITLE.to_string();
    finding.description = "A request-controlled value reaches a MongoDB $where expression, which the database evaluates as JavaScript. Use structured query operators instead of $where, or validate and cast the value first.".to_string();
    finding.remediation = Some("Replace $where with structured query operators ($gt, $eq, ...) and cast request values to their expected type before they reach the query.".to_string());
    finding.cwe_id = Some("CWE-943".to_string());
}

/// Emit only cross-file flow findings for a file outside the scanned set (a
/// package entry resolved through `node_modules`). Pattern rules stay off:
/// package code is reported only when project request input provably reaches
/// one of its sinks.
fn scan_file_flow_only(path: &Path, cross_file: &CrossFileSinkLines) -> Vec<Finding> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let patterns = build_vuln_patterns();
    let mut findings = Vec::new();
    for (name, sinks) in [
        (
            "SQL Injection \u{2014} String Concatenation",
            &cross_file.sql,
        ),
        ("Command Injection", &cross_file.command),
        ("Server-Side Request Forgery (SSRF)", &cross_file.ssrf),
    ] {
        let Some(pattern) = patterns.iter().find(|p| p.name == name) else {
            continue;
        };
        for &line_number in sinks {
            let Some(line) = line_number
                .checked_sub(1)
                .and_then(|index| lines.get(index))
            else {
                continue;
            };
            findings.push(pattern_finding(pattern, path, line_number, line));
        }
    }
    findings
}

/// Whether a source path is explicitly test, fixture, example, or sample code.
/// Classify relative to the project root so a parent named `tests` or an
/// example-repo checkout name cannot relabel production files. Match whole
/// components and common test filename conventions, not substrings such as
/// `contest` or `specification`.
fn is_test_context_path(path: &Path, root: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    let directories: Vec<String> = relative
        .parent()
        .into_iter()
        .flat_map(Path::components)
        .map(|part| part.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect();
    if directories.iter().any(|part| {
        matches!(
            part.as_str(),
            "test"
                | "tests"
                | "__tests__"
                | "spec"
                | "specs"
                | "fixture"
                | "fixtures"
                | "testdata"
                | "test-data"
                | "example"
                | "examples"
                | "sample"
                | "samples"
                | "benchmark"
                | "benchmarks"
                | "step_definitions"
        ) || part.ends_with("-tests")
            || part.ends_with("_tests")
            || part.ends_with("-test")
            || part.ends_with("_test")
    }) {
        return true;
    }
    let Some(name) = relative
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
    else {
        return false;
    };
    let stem = name.split('.').next().unwrap_or("");
    let java_test = (name.ends_with("test.java") || name.ends_with("tests.java")) && stem != "test";
    java_test
        || name.starts_with("test_")
        || name.starts_with("spec_")
        || name.starts_with("fixture_")
        || name.starts_with("example_")
        || name.starts_with("sample_")
        || name.contains("_test.")
        || name.contains("_spec.")
        || name.contains(".test.")
        || name.contains(".spec.")
        || name.contains(".fixture.")
        || name.contains(".example.")
        || name.contains(".sample.")
}

/// Conventional seed files may run in production; keep the finding but mark its
/// deployment-dependent risk. Development-only settings are not production
/// debug flags. These are relative paths, not checkout-name heuristics.
fn contextual_deployment_path(path: &Path, root: &Path) -> Option<&'static str> {
    let relative = path.strip_prefix(root).ok()?;
    let parts: Vec<String> = relative
        .components()
        .map(|part| part.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect();
    if parts.as_slice() == ["db", "seeds.rb"] {
        Some("Seed data context: ")
    } else if parts.as_slice() == ["config", "environments", "development.rb"] {
        Some("Development-only setting: ")
    } else {
        None
    }
}

fn mark_deployment_context(findings: &mut [Finding], root: &Path) {
    for finding in findings {
        let Some(path) = finding.file_path.as_deref() else {
            continue;
        };
        let Some(context) = contextual_deployment_path(Path::new(path), root) else {
            continue;
        };
        let applicable = match context {
            "Seed data context: " => finding.title == "Hardcoded Credentials",
            _ => finding.title == "Debug Mode Enabled",
        };
        if !applicable {
            continue;
        }
        let ceiling = if context == "Seed data context: " {
            Severity::Medium
        } else {
            Severity::Low
        };
        if finding.severity.score() > ceiling.score() {
            finding.severity = ceiling;
        }
        if !finding.description.starts_with(context) {
            finding.description = format!("{context}{}", finding.description);
        }
    }
}

/// Keep findings visible but lower the production risk of test-only code.
/// Detection confidence remains intact: a credential can truly be hardcoded
/// in a fixture while being low severity for a deployed application.
fn downgrade_test_context(findings: &mut [Finding], root: &Path) {
    for finding in findings {
        let Some(path) = finding.file_path.as_deref() else {
            continue;
        };
        if !is_test_context_path(Path::new(path), root) {
            continue;
        }
        if finding.severity.score() > Severity::Low.score() {
            finding.severity = Severity::Low;
        }
        if !finding.description.starts_with("Test/fixture context: ") {
            finding.description = format!("Test/fixture context: {}", finding.description);
        }
    }
}

/// Link Express route declarations to locally imported handlers before making
/// missing-authorization claims. Only a recognized privileged operation or a
/// request-selected private account exposed without ownership checking qualifies.
fn scoped_route_authz_findings(
    files: &[std::path::PathBuf],
    root: &Path,
    patterns: &[VulnPattern],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(route) = Regex::new(
        r#"\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]\s*,\s*([^;]+)"#,
    ) else {
        return findings;
    };
    let Ok(import) = Regex::new(
        r#"(?m)\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\s*\(\s*['"](\.[^'"]+)['"]\s*\)"#,
    ) else {
        return findings;
    };
    let Ok(instance) = Regex::new(
        r"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*new\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
    ) else {
        return findings;
    };
    let Ok(method) =
        Regex::new(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*([A-Za-z_$][A-Za-z0-9_$]*)\b")
    else {
        return findings;
    };
    let Ok(admin_binding) = Regex::new(
        r"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[^;\n]*\.isAdminUserMiddleware\b",
    ) else {
        return findings;
    };
    let Ok(login_binding) = Regex::new(
        r"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[^;\n]*\.isLoggedInMiddleware\b",
    ) else {
        return findings;
    };
    let Ok(privileged) = Regex::new(
        r"\b(?:getAllNonAdminUsers|updateBenefits|setAdmin|grantRole|deleteAllUsers)\s*\(",
    ) else {
        return findings;
    };
    let Ok(request_param) = Regex::new(
        r"(?s)\b(?:const|let|var)\s*\{\s*userId\s*\}\s*=\s*req\.params\b|\breq\.params\.userId\b",
    ) else {
        return findings;
    };
    let Ok(account_access) = Regex::new(
        r"\b(?:getByUserIdAndThreshold|getByUserId|findByUserId|findById)\s*\(\s*userId\b",
    ) else {
        return findings;
    };
    let Ok(ownership) = Regex::new(
        r"(?i)\b(?:checkOwnership|hasPermission|isOwner|canRead|authorize|userId\s*===?\s*req\.session\.userId|req\.session\.userId\s*===?\s*userId)\b",
    ) else {
        return findings;
    };
    for path in files {
        if !matches!(file_extension(path).as_str(), "js" | "ts") || is_test_context_path(path, root)
        {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        let (Some(admin), Some(login)) = (
            admin_binding
                .captures(&content)
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string())),
            login_binding
                .captures(&content)
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string())),
        ) else {
            continue;
        };
        let imports: std::collections::HashMap<String, String> = import
            .captures_iter(&content)
            .filter_map(|c| {
                Some((
                    c.get(1)?.as_str().to_string(),
                    c.get(2)?.as_str().to_string(),
                ))
            })
            .collect();
        let instances: std::collections::HashMap<String, String> = instance
            .captures_iter(&content)
            .filter_map(|c| {
                Some((
                    c.get(1)?.as_str().to_string(),
                    c.get(2)?.as_str().to_string(),
                ))
            })
            .collect();
        for (index, line) in content.lines().enumerate() {
            let trim = line.trim_start();
            if trim.starts_with("//") || trim.starts_with("/*") || trim.starts_with('*') {
                continue;
            }
            let Some(caps) = route.captures(line) else {
                continue;
            };
            let Some(route_path) = caps.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let Some(args) = caps.get(2).map(|m| m.as_str()) else {
                continue;
            };
            if !identifier_in(args, &login) || identifier_in(args, &admin) {
                continue;
            }
            let Some((receiver, operation)) = method
                .captures_iter(args)
                .last()
                .and_then(|c| Some((c.get(1)?.as_str(), c.get(2)?.as_str())))
            else {
                continue;
            };
            let Some(import_path) = instances.get(receiver).and_then(|class| imports.get(class))
            else {
                continue;
            };
            let Some(parent) = path.parent() else {
                continue;
            };
            let target = parent.join(import_path).with_extension("js");
            let target = std::fs::canonicalize(&target).unwrap_or(target);
            if !target.starts_with(root) || !files.contains(&target) {
                continue;
            }
            let Ok(handler) = std::fs::read_to_string(&target) else {
                continue;
            };
            if route_path.contains("benefit")
                && matches!(operation, "updateBenefits" | "displayBenefits")
                && privileged.is_match(&handler)
            {
                if let Some(pattern) = patterns
                    .iter()
                    .find(|p| p.name == "Missing Privileged Route Authorization")
                {
                    findings.push(pattern_finding(pattern, path, index + 1, line));
                }
            }
            if route_path.contains(":userId")
                && operation == "displayAllocations"
                && request_param.is_match(&handler)
                && account_access.is_match(&handler)
                && handler.contains("res.render(")
                && !ownership.is_match(&handler)
            {
                if let Some(pattern) = patterns
                    .iter()
                    .find(|p| p.name == "Insecure Direct Object Reference (IDOR)")
                {
                    // The request-controlled id is read in this handler, not at
                    // the route declaration. Report the actual source line.
                    if let Some(source_line) = handler.lines().enumerate().find_map(|(i, text)| {
                        (text.trim().starts_with("userId")
                            && handler
                                .lines()
                                .skip(i + 1)
                                .take(3)
                                .any(|next| next.contains("req.params")))
                        .then_some(i + 1)
                    }) {
                        let text = handler.lines().nth(source_line - 1).unwrap_or("");
                        findings.push(pattern_finding(pattern, &target, source_line, text));
                    } else if let Some(source_line) = handler
                        .lines()
                        .enumerate()
                        .find_map(|(i, text)| text.contains("req.params.userId").then_some(i + 1))
                    {
                        let text = handler.lines().nth(source_line - 1).unwrap_or("");
                        findings.push(pattern_finding(pattern, &target, source_line, text));
                    }
                }
            }
        }
    }
    findings
}

/// Match active Rails model writes linked to unchecked or privilege-bearing parameters.
/// Keep the finding on the write, not on the strong-parameter declaration.
fn rails_assignment_sink_lines(content: &str, ext: &str) -> std::collections::HashSet<usize> {
    use std::collections::HashSet;
    let mut sites = HashSet::new();
    if ext != "rb" || !content.contains("< ApplicationController") {
        return sites;
    }
    let lines: Vec<&str> = content.lines().collect();
    let mut method = "";
    let mut method_start = 0;
    let mut unsafe_params = false;
    for (i, line) in lines.iter().enumerate() {
        let code = line.trim();
        if code.starts_with('#') {
            continue;
        }
        if code.starts_with("def ") {
            method = code
                .strip_prefix("def ")
                .unwrap_or("")
                .split(['(', ' '])
                .next()
                .unwrap_or("");
            method_start = i;
            unsafe_params = false;
        }
        if method == "update_user"
            && (code.contains("params[:user].to_unsafe_h")
                || code.contains("user_params ||= params[:user]"))
        {
            unsafe_params = true;
        }
        if method == "update_user"
            && unsafe_params
            && code.contains(".update(filtered_params)")
            && lines[method_start..i]
                .iter()
                .any(|prior| prior.contains("filtered_params = user_params.reject"))
        {
            sites.insert(i + 1);
        }
        if method == "user_params_without_password"
            && code.contains("params.require(:user).permit(:email, :admin,")
            && content.contains(".update(user_params_without_password)")
        {
            sites.insert(i + 1);
        }
        if method == "create"
            && code.contains("User.new(user_params)")
            && content.contains("params.require(:user).permit!")
        {
            sites.insert(i + 1);
        }
    }
    sites
}

/// Django settings misconfigurations: MD5 password hasher, signed-cookie
/// session storage, and the Pickle session serializer. Each is a real
/// configuration value with a documented weakness; detection is by exact
/// settings assignment, so the FP surface is empty.
#[allow(clippy::type_complexity)]
fn django_settings_sink_lines(
    content: &str,
    ext: &str,
) -> (
    std::collections::HashSet<usize>,
    std::collections::HashSet<usize>,
    std::collections::HashSet<usize>,
) {
    use std::collections::HashSet;
    let mut password = HashSet::new();
    let mut cookie_session = HashSet::new();
    let mut pickle = HashSet::new();
    if ext != "py" {
        return (password, cookie_session, pickle);
    }
    for (i, line) in content.lines().enumerate() {
        let code = line.trim();
        if code.starts_with('#') {
            continue;
        }
        if code.contains("PASSWORD_HASHERS") && code.contains("MD5PasswordHasher") {
            password.insert(i + 1);
        }
        if code.contains("SESSION_ENGINE") && code.contains("signed_cookies") {
            cookie_session.insert(i + 1);
        }
        if code.contains("SESSION_SERIALIZER") && code.contains("PickleSerializer") {
            pickle.insert(i + 1);
        }
    }
    (password, cookie_session, pickle)
}

/// Missing function-level access control: a Django view that verifies only
/// `is_authenticated` and then mutates group or permission membership, with
/// no role check (`is_staff`, `is_superuser`, `has_perm`,
/// `permission_required`, `user_passes_test`) anywhere in the view body.
/// Authentication is not authorization; the mutation line is the sink.
#[allow(clippy::items_after_test_module)]
fn django_missing_role_check_lines(content: &str, ext: &str) -> std::collections::HashSet<usize> {
    use std::collections::HashSet;
    let mut sinks = HashSet::new();
    if ext != "py" || !content.contains("is_authenticated") {
        return sinks;
    }
    let Ok(mutation) = Regex::new(
        r"\.(?:groups|user_permissions)\s*\.\s*add\s*\(|\b(?:is_staff|is_superuser)\s*=\s*True",
    ) else {
        return sinks;
    };
    let Ok(role_check) =
        Regex::new(r"is_staff|is_superuser|has_perm|permission_required|user_passes_test")
    else {
        return sinks;
    };
    let lines: Vec<&str> = content.lines().collect();
    for function in flow_functions(&lines, FlowLanguage::Python) {
        let body: Vec<&str> = lines[function.body.clone()].to_vec();
        if !body.join("\n").contains("is_authenticated") {
            continue;
        }
        // A role check guards only what follows it: a check placed after the
        // mutation (django.nV checks GET but not POST) leaves the sink open.
        let mut guarded = false;
        for (offset, line) in body.iter().enumerate() {
            let code = line.split('#').next().unwrap_or("");
            if role_check.is_match(code) {
                guarded = true;
            } else if !guarded && mutation.is_match(code) {
                sinks.insert(function.body.start + offset + 1);
            }
        }
    }
    sinks
}

/// Django ModelForm mass assignment: a `Meta` with `model = User` whose
/// `exclude` blacklist omits `is_superuser` or `is_staff`, so a crafted
/// registration or profile submission can set the flag. `fields` whitelists
/// and blacklists covering both flags are clean. The documented form is a
/// single- or few-line list; the list is read across up to six lines.
#[allow(clippy::items_after_test_module)]
fn django_modelform_exclude_lines(content: &str, ext: &str) -> std::collections::HashSet<usize> {
    use std::collections::HashSet;
    let mut sinks = HashSet::new();
    if ext != "py" || !content.contains("forms.ModelForm") {
        return sinks;
    }
    let Ok(exclude) = Regex::new(r"^\s*exclude\s*=\s*[\[\(]") else {
        return sinks;
    };
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if !exclude.is_match(line) {
            continue;
        }
        let mut list = String::new();
        for extra in lines.iter().skip(i).take(6) {
            list.push_str(extra);
            if extra.contains(']') || extra.contains(')') {
                break;
            }
        }
        if list.contains("is_superuser") && list.contains("is_staff") {
            continue;
        }
        // The `model = User` binding must belong to the same class body:
        // walk back at most ten lines and stop at the previous class header.
        let in_user_form = lines[..i]
            .iter()
            .rev()
            .take(10)
            .take_while(|prior| !prior.trim_start().starts_with("class "))
            .any(|prior| {
                prior.trim_start().starts_with("model =")
                    && prior
                        .split('=')
                        .nth(1)
                        .is_some_and(|value| value.trim().trim_end_matches(',').trim() == "User")
            });
        if in_user_form {
            sinks.insert(i + 1);
        }
    }
    sinks
}

/// Django views decorated with @csrf_exempt opt out of CSRF token validation.
/// The decorator is an exact, intentional opt-out, so the FP surface is empty;
/// commented-out lines are skipped by the trim/'#' guard.
fn django_csrf_exempt_lines(content: &str, ext: &str) -> std::collections::HashSet<usize> {
    use std::collections::HashSet;
    let mut sinks = HashSet::new();
    if ext != "py" {
        return sinks;
    }
    for (i, line) in content.lines().enumerate() {
        let code = line.trim();
        if code.starts_with('#') {
            continue;
        }
        if code == "@csrf_exempt" {
            sinks.insert(i + 1);
        }
    }
    sinks
}

/// Django ORM IDOR: `<Model>.objects.get(pk=<url param>)` inside a view whose
/// signature takes the parameter, with no same-model ownership filter
/// (`Model.objects.filter(... request.user ...)` or a
/// `instance.users_assigned.filter(... request.user ...)` relation check) in
/// the view body. POST-derived and literal primary keys are out of scope.
fn django_idor_sink_lines(content: &str, ext: &str) -> std::collections::HashSet<usize> {
    use std::collections::{HashMap, HashSet};
    let mut sinks = HashSet::new();
    if ext != "py" {
        return sinks;
    }
    let lines: Vec<&str> = content.lines().collect();
    let def_re =
        Regex::new(r"^def\s+[A-Za-z_][A-Za-z0-9_]*\(\s*request\s*(?:,\s*([^)]*))?\)\s*:").unwrap();
    let get_re =
        Regex::new(r"\b([A-Z][A-Za-z0-9_]*)\.objects\.get\(\s*pk\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\b")
            .unwrap();
    let assign_re =
        Regex::new(r"\b([a-z_][A-Za-z0-9_]*)\s*=\s*([A-Z][A-Za-z0-9_]*)\.objects\.get\(").unwrap();
    let model_filter_re = Regex::new(r"\b([A-Z][A-Za-z0-9_]*)\.objects\.filter\(").unwrap();
    let rel_filter_re =
        Regex::new(r"\b([a-z_][A-Za-z0-9_]*)\.(?:users_assigned|members|owners?)\.filter\(")
            .unwrap();
    let mut i = 0;
    while i < lines.len() {
        let Some(def_caps) = def_re.captures(lines[i]) else {
            i += 1;
            continue;
        };
        let params: HashSet<String> = def_caps
            .get(1)
            .map(|m| {
                m.as_str()
                    .split(',')
                    .map(|p| p.trim().trim_start_matches('*').to_string())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let mut j = i + 1;
        while j < lines.len()
            && !lines[j].starts_with("def ")
            && !lines[j].starts_with('@')
            && !lines[j].starts_with("# A")
        {
            j += 1;
        }
        let body = &lines[i + 1..j];
        let var_model: HashMap<String, String> = body
            .iter()
            .filter_map(|line| {
                assign_re
                    .captures(line)
                    .map(|c| (c[1].to_string(), c[2].to_string()))
            })
            .collect();
        let mut guarded: HashSet<String> = HashSet::new();
        for (k, line) in body.iter().enumerate() {
            let code = line.trim();
            if code.starts_with('#') {
                continue;
            }
            // Filter calls can span lines; gather text to the closing paren.
            let mut call_text = code.to_string();
            if model_filter_re.is_match(code) || rel_filter_re.is_match(code) {
                let mut depth = code.matches('(').count() as i32 - code.matches(')').count() as i32;
                let mut m = k + 1;
                while depth > 0 && m < body.len() {
                    let next = body[m].trim();
                    depth += next.matches('(').count() as i32 - next.matches(')').count() as i32;
                    call_text.push(' ');
                    call_text.push_str(next);
                    m += 1;
                }
            }
            if !call_text.contains("request.user") {
                continue;
            }
            if let Some(caps) = model_filter_re.captures(&call_text) {
                guarded.insert(caps[1].to_string());
            }
            if let Some(caps) = rel_filter_re.captures(&call_text) {
                if let Some(model) = var_model.get(&caps[1]) {
                    guarded.insert(model.clone());
                }
            }
        }
        for (offset, line) in body.iter().enumerate() {
            let code = line.trim();
            if code.starts_with('#') || code.contains("request.user") {
                continue;
            }
            if let Some(caps) = get_re.captures(code) {
                if params.contains(&caps[2]) && !guarded.contains(&caps[1]) {
                    sinks.insert(i + 2 + offset);
                }
            }
        }
        i = j;
    }
    sinks
}

/// Security-sensitive crypto/cookie patterns with enough local context to avoid
/// generic math/rand, plain MD5 checksums, non-session cookies and dead TLS configs.
#[allow(clippy::type_complexity)]
fn pilot_crypto_cookie_lines(
    content: &str,
    ext: &str,
) -> (
    std::collections::HashSet<usize>,
    std::collections::HashSet<usize>,
    std::collections::HashSet<usize>,
    std::collections::HashSet<usize>,
    std::collections::HashSet<usize>,
) {
    use std::collections::HashSet;
    let mut password = HashSet::new();
    let mut token = HashSet::new();
    let mut rsa = HashSet::new();
    let mut tls = HashSet::new();
    let mut cookie = HashSet::new();
    let lines: Vec<&str> = content.lines().collect();
    if ext == "rb" && content.contains("before_save :hash_password") {
        for (i, line) in lines.iter().enumerate() {
            let code = line.trim();
            if code.starts_with('#') {
                continue;
            }
            if code.contains("self.password = Digest::MD5.hexdigest(self.password)") {
                password.insert(i + 1);
            }
        }
    }
    if ext == "php" && content.contains("setcookie(") && content.contains("dvwaSession") {
        for (i, line) in lines.iter().enumerate() {
            let code = line.trim();
            if code.starts_with("//") || code.starts_with('#') {
                continue;
            }
            if code.contains("$cookie_value = $_SESSION['last_session_id']")
                && lines[..i]
                    .iter()
                    .rev()
                    .take(6)
                    .any(|previous| previous.contains("$_SESSION['last_session_id']++"))
                && lines[i + 1..]
                    .iter()
                    .take(3)
                    .any(|next| next.contains("setcookie(\"dvwaSession\", $cookie_value)"))
            {
                token.insert(i + 1);
            }
        }
    }
    if ext != "go" {
        return (password, token, rsa, tls, cookie);
    }
    let weak_rng = content.contains("mathrand \"math/rand\"");
    let tls_server =
        content.contains("TLSConfig: tlsConfig") && content.contains("ListenAndServeTLS(");
    let weak_rsa = Regex::new(r"rsa\.GenerateKey\s*\([^,]+,\s*(?:[1-9][0-9]{0,2}|1[0-9]{3})\s*\)")
        .expect("valid RSA key-size pattern");
    for (i, line) in lines.iter().enumerate() {
        let code = line.trim();
        if code.starts_with("//") || code.starts_with("/*") {
            continue;
        }
        if weak_rng && code.contains("mathrand.Int63()") && code.contains("token :=") {
            token.insert(i + 1);
        }
        if code.contains("rsa.GenerateKey(") && weak_rsa.is_match(code) {
            rsa.insert(i + 1);
        }
        if tls_server
            && (code.contains("MinVersion: tls.VersionTLS10")
                || code.contains("MinVersion: tls.VersionTLS11"))
        {
            tls.insert(i + 1);
        }
        if code.contains("http.SetCookie(") && code.contains("&http.Cookie{") {
            let fields = lines
                .iter()
                .skip(i + 1)
                .take_while(|next| !next.contains('}'))
                .map(|next| next.trim())
                .filter(|next| !next.starts_with("//") && !next.starts_with("/*"))
                .collect::<Vec<_>>();
            if fields
                .iter()
                .any(|field| field.starts_with("Name:") && field.contains("session"))
                && fields
                    .iter()
                    .any(|field| field.starts_with("Value:") && !field.contains("\"\""))
                && (!fields
                    .iter()
                    .any(|field| field.starts_with("HttpOnly:") && field.contains("true"))
                    || !fields
                        .iter()
                        .any(|field| field.starts_with("Secure:") && field.contains("true")))
            {
                cookie.insert(i + 1);
            }
        }
    }
    (password, token, rsa, tls, cookie)
}

/// Local PHP/Ruby sites where the source and terminal are in the same file.
/// PHP upload checks demand an unvalidated move to a web-accessible path;
/// reflected XSS tracks direct request data or weak script-tag stripping.
fn php_ruby_file_xss_lines(
    content: &str,
    ext: &str,
) -> (
    std::collections::HashSet<usize>,
    std::collections::HashSet<usize>,
    std::collections::HashSet<usize>,
) {
    use std::collections::HashSet;
    let mut uploads = HashSet::new();
    let mut reflected = HashSet::new();
    let mut ruby_files = HashSet::new();
    if ext == "rb" && content.contains("params[:name]") {
        let mut selected = false;
        for (i, line) in content.lines().enumerate() {
            if line.trim_start().starts_with('#') {
                continue;
            }
            if line.contains("path = params[:name]") {
                selected = true;
            }
            if selected
                && line.contains("send_file file")
                && content.contains("constantize.new(path)")
            {
                ruby_files.insert(i + 1);
            }
            if line.trim_start().starts_with("end") {
                selected = false;
            }
        }
    }
    if ext != "php" {
        return (uploads, reflected, ruby_files);
    }
    let web_upload = content.contains("hackable/uploads/");
    let user_filename = content.contains("$_FILES") && content.contains("basename(");
    let content_checked = content.contains("getimagesize(") || content.contains("imagecreatefrom");
    let extension_checked =
        content.contains("$uploaded_ext") && (content.contains("jpg") || content.contains("png"));
    let mut request_name = false;
    let mut weak_filtered = false;
    let mut encoded = false;
    let mut statement_started = false;
    for (i, line) in content.lines().enumerate() {
        let code = line.trim();
        if code.starts_with("//") || code.starts_with('#') {
            continue;
        }
        if code.starts_with("$target_path") {
            statement_started = true;
        }
        if web_upload
            && user_filename
            && !content_checked
            && !extension_checked
            && statement_started
            && code.contains("move_uploaded_file(")
            && code.contains("$target_path")
        {
            uploads.insert(i + 1);
        }
        if code.contains("$name =") || code.contains("$name    =") {
            request_name = code.contains("$_GET")
                || (request_name
                    && (code.contains("str_replace(") || code.contains("preg_replace(")));
            weak_filtered =
                request_name && (code.contains("str_replace(") || code.contains("preg_replace("));
            encoded = code.contains("htmlspecialchars(") || code.contains("htmlentities(");
        }
        if code.contains("$html")
            && code.contains("<pre>")
            && ((code.contains("$_GET") && !code.contains("htmlspecialchars("))
                || (code.contains("{$name}") && request_name && weak_filtered && !encoded))
        {
            reflected.insert(i + 1);
        }
    }
    (uploads, reflected, ruby_files)
}

/// Project-context routes: PHP's selected include reads a low-security request
/// source; the guestbook renders database fields inserted by the stored-XSS
/// exercise. ERB's html_safe must be on a user-editable profile field.
fn scoped_php_ruby_file_xss_findings(
    files: &[std::path::PathBuf],
    root: &Path,
    patterns: &[VulnPattern],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let present: std::collections::HashSet<&Path> = files.iter().map(|p| p.as_path()).collect();
    let add = |findings: &mut Vec<Finding>, path: &Path, title: &str, number: usize, line: &str| {
        if let Some(pattern) = patterns.iter().find(|p| p.name == title) {
            findings.push(pattern_finding(pattern, path, number, line));
        }
    };
    let index = root.join("vulnerabilities/fi/index.php");
    let low = root.join("vulnerabilities/fi/source/low.php");
    if present.contains(index.as_path())
        && present.contains(low.as_path())
        && std::fs::read_to_string(&low).is_ok_and(|s| s.contains("$file = $_GET[ 'page' ]"))
    {
        if let Ok(content) = std::fs::read_to_string(&index) {
            if content.contains("vulnerabilities/fi/source/{$vulnerabilityFile}")
                && !content.contains("in_array($file,")
            {
                for (i, line) in content.lines().enumerate() {
                    if line.trim_start().starts_with("include( $file )") {
                        add(&mut findings, &index, "File Inclusion", i + 1, line);
                    }
                }
            }
        }
    }
    let guest = root.join("dvwa/includes/dvwaPage.inc.php");
    let stored = root.join("vulnerabilities/xss_s/source/low.php");
    let route = root.join("vulnerabilities/xss_s/index.php");
    if [guest.as_path(), stored.as_path(), route.as_path()]
        .iter()
        .all(|p| present.contains(p))
        && std::fs::read_to_string(&stored)
            .is_ok_and(|s| s.contains("$_POST[ 'txtName' ]") && s.contains("INSERT INTO guestbook"))
        && std::fs::read_to_string(&route).is_ok_and(|s| s.contains("dvwaGuestbook()"))
    {
        if let Ok(content) = std::fs::read_to_string(&guest) {
            let mut in_guestbook = false;
            let mut outside_impossible = false;
            for (i, line) in content.lines().enumerate() {
                if line.contains("function dvwaGuestbook()") {
                    in_guestbook = true;
                }
                if !in_guestbook {
                    continue;
                }
                if line.contains("else {") {
                    outside_impossible = true;
                }
                if outside_impossible
                    && line.contains("$name")
                    && line.contains("$row[0]")
                    && !line.contains("htmlspecialchars(")
                {
                    add(&mut findings, &guest, "Stored XSS", i + 1, line);
                }
                if line.contains("// -- END (XSS Stored guestbook)") {
                    break;
                }
            }
        }
    }
    let view = root.join("app/views/layouts/shared/_header.html.erb");
    let permitted = root.join("app/controllers/users_controller.rb");
    if present.contains(view.as_path())
        && present.contains(permitted.as_path())
        && std::fs::read_to_string(&permitted)
            .is_ok_and(|s| s.contains("permit(") && s.contains(":first_name"))
    {
        if let Ok(content) = std::fs::read_to_string(&view) {
            for (i, line) in content.lines().enumerate() {
                if line.contains("<%=") && line.contains("current_user.first_name.html_safe") {
                    add(
                        &mut findings,
                        &view,
                        "Unescaped Rails Output (XSS)",
                        i + 1,
                        line,
                    );
                }
            }
        }
    }
    findings
}
