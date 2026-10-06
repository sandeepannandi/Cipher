/// SQL injection in Java library code: a public method appends one of its own
/// `String` parameters straight into a `StringBuilder` that holds SQL text, as
/// in `sql.append(" like '%").append(keyword).append("%'")`. There is no web
/// request in the file, so the parameter is the caller boundary. The builder
/// must carry SQL (a `select`/`from`/`where` literal) and the method must reach
/// a database call. A parameter bound with `?` and `parameters.add(...)` is
/// never appended, so it never fires; numeric parameters, private methods and
/// methods that escape or sanitize the value stay quiet.
fn java_sql_append_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    let mut found = std::collections::HashSet::new();
    if extension != "java"
        || !content.contains("StringBuilder") && !content.contains("StringBuffer")
    {
        return found;
    }
    let (Ok(header_re), Ok(builder_re), Ok(sql_literal_re), Ok(db_re), Ok(clean_re)) = (
        Regex::new(
            r#"^\s*public\s+(?:static\s+|final\s+|synchronized\s+)*[\w<>\[\],.? ]+?\s+\w+\s*\("#,
        ),
        Regex::new(r#"\b(?:StringBuilder|StringBuffer)\s+(\w+)\s*="#),
        Regex::new(r#"(?i)\.append\(\s*"[^"]*\b(?:select|from|where)\b"#),
        Regex::new(
            r#"\b(?:executeQuery|executeUpdate|executeLargeUpdate|prepareStatement|prepareCall|createQuery|createNativeQuery|createSQLQuery|queryForList|queryForObject|queryForRowSet)\s*\(|\bexecute\s*\(|\bquery\s*\(|\bgetConnection\s*\("#,
        ),
        Regex::new(r#"(?i)escape|sanitiz|\bquote\s*\(|replaceAll|\.replace\("#),
    ) else {
        return found;
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        if !header_re.is_match(lines[index]) {
            index += 1;
            continue;
        }
        let end = function_end(&lines, index, extension);
        // Header text up to the opening brace, then its parameter list.
        let mut header = String::new();
        let mut body_start = index;
        for (offset, line) in lines.iter().enumerate().take(end).skip(index) {
            header.push_str(line);
            header.push(' ');
            body_start = offset + 1;
            if line.contains('{') || line.trim_end().ends_with(';') {
                break;
            }
        }
        let (Some(open), Some(close)) = (header.find('('), header.rfind(')')) else {
            index = end.max(index + 1);
            continue;
        };
        if close <= open || header.trim_end().ends_with(';') {
            index = end.max(index + 1);
            continue;
        }
        let mut params: Vec<String> = Vec::new();
        let mut depth = 0i32;
        let mut current = String::new();
        let mut pieces: Vec<String> = Vec::new();
        for ch in header[open + 1..close].chars() {
            match ch {
                '<' => depth += 1,
                '>' => depth -= 1,
                ',' if depth == 0 => {
                    pieces.push(std::mem::take(&mut current));
                    continue;
                }
                _ => {}
            }
            current.push(ch);
        }
        pieces.push(current);
        for piece in pieces {
            let words: Vec<&str> = piece
                .split_whitespace()
                .filter(|w| !w.starts_with('@') && *w != "final")
                .collect();
            if words.len() >= 2 {
                let ty = words[..words.len() - 1].join(" ");
                let name =
                    words[words.len() - 1].trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
                if matches!(ty.as_str(), "String" | "CharSequence" | "java.lang.String") {
                    params.push(name.to_string());
                }
            }
        }
        let body = &lines[body_start.min(end)..end];
        let body_text = body.join("\n");
        let builders: Vec<String> = builder_re
            .captures_iter(&body_text)
            .map(|c| c[1].to_string())
            .collect();
        if params.is_empty()
            || builders.is_empty()
            || !sql_literal_re.is_match(&body_text)
            || !db_re.is_match(&body_text)
            || clean_re.is_match(&body_text)
        {
            index = end.max(index + 1);
            continue;
        }
        for (offset, line) in body.iter().enumerate() {
            let trimmed = line.trim_start();
            if !builders
                .iter()
                .any(|b| trimmed.starts_with(&format!("{b}.append(")))
            {
                continue;
            }
            // The whole statement (it may continue on later lines).
            let mut statement = String::new();
            for next in body.iter().skip(offset) {
                statement.push_str(next);
                statement.push(' ');
                if next.trim_end().ends_with(';') {
                    break;
                }
            }
            let masked = ruby_mask_strings(&statement);
            let appended = params.iter().any(|p| {
                let name = regex::escape(p);
                Regex::new(&format!(r#"\.append\(\s*{name}\s*\)"#))
                    .is_ok_and(|re| re.is_match(&masked))
                    || Regex::new(&format!(r#"\+\s*{name}\s*[+)]"#))
                        .is_ok_and(|re| re.is_match(&masked))
            });
            if appended {
                found.insert(body_start + offset + 1);
            }
        }
        index = end.max(index + 1);
    }
    found
}

/// Argument injection into `git` from a constructor or public-method
/// parameter (Python). `subprocess.run(["git", "ls-remote", self.url])` has no
/// shell, but a URL that starts with `-` is read as an option, e.g.
/// `--upload-pack=...`, which runs a command. The value must be a bare list
/// element taken from a parameter of a public method, or from a field that
/// `__init__` stores straight from one of its parameters. A `--` separator
/// before the value, or any check that the value does not start with `-`,
/// keeps it quiet. Private methods and literal-only argv lists never fire.
fn python_git_option_injection_lines(
    content: &str,
    extension: &str,
) -> std::collections::HashSet<usize> {
    let mut found = std::collections::HashSet::new();
    if extension != "py" || !content.contains("\"git\"") && !content.contains("'git'") {
        return found;
    }
    let (Ok(def_re), Ok(field_re), Ok(list_re), Ok(guard_re)) = (
        Regex::new(r#"^(\s*)(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]*)\)"#),
        Regex::new(r#"^\s*self\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*$"#),
        Regex::new(
            r#"\[\s*["']git["']\s*,\s*["'](?:ls-remote|clone|fetch|pull)["']\s*,([^\]]*)\]"#,
        ),
        Regex::new(r#"startswith\(\s*["']-|["']--end-of-options["']|\bis_safe_git|\bvalidate_url"#),
    ) else {
        return found;
    };
    if guard_re.is_match(content) {
        return found;
    }
    let lines: Vec<&str> = content.lines().collect();
    // (indent, name, params, start, end) for every def.
    let mut defs: Vec<(usize, String, Vec<String>, usize, usize)> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if let Some(c) = def_re.captures(line) {
            let indent = c[1].len();
            let params: Vec<String> = c[3]
                .split(',')
                .filter_map(|p| {
                    let p = p.trim().trim_start_matches('*');
                    let p = p.split([':', '=']).next().unwrap_or("").trim();
                    (!p.is_empty() && p != "self" && p != "cls").then(|| p.to_string())
                })
                .collect();
            let mut end = lines.len();
            for (j, later) in lines.iter().enumerate().skip(i + 1) {
                if !later.trim().is_empty() && later.len() - later.trim_start().len() <= indent {
                    end = j;
                    break;
                }
            }
            defs.push((indent, c[2].to_string(), params, i, end));
        }
    }
    // Fields that `__init__` stores directly from one of its own parameters.
    let mut fields: Vec<String> = Vec::new();
    for (_, name, params, start, end) in &defs {
        if name != "__init__" {
            continue;
        }
        for line in &lines[*start + 1..*end] {
            if let Some(c) = field_re.captures(line) {
                if params.iter().any(|p| p == &c[2]) {
                    fields.push(c[1].to_string());
                }
            }
        }
    }
    for (index, line) in lines.iter().enumerate() {
        let Some(c) = list_re.captures(line) else {
            continue;
        };
        // Innermost def around the line.
        let Some((_, name, params, _, _)) = defs
            .iter()
            .filter(|d| d.3 < index && index < d.4)
            .max_by_key(|d| d.3)
        else {
            continue;
        };
        if name.starts_with('_') && name != "__init__" {
            continue;
        }
        let rest = &c[1];
        let elements: Vec<&str> = rest.split(',').map(str::trim).collect();
        for (n, element) in elements.iter().enumerate() {
            let element = element.trim_matches(|ch| ch == ' ' || ch == ')');
            let tainted = params.iter().any(|p| p == element)
                || element
                    .strip_prefix("self.")
                    .is_some_and(|f| fields.iter().any(|x| x == f));
            if !tainted {
                continue;
            }
            let separated = elements[..n]
                .iter()
                .any(|e| matches!(*e, "\"--\"" | "'--'"));
            if !separated {
                found.insert(index + 1);
            }
        }
    }
    found
}

/// Command injection in library code: a public function builds a shell
/// command string out of one of its own parameters. There is no web request
/// source in a library, so the caller-supplied parameter is the attacker
/// boundary. Only shell-string sinks count (a call that hands one string to a
/// shell), the parameter must be composed into the string, and a shell-quote
/// helper applied in the function body clears it. A fixed argv call, or a
/// parameter that is not part of the command text, never fires.
fn library_parameter_command_lines(
    content: &str,
    extension: &str,
) -> std::collections::HashSet<usize> {
    let mut found = std::collections::HashSet::new();
    // Build-tool scripts (Grunt/Gulp) take their arguments from the developer's
    // own command line, not from an untrusted caller.
    if matches!(extension, "js" | "mjs" | "cjs" | "ts")
        && (content.contains("grunt.registerTask")
            || content.contains("grunt.initConfig")
            || content.contains("gulp.task(")
            || content.contains("gulp.series("))
    {
        return found;
    }
    let lines: Vec<&str> = content.lines().collect();
    let (sink, quoted): (&str, &str) = match extension {
        "js" | "mjs" | "cjs" | "ts" => (
            r#"(?:^|[^.\w$])(?:exec|execSync)\s*\(|\b(?:child_process|childProcess|cp)\s*\.\s*(?:exec|execSync)\s*\("#,
            r#"(?i)shell-?quote|shell-?escape|escapeshellarg|\bquote\s*\(|execFile"#,
        ),
        "py" => (
            r#"\bos\s*\.\s*(?:system|popen)\s*\(|\b(?:subprocess|commands)\s*\.\s*(?:getoutput|getstatusoutput)\s*\(|\bsubprocess\s*\.\s*(?:run|call|check_call|check_output|Popen)\s*\("#,
            r#"shlex\s*\.\s*quote|pipes\s*\.\s*quote|\bquote\s*\("#,
        ),
        "go" => (
            r#"\bexec\s*\.\s*Command(?:Context)?\s*\(\s*(?:[A-Za-z_.]+\s*,\s*)?"(?:/bin/)?(?:sh|bash|zsh)"\s*,\s*"-c"\s*,"#,
            r#"shellescape|shellquote|\bQuote\s*\("#,
        ),
        _ => return found,
    };
    let (Ok(sink), Ok(quoted)) = (Regex::new(sink), Regex::new(quoted)) else {
        return found;
    };
    let (Ok(py_shell_true), Ok(py_shell_call)) = (
        Regex::new(r#"shell\s*=\s*True"#),
        Regex::new(r#"\bos\s*\.\s*(?:system|popen)|getoutput|getstatusoutput"#),
    ) else {
        return found;
    };
    for (index, line) in lines.iter().enumerate() {
        if !sink.is_match(line) {
            continue;
        }
        let Some((params, body_start, body_end)) =
            enclosing_public_function(&lines, index, extension)
        else {
            continue;
        };
        let body = lines[body_start..body_end].join("\n");
        if quoted.is_match(&body) {
            continue;
        }
        let call_text = call_arguments_text(&lines, index, &sink);
        if extension == "py" && !py_shell_true.is_match(&call_text) && !py_shell_call.is_match(line)
        {
            continue;
        }
        if composes_parameter(&call_text, &params, &lines[body_start..=index]) {
            found.insert(index + 1);
        }
    }
    found
}

/// Text of the sink call's argument list, up to its closing parenthesis.
fn call_arguments_text(lines: &[&str], index: usize, sink: &Regex) -> String {
    let first = lines[index];
    let start = sink.find(first).map_or(0, |m| m.end());
    let mut text = String::new();
    let mut depth = 1i64;
    let mut current = &first[start..];
    let mut line_index = index;
    loop {
        for ch in current.chars() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return text;
                    }
                }
                _ => {}
            }
            text.push(ch);
        }
        text.push('\n');
        line_index += 1;
        if line_index >= lines.len() || line_index > index + 6 {
            return text;
        }
        current = lines[line_index];
    }
}

/// True when the call text composes a parameter into the command string:
/// concatenation, interpolation, formatting, or a local variable assigned
/// from one of those earlier in the function.
fn composes_parameter(call_text: &str, params: &[String], earlier: &[&str]) -> bool {
    let mut names: Vec<String> = params.to_vec();
    // One hop: `cmd = "..." + param` earlier in the body taints `cmd`.
    for line in earlier {
        let Some((lhs, rhs)) = line.split_once('=') else {
            continue;
        };
        let lhs = lhs
            .trim()
            .trim_start_matches("var ")
            .trim_start_matches("let ")
            .trim_start_matches("const ")
            .trim_start_matches("local ")
            .trim_end_matches(':')
            .trim();
        let first = lhs.split([':', ' ']).next().unwrap_or("");
        if first.is_empty()
            || !first
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
            || rhs.starts_with('=')
        {
            continue;
        }
        if params.iter().any(|p| contains_identifier(rhs, p))
            && (rhs.contains('+')
                || rhs.contains("${")
                || rhs.contains("f\"")
                || rhs.contains("f'")
                || rhs.contains('%')
                || rhs.contains(".format(")
                || rhs.contains("Sprintf")
                || rhs.contains(".join("))
        {
            names.push(first.to_string());
        }
    }
    let trimmed = call_text.trim();
    // A bare identifier or literal alone is not composition unless it names
    // a tainted local.
    let composed = trimmed.contains('+')
        || trimmed.contains("${")
        || trimmed.contains(".format(")
        || trimmed.contains("Sprintf")
        || trimmed.contains('%')
        || trimmed.contains("f\"")
        || trimmed.contains("f'")
        || trimmed.contains(".join(");
    names
        .iter()
        .enumerate()
        .any(|(i, name)| contains_identifier(call_text, name) && (composed || i >= params.len()))
}

fn contains_identifier(text: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(pos) = text[from..].find(name) {
        let start = from + pos;
        let end = start + name.len();
        let before_ok = start == 0
            || !(bytes[start - 1].is_ascii_alphanumeric()
                || bytes[start - 1] == b'_'
                || bytes[start - 1] == b'$'
                || bytes[start - 1] == b'.');
        let after_ok = end >= bytes.len()
            || !(bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_' || bytes[end] == b'$');
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

/// The public function containing `index`: its parameters and body line
/// range. Public means exported (`module.exports`, `exports.x`, `export`),
/// a module-level Python `def` without a leading underscore, or a Go
/// function with an upper-case name.
fn enclosing_public_function(
    lines: &[&str],
    index: usize,
    extension: &str,
) -> Option<(Vec<String>, usize, usize)> {
    let header = match extension {
        "js" | "mjs" | "cjs" | "ts" => Regex::new(
            r#"^\s*(?:module\s*\.\s*exports(?:\s*\.\s*[A-Za-z_$][\w$]*)?|exports\s*\.\s*[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function\s*[\w$]*\s*\(([^()]*)\)\s*\{|^\s*export\s+(?:default\s+)?(?:async\s+)?function\s*[\w$]*\s*\(([^()]*)\)[^{]*\{"#,
        ),
        "py" => Regex::new(r#"^(?:async\s+)?def\s+([A-Za-z][A-Za-z0-9_]*)\s*\(([^()]*)\)\s*(?:->\s*[^:]+)?:\s*$"#),
        "go" => Regex::new(r#"^func\s+[A-Z][A-Za-z0-9_]*\s*\(([^()]*)\)[^{]*\{\s*$"#),
        _ => return None,
    }
    .ok()?;
    let mut start = index;
    loop {
        let line = lines[start];
        if let Some(captures) = header.captures(line) {
            let raw = captures
                .iter()
                .skip(1)
                .flatten()
                .map(|m| m.as_str())
                .last()
                .unwrap_or("");
            let params = library_param_names(raw, extension);
            // The body must reach the sink line.
            let end = function_end(lines, start, extension);
            if end > index {
                return Some((params, start + 1, end));
            }
            return None;
        }
        if start == 0 {
            return None;
        }
        start -= 1;
    }
}

fn library_param_names(raw: &str, extension: &str) -> Vec<String> {
    raw.split(',')
        .filter_map(|part| {
            let part = part.trim();
            let part = part.split('=').next().unwrap_or("").trim();
            let name = match extension {
                "go" => part.split_whitespace().next().unwrap_or(""),
                "py" => part
                    .trim_start_matches('*')
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .trim(),
                _ => part
                    .trim_start_matches("...")
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .trim(),
            };
            (!name.is_empty()
                && name != "self"
                && name != "cls"
                && name
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '$'))
            .then(|| name.to_string())
        })
        .collect()
}

fn function_end(lines: &[&str], start: usize, extension: &str) -> usize {
    if extension == "py" {
        let mut end = start + 1;
        for (offset, next) in lines.iter().enumerate().skip(start + 1) {
            if next.trim().is_empty() || next.trim_start().starts_with('#') {
                continue;
            }
            if !next.starts_with([' ', '\t']) {
                break;
            }
            end = offset + 1;
        }
        return end;
    }
    let mut depth = 0i64;
    let mut opened = false;
    for (offset, next) in lines.iter().enumerate().skip(start) {
        for ch in next.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    opened = true;
                }
                '}' => depth -= 1,
                _ => {}
            }
        }
        if opened && depth <= 0 {
            return offset + 1;
        }
    }
    lines.len()
}

#[allow(clippy::items_after_test_module)]
fn command_flow_sinks(language: FlowLanguage) -> Vec<FlowSink> {
    let shell_prefix = r#""(?:/bin/)?(?:sh|bash|zsh)"\s*,\s*"-c"|"cmd(?:\.exe)?"\s*,\s*"/c""#;
    let patterns: &[(&str, FlowArguments, Option<&str>)] = match language {
        FlowLanguage::Python => &[
            (r#"\bos\s*\.\s*(system|popen)\s*\("#, first_argument, None),
            (
                r#"\b(?:subprocess|commands)\s*\.\s*(getoutput|getstatusoutput)\s*\("#,
                first_argument,
                None,
            ),
            (
                r#"\bsubprocess\s*\.\s*(run|call|check_call|check_output|Popen)\s*\("#,
                first_argument,
                Some(r#"\bshell\s*=\s*True\b"#),
            ),
        ],
        FlowLanguage::JavaScript => &[
            (r#"(?:^|[^.\w$])(exec|execSync)\s*\("#, first_argument, None),
            (
                r#"\b(?:child_process|childProcess|cp)\s*\.\s*(exec|execSync)\s*\("#,
                first_argument,
                None,
            ),
        ],
        FlowLanguage::Java => &[
            (
                r#"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*(exec)\s*\("#,
                first_argument,
                None,
            ),
            (
                r#"\bnew\s+(ProcessBuilder)\s*\("#,
                shell_command_argument,
                Some(shell_prefix),
            ),
        ],
        FlowLanguage::Go => &[(
            r#"\bexec\s*\.\s*(Command|CommandContext)\s*\("#,
            shell_command_argument,
            Some(shell_prefix),
        )],
        FlowLanguage::Rust => &[(
            r#"\.\s*(arg)\s*\("#,
            first_argument,
            Some(
                r#"Command\s*::\s*new\s*\(\s*"(?:/bin/)?(?:sh|bash|zsh)"\s*\)\s*\.\s*arg\s*\(\s*"-c""#,
            ),
        )],
    };
    patterns
        .iter()
        .filter_map(|(pattern, arguments, requires)| {
            let call = Regex::new(pattern).ok()?;
            let line_requires = match requires {
                Some(required) => Some(Regex::new(required).ok()?),
                None => None,
            };
            Some(FlowSink {
                call,
                arguments: *arguments,
                line_requires,
            })
        })
        .collect()
}

#[allow(clippy::items_after_test_module)]
fn outbound_url_argument(name: &str) -> Vec<usize> {
    match name {
        "request" | "NewRequest" => vec![1],
        "NewRequestWithContext" => vec![2],
        _ => vec![0],
    }
}

/// Express redirects are vulnerable only when their destination is request-controlled.
/// Express accepts either `redirect(path)` or `redirect(status, path)`.
#[allow(clippy::items_after_test_module)]
fn open_redirect_sink_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    if extension == "py" {
        let Ok(call) = Regex::new(r"\b(?:redirect|HttpResponseRedirect)\s*\(") else {
            return std::collections::HashSet::new();
        };
        let mut lines = request_flow_sink_lines(
            content,
            FlowLanguage::Python,
            &[FlowSink {
                call,
                arguments: first_argument,
                line_requires: None,
            }],
            |_| false,
            false,
        );
        // URL parameters interpolated into a fixed local path are not open
        // redirects. Require the target itself to be read from request input.
        lines.retain(|line_number| {
            content.lines().nth(line_number - 1).is_some_and(|code| {
                code.contains("request.GET.get(") || code.contains("request.POST.get(")
            })
        });
        return lines;
    }
    if extension == "go" {
        let Ok(call) = Regex::new(r"\bhttp\s*\.\s*(Redirect)\s*\(") else {
            return std::collections::HashSet::new();
        };
        return request_flow_sink_lines(
            content,
            FlowLanguage::Go,
            &[FlowSink {
                call,
                arguments: redirect_target_argument,
                line_requires: None,
            }],
            |_| false,
            false,
        );
    }
    if !matches!(extension, "js" | "ts") {
        return std::collections::HashSet::new();
    }
    let Ok(first) = Regex::new(r"\b(?:res|response)\s*\.\s*(redirect)\s*\(") else {
        return std::collections::HashSet::new();
    };
    let mut lines = request_flow_sink_lines(
        content,
        FlowLanguage::JavaScript,
        &[FlowSink {
            call: first,
            arguments: first_argument,
            line_requires: None,
        }],
        |_| false,
        false,
    );
    lines.retain(|line_number| {
        let code = content.lines().nth(line_number - 1).unwrap_or("");
        first_redirect_has_one_argument(code)
    });
    lines.extend(request_flow_sink_lines(
        content,
        FlowLanguage::JavaScript,
        &[FlowSink {
            call: Regex::new(r"\b(?:res|response)\s*\.\s*(redirect)\s*\(")
                .expect("redirect pattern"),
            arguments: redirect_second_argument,
            line_requires: Regex::new(r"\b(?:res|response)\s*\.\s*redirect\s*\(\s*\d{3}\s*,").ok(),
        }],
        |_| false,
        false,
    ));
    lines
}

#[allow(clippy::items_after_test_module)]
fn first_redirect_has_one_argument(line: &str) -> bool {
    let Ok(call) = Regex::new(r"\b(?:res|response)\s*\.\s*redirect\s*\(") else {
        return false;
    };
    let one_argument = call
        .find_iter(line)
        .any(|found| call_arguments(line, found.end() - 1).len() == 1);
    one_argument
}

#[allow(clippy::items_after_test_module)]
fn redirect_second_argument(_name: &str) -> Vec<usize> {
    vec![1]
}

/// Report the vulnerable pattern declaration only when its `.test` call
/// consumes request-controlled input. This is deliberately a narrow nested
/// quantifier model rather than claiming all regexes with repetition are slow.
#[allow(clippy::items_after_test_module)]
fn redos_sink_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    if !matches!(extension, "js" | "ts") {
        return std::collections::HashSet::new();
    }
    let Ok(binding) = Regex::new(
        r"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*/((?:\\.|[^/])*)/[a-z]*",
    ) else {
        return std::collections::HashSet::new();
    };
    let Ok(nested) = Regex::new(r"\([^)]*[+*][^)]*\)[+*]") else {
        return std::collections::HashSet::new();
    };
    let mut sites = std::collections::HashSet::new();
    for (index, line) in content.lines().enumerate() {
        if line.trim_start().starts_with("//") || line.trim_start().starts_with("/*") {
            continue;
        }
        for capture in binding.captures_iter(line) {
            let (Some(name), Some(pattern)) = (capture.get(1), capture.get(2)) else {
                continue;
            };
            if !nested.is_match(pattern.as_str()) {
                continue;
            }
            let call = format!(r"\b{}\s*\.\s*(test)\s*\(", regex::escape(name.as_str()));
            let Ok(call) = Regex::new(&call) else {
                continue;
            };
            let reached = request_flow_sink_lines(
                content,
                FlowLanguage::JavaScript,
                &[FlowSink {
                    call,
                    arguments: first_argument,
                    line_requires: None,
                }],
                |_| false,
                false,
            );
            if reached.iter().any(|line_number| *line_number > index + 1) {
                sites.insert(index + 1);
            }
        }
    }
    sites
}

/// Find direct password storage in an object passed to a database insert.
/// Ignore commented-out hash examples: only active lines participate.
#[allow(clippy::items_after_test_module)]
fn plaintext_password_lines(
    content: &str,
    extension: &str,
) -> (
    std::collections::HashSet<usize>,
    std::collections::HashSet<usize>,
) {
    let mut stores = std::collections::HashSet::new();
    let mut compares = std::collections::HashSet::new();
    if !matches!(extension, "js" | "ts") {
        return (stores, compares);
    }
    let Ok(object) = Regex::new(r"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\{")
    else {
        return (stores, compares);
    };
    let Ok(field) = Regex::new(r"(?i)^\s*password\s*(?:,|(?://.*)?$|:\s*password\s*,?)") else {
        return (stores, compares);
    };
    let Ok(compare) = Regex::new(
        r"\b(?:return\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:===|==)\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*;",
    ) else {
        return (stores, compares);
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut in_comment = false;
    let mut active = vec![false; lines.len()];
    for (i, line) in lines.iter().enumerate() {
        let trim = line.trim();
        if in_comment {
            if trim.contains("*/") {
                in_comment = false;
            }
            continue;
        }
        if trim.starts_with("/*") {
            in_comment = !trim.contains("*/");
            continue;
        }
        active[i] = !trim.starts_with("//") && !trim.starts_with('*');
    }
    for (i, line) in lines.iter().enumerate() {
        if !active[i] {
            continue;
        }
        if let Some(capture) = object.captures(line) {
            let name = capture.get(1).map_or("", |m| m.as_str());
            let mut depth = 0i32;
            let mut fields = Vec::new();
            let mut end = i;
            for (j, body) in lines.iter().enumerate().skip(i).take(35) {
                if !active[j] {
                    continue;
                }
                if field.is_match(body) {
                    fields.push(j + 1);
                }
                depth += body.matches('{').count() as i32 - body.matches('}').count() as i32;
                end = j;
                if depth <= 0 {
                    break;
                }
            }
            if !fields.is_empty()
                && lines
                    .iter()
                    .enumerate()
                    .skip(end + 1)
                    .take(55)
                    .any(|(j, body)| {
                        active[j]
                            && (body.contains(".insert(")
                                || body.contains(".insertOne(")
                                || body.contains(".save("))
                            && identifier_in(body, name)
                    })
            {
                stores.extend(fields);
            }
        }
        if let Some(capture) = compare.captures(line) {
            let lhs = capture.get(1).map_or("", |m| m.as_str());
            let rhs = capture.get(2).map_or("", |m| m.as_str());
            let vicinity = lines[i.saturating_sub(5)..=i]
                .join(" ")
                .to_ascii_lowercase();
            let downstream = lines
                .iter()
                .enumerate()
                .skip(i + 1)
                .take(25)
                .any(|(j, body)| {
                    active[j] && body.contains("comparePassword(") && body.contains(".password")
                });
            if vicinity.contains("comparepassword") && downstream && lhs != rhs {
                compares.insert(i + 1);
            }
        }
    }
    (stores, compares)
}

/// Find outbound HTTP requests whose URL is built from request input in the
/// same file.
///
/// Sources and propagation match the SQL injection model. Only the URL
/// argument counts: Python `requests`/`httpx` calls and `urlopen`; JS
/// `fetch`, `axios`, `needle`, `got`, and `http(s).get/request`; Java `new URL`,
/// `URI.create`, and `RestTemplate` calls; Go `http.Get/Post/Head/PostForm`
/// and `http.NewRequest*`; Rust `reqwest`/`ureq` `get`/`post`/... calls. A
/// request value sent only as a query parameter,
/// body, or header of a fixed URL is not reported. Host allowlists are not
/// modeled as sanitizers; numeric conversions stop the flow. Same-file and
/// straight-line only; no interprocedural claim.
#[allow(clippy::items_after_test_module)]
fn ssrf_sink_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    let Some(language) = flow_language(extension) else {
        return std::collections::HashSet::new();
    };
    let mut sinks = request_flow_sink_lines(
        content,
        language,
        &ssrf_flow_sinks(language),
        contains_numeric_conversion,
        false,
    );
    if extension == "py" {
        move_python_connection_sinks_to_request(content, &mut sinks);
    }
    sinks
}

/// `conn = HTTPConnection(host)` only builds the connection; the request
/// leaves at `conn.request(...)`. When the constructor line is a tainted sink
/// and the same variable makes a `.request(` call within the next 15 lines,
/// report at that call instead. Without such a call the constructor line stays.
fn move_python_connection_sinks_to_request(
    content: &str,
    sinks: &mut std::collections::HashSet<usize>,
) {
    let Ok(assign) = Regex::new(r"^\s*(\w+)\s*=\s*(?:\w+\s*\.\s*)*HTTPS?Connection\s*\(") else {
        return;
    };
    let lines: Vec<&str> = content.lines().collect();
    for number in sinks.clone() {
        let Some(line) = lines.get(number - 1) else {
            continue;
        };
        let Some(caps) = assign.captures(line) else {
            continue;
        };
        let call = format!("{}.request(", &caps[1]);
        let found = lines
            .iter()
            .enumerate()
            .skip(number)
            .take(15)
            .find(|(_, l)| l.contains(&call));
        if let Some((idx, _)) = found {
            sinks.remove(&number);
            sinks.insert(idx + 1);
        }
    }
}

#[allow(clippy::items_after_test_module)]
fn ssrf_flow_sinks(language: FlowLanguage) -> Vec<FlowSink> {
    let patterns: &[&str] = match language {
        FlowLanguage::Python => &[
            r#"\b(?:requests|httpx|session|client)\s*\.\s*(get|post|put|delete|head|patch|options|request)\s*\("#,
            r#"\b(?:urllib\s*\.\s*request\s*\.\s*)?(urlopen)\s*\("#,
            r#"\b(?:http\s*\.\s*client\s*\.\s*|httplib\s*\.\s*)?(HTTPS?Connection)\s*\("#,
        ],
        FlowLanguage::JavaScript => &[
            r#"(?:^|[^.\w$])(fetch|got|axios)\s*\("#,
            r#"\b(?:axios|needle|got)\s*\.\s*(get|post|put|delete|head|patch|request)\s*\("#,
            r#"\bhttps?\s*\.\s*(get|request)\s*\("#,
        ],
        FlowLanguage::Java => &[
            r#"\bnew\s+(URL)\s*\("#,
            r#"\bURI\s*\.\s*(create)\s*\("#,
            r#"\b[A-Za-z_]*[Rr]est[Tt]emplate\s*\.\s*(getForObject|getForEntity|postForObject|postForEntity|exchange)\s*\("#,
        ],
        FlowLanguage::Go => &[
            r#"\bhttp\s*\.\s*(Get|Post|Head|PostForm|NewRequest|NewRequestWithContext)\s*\("#,
            r#"\b(?:client|httpClient)\s*\.\s*(Get|Head)\s*\("#,
        ],
        FlowLanguage::Rust => &[
            r#"\b(?:reqwest|ureq)\s*::\s*(get|post|put|delete|head|patch)\s*\("#,
            r#"\b(?:client|reqwest)\s*\.\s*(get|post|put|delete|head|patch|request)\s*\("#,
        ],
    };
    patterns
        .iter()
        .filter_map(|pattern| {
            Regex::new(pattern).ok().map(|call| FlowSink {
                call,
                arguments: outbound_url_argument,
                line_requires: None,
            })
        })
        .collect()
}
