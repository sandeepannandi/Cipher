/// Find calls through local Python aliases bound directly to `hashlib.md5`.
///
/// This intentionally stays narrow: it follows only direct callable bindings in
/// the same file and reports an invocation of that identifier. Secure hash
/// aliases and unrelated callables remain clean.
#[allow(clippy::items_after_test_module)]
fn python_md5_alias_call_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    if extension != "py" {
        return std::collections::HashSet::new();
    }

    let Ok(binding) =
        Regex::new(r#"(?i)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:hashlib\s*\.\s*md5|md5)\s*$"#)
    else {
        return std::collections::HashSet::new();
    };

    let mut aliases = std::collections::HashSet::new();
    let mut call_lines = std::collections::HashSet::new();
    for (line_index, line) in content.lines().enumerate() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.is_empty() {
            continue;
        }

        if let Some(alias) = binding
            .captures(code)
            .and_then(|captures| captures.get(1))
            .map(|capture| capture.as_str().to_string())
        {
            aliases.insert(alias);
            continue;
        }

        if aliases.iter().any(|alias| {
            Regex::new(&format!(r"\b{}\s*\(", regex::escape(alias)))
                .is_ok_and(|call| call.is_match(code))
        }) {
            call_lines.insert(line_index + 1);
        }
    }
    call_lines
}

/// Find Python filesystem sinks reached by a request-path value.
///
/// This intentionally models only straight-line local bindings. It follows Flask
/// and Django request path input through aliases and path construction, but stops
/// at basename-style sanitizers. The narrow model does not claim interprocedural
/// coverage.
#[allow(clippy::items_after_test_module)]
fn python_path_traversal_sink_lines(
    content: &str,
    extension: &str,
) -> std::collections::HashSet<usize> {
    if extension != "py" {
        return std::collections::HashSet::new();
    }

    let Ok(source) = Regex::new(
        r#"(?i)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:[A-Za-z_][A-Za-z0-9_.]*\s*\(\s*)?(?:request\.(?:args|form|values|GET|POST|headers|cookies|json|data)(?:\.get\s*\([^)]*\)|\s*\[[^\]]+\])|request\.path)"#,
    ) else {
        return std::collections::HashSet::new();
    };
    let Ok(binding) = Regex::new(r#"(?i)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$"#) else {
        return std::collections::HashSet::new();
    };
    let Ok(open_sink) = Regex::new(r#"(?i)\bopen\s*\("#) else {
        return std::collections::HashSet::new();
    };
    let Ok(method_sink) = Regex::new(
        r#"(?i)\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:read_text|read_bytes|write_text|write_bytes|open)\s*\("#,
    ) else {
        return std::collections::HashSet::new();
    };

    let mut tainted: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut sink_lines = std::collections::HashSet::new();
    for (line_index, line) in content.lines().enumerate() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.is_empty() {
            continue;
        }

        if let Some(name) = source
            .captures(code)
            .and_then(|captures| captures.get(1))
            .map(|capture| capture.as_str().to_string())
        {
            if !contains_python_path_sanitizer(code) {
                tainted.insert(name);
            }
            continue;
        }

        if let Some(captures) = binding.captures(code) {
            let lhs = captures.get(1).map(|capture| capture.as_str());
            let rhs = captures
                .get(2)
                .map(|capture| capture.as_str())
                .unwrap_or("");
            let derives_from_taint = tainted.iter().any(|name| identifier_in(rhs, name));
            if derives_from_taint && !contains_python_path_sanitizer(rhs) {
                if let Some(lhs) = lhs {
                    tainted.insert(lhs.to_string());
                }
            }
        }

        let tainted_open =
            open_sink.is_match(code) && tainted.iter().any(|name| identifier_in(code, name));
        let tainted_method = method_sink.captures_iter(code).any(|captures| {
            captures
                .get(1)
                .is_some_and(|receiver| tainted.contains(receiver.as_str()))
        });
        if (tainted_open || tainted_method) && !contains_python_path_sanitizer(code) {
            sink_lines.insert(line_index + 1);
        }
    }
    sink_lines
}

/// Find Java filesystem sinks reached by a servlet request-path value.
///
/// This intentionally models only straight-line local bindings. It follows
/// `getParameter`/`getHeader`/`getPathInfo` input through aliases, string
/// construction, `new File`, `Paths.get`/`Path.of`, and `resolve`, but stops at
/// file-name sanitizers such as `getFileName()`. The narrow model does not claim
/// interprocedural coverage.
#[allow(clippy::items_after_test_module)]
fn java_path_traversal_sink_lines(
    content: &str,
    extension: &str,
) -> std::collections::HashSet<usize> {
    if extension != "java" {
        return std::collections::HashSet::new();
    }

    let Ok(source) = Regex::new(
        r#"(?i)^\s*(?:final\s+)?(?:[A-Za-z_][A-Za-z0-9_.<>\[\]]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:[A-Za-z_][A-Za-z0-9_.]*\s*\(\s*)?(?:req|request)\s*\.\s*(?:getParameter|getHeader|getPathInfo|getQueryString)\s*\("#,
    ) else {
        return std::collections::HashSet::new();
    };
    let Ok(binding) = Regex::new(
        r#"(?i)^\s*(?:final\s+)?(?:[A-Za-z_][A-Za-z0-9_.<>\[\]]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^=].*?);?\s*$"#,
    ) else {
        return std::collections::HashSet::new();
    };
    let Ok(sink) = Regex::new(
        r#"(?i)\bnew\s+(?:FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)\s*\(|\bFiles\s*\.\s*(?:readAllBytes|readString|readAllLines|lines|newInputStream|newBufferedReader|newBufferedWriter|newOutputStream|write|writeString)\s*\("#,
    ) else {
        return std::collections::HashSet::new();
    };

    let mut tainted: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut sink_lines = std::collections::HashSet::new();
    for (line_index, line) in content.lines().enumerate() {
        let code = line.trim();
        if code.is_empty()
            || code.starts_with("//")
            || code.starts_with("/*")
            || code.starts_with('*')
        {
            continue;
        }

        if let Some(name) = source
            .captures(code)
            .and_then(|captures| captures.get(1))
            .map(|capture| capture.as_str().to_string())
        {
            if !contains_java_path_sanitizer(code) {
                tainted.insert(name);
            }
            continue;
        }

        if let Some(captures) = binding.captures(code) {
            let lhs = captures.get(1).map(|capture| capture.as_str());
            let rhs = captures
                .get(2)
                .map(|capture| capture.as_str())
                .unwrap_or("");
            let derives_from_taint = tainted.iter().any(|name| identifier_in(rhs, name));
            if derives_from_taint && !contains_java_path_sanitizer(rhs) {
                if let Some(lhs) = lhs {
                    tainted.insert(lhs.to_string());
                }
            }
        }

        if sink.is_match(code)
            && tainted.iter().any(|name| identifier_in(code, name))
            && !contains_java_path_sanitizer(code)
        {
            sink_lines.insert(line_index + 1);
        }
    }
    sink_lines
}

#[allow(clippy::items_after_test_module)]
fn contains_java_path_sanitizer(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains(".getfilename(")
        || lower.contains("filenameutils.getname(")
        || lower.contains(".getname()")
}

/// Find Go filesystem sinks reached by a `net/http` request-path value.
///
/// This intentionally models only straight-line local bindings. It follows
/// query, form, and URL path input through aliases, string construction, and
/// `filepath.Join`/`path.Join`, but stops at `filepath.Base`/`path.Base`.
/// `filepath.Clean` is not treated as a sanitizer because it keeps leading
/// `../` segments. The narrow model does not claim interprocedural coverage.
/// Go archive extraction that joins an entry's own name onto a destination
/// directory ("zip slip"): inside one function, a value read from an archive
/// iterator (`tar`/`zip` `Next`, `ReadNextEntry`, `range ...File`) is used in
/// `filepath.Join`/`path.Join`, and the function has no containment check
/// (`HasPrefix`, `IsLocal`, `Rel`, `SecureJoin`, a `".."` test) and does not
/// reduce the name with `Base`. `path.Clean` alone does not count: it keeps a
/// leading `..`. Same function and straight-line only.
#[allow(clippy::items_after_test_module)]
fn go_archive_entry_join_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    let mut found = std::collections::HashSet::new();
    if extension != "go" {
        return found;
    }
    let (Ok(entry_re), Ok(range_re), Ok(join_re), Ok(guard_re), Ok(alias_re)) = (
        Regex::new(
            r#"\b([A-Za-z_][A-Za-z0-9_]*)\s*,\s*[A-Za-z_][A-Za-z0-9_]*\s*:?=\s*[A-Za-z0-9_.()]*\.\s*(?:Next|ReadNextEntry)\s*\("#,
        ),
        Regex::new(
            r#"\bfor\s+_\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*:=\s*range\s+[A-Za-z0-9_.]+\.File\b"#,
        ),
        Regex::new(r#"\b(?:filepath|path)\s*\.\s*Join\s*\("#),
        Regex::new(
            r#"HasPrefix\s*\(|IsLocal\s*\(|filepath\s*\.\s*Rel\s*\(|[Ss]ecure[Jj]oin|"\.\.""#,
        ),
        Regex::new(
            r#"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:?=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*[A-Za-z_]"#,
        ),
    ) else {
        return found;
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut start = 0;
    while start < lines.len() {
        if !lines[start].starts_with("func ") {
            start += 1;
            continue;
        }
        let mut end = start + 1;
        while end < lines.len() && !lines[end].starts_with("func ") {
            end += 1;
        }
        let body = &lines[start..end];
        let text = body.join("\n");
        if !guard_re.is_match(&text) {
            let mut names: Vec<String> = Vec::new();
            for (offset, line) in body.iter().enumerate() {
                let code = line.trim();
                if code.starts_with("//") {
                    continue;
                }
                for re in [&entry_re, &range_re] {
                    if let Some(name) = re.captures(code).and_then(|c| c.get(1)) {
                        names.push(name.as_str().to_string());
                    }
                }
                if let Some(c) = alias_re.captures(code) {
                    if let (Some(alias), Some(from)) = (c.get(1), c.get(2)) {
                        if names.iter().any(|n| n == from.as_str()) {
                            names.push(alias.as_str().to_string());
                        }
                    }
                }
                if let Some(m) = join_re.find(code) {
                    let args = &code[m.end()..];
                    if args.contains("Base(") {
                        continue;
                    }
                    if names.iter().any(|n| contains_identifier(args, n)) {
                        found.insert(start + offset + 1);
                    }
                }
            }
        }
        start = end;
    }
    found
}

#[allow(clippy::items_after_test_module)]
fn go_path_traversal_sink_lines(
    content: &str,
    extension: &str,
) -> std::collections::HashSet<usize> {
    if extension != "go" {
        return std::collections::HashSet::new();
    }

    let Ok(source) = Regex::new(
        r#"^\s*(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:\s+string)?\s*(?::=|=)\s*(?:r|req|request)\s*\.\s*(?:URL\s*\.\s*Query\s*\(\s*\)\s*\.\s*Get\s*\(|FormValue\s*\(|PostFormValue\s*\(|URL\s*\.\s*Path\b)"#,
    ) else {
        return std::collections::HashSet::new();
    };
    let Ok(binding) = Regex::new(
        r#"^\s*(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)?(?:\s+[A-Za-z_][A-Za-z0-9_.]*)?\s*(?::=|=)\s*([^=].*?)\s*$"#,
    ) else {
        return std::collections::HashSet::new();
    };
    let Ok(sink) = Regex::new(
        r#"\b(?:os\s*\.\s*(?:Open|OpenFile|ReadFile|WriteFile|Create)|ioutil\s*\.\s*(?:ReadFile|WriteFile)|http\s*\.\s*ServeFile)\s*\("#,
    ) else {
        return std::collections::HashSet::new();
    };

    let mut tainted: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut sink_lines = std::collections::HashSet::new();
    for (line_index, line) in content.lines().enumerate() {
        let code = line.trim();
        if code.is_empty()
            || code.starts_with("//")
            || code.starts_with("/*")
            || code.starts_with('*')
        {
            continue;
        }

        if let Some(name) = source
            .captures(code)
            .and_then(|captures| captures.get(1))
            .map(|capture| capture.as_str().to_string())
        {
            if !contains_go_path_sanitizer(code) {
                tainted.insert(name);
            }
            continue;
        }

        if let Some(captures) = binding.captures(code) {
            let lhs = captures.get(1).map(|capture| capture.as_str());
            let rhs = captures
                .get(2)
                .map(|capture| capture.as_str())
                .unwrap_or("");
            let derives_from_taint = tainted.iter().any(|name| identifier_in(rhs, name));
            if derives_from_taint && !contains_go_path_sanitizer(rhs) {
                if let Some(lhs) = lhs {
                    tainted.insert(lhs.to_string());
                }
            }
        }

        if sink.is_match(code)
            && tainted.iter().any(|name| identifier_in(code, name))
            && !contains_go_path_sanitizer(code)
        {
            sink_lines.insert(line_index + 1);
        }
    }
    sink_lines
}

#[allow(clippy::items_after_test_module)]
fn contains_go_path_sanitizer(text: &str) -> bool {
    text.contains("filepath.Base(") || text.contains("path.Base(")
}

#[allow(clippy::items_after_test_module)]
fn contains_python_path_sanitizer(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("os.path.basename")
        || lower.contains("path.basename")
        // `pathlib.Path(value).name` keeps only the final component, the same
        // guarantee `os.path.basename` gives.
        || (lower.contains("path(") && lower.contains(").name"))
}

/// Find JavaScript/TypeScript filesystem sinks reached by a request-path value.
///
/// This intentionally models only straight-line local bindings. It follows a request
/// source through direct aliases, string construction, and `path.join`/`path.resolve`,
/// but stops at `path.basename`, which reduces a path to one component. The narrow
/// model adds useful multi-line coverage without pretending to be interprocedural.
#[allow(clippy::items_after_test_module)]
fn js_path_traversal_sink_lines(
    content: &str,
    extension: &str,
) -> std::collections::HashSet<usize> {
    if !matches!(extension, "js" | "ts") {
        return std::collections::HashSet::new();
    }

    let Ok(source) = Regex::new(
        r#"(?i)^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:[A-Za-z_$][A-Za-z0-9_$]*\s*\(\s*)?(?:req|request)\.(?:params|query|body|headers|cookies)(?:\.[A-Za-z_$][A-Za-z0-9_$]*|\s*\[[^\]]+\])"#,
    ) else {
        return std::collections::HashSet::new();
    };
    let Ok(binding) =
        Regex::new(r#"(?i)^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(.+?);?\s*$"#)
    else {
        return std::collections::HashSet::new();
    };
    let Ok(sink) = Regex::new(
        r#"(?i)(?:\bfs\s*\.\s*)?(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)\s*\(|\.sendFile\s*\("#,
    ) else {
        return std::collections::HashSet::new();
    };

    let mut tainted: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut sink_lines = std::collections::HashSet::new();
    for (line_index, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
        {
            continue;
        }

        if let Some(name) = source
            .captures(line)
            .and_then(|captures| captures.get(1))
            .map(|capture| capture.as_str().to_string())
        {
            tainted.insert(name);
        }

        if let Some(captures) = binding.captures(line) {
            let lhs = captures.get(1).map(|capture| capture.as_str());
            let rhs = captures
                .get(2)
                .map(|capture| capture.as_str())
                .unwrap_or("");
            let derives_from_taint = tainted.iter().any(|name| identifier_in(rhs, name));
            if derives_from_taint && !rhs.to_ascii_lowercase().contains("path.basename") {
                if let Some(lhs) = lhs {
                    tainted.insert(lhs.to_string());
                }
            }
        }

        if sink.is_match(line)
            && tainted.iter().any(|name| identifier_in(line, name))
            && !line.to_ascii_lowercase().contains("path.basename")
        {
            sink_lines.insert(line_index + 1);
        }
    }
    sink_lines
}

#[allow(clippy::items_after_test_module)]
fn identifier_in(text: &str, identifier: &str) -> bool {
    Regex::new(&format!(r"\b{}\b", regex::escape(identifier)))
        .is_ok_and(|reference| reference.is_match(text))
}

/// Language family for the shared same-file request-flow engine.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FlowLanguage {
    JavaScript,
    Python,
    Java,
    Go,
    Rust,
}

#[allow(clippy::items_after_test_module)]
fn flow_language(extension: &str) -> Option<FlowLanguage> {
    match extension {
        "js" | "ts" => Some(FlowLanguage::JavaScript),
        "py" => Some(FlowLanguage::Python),
        "java" => Some(FlowLanguage::Java),
        "go" => Some(FlowLanguage::Go),
        "rs" => Some(FlowLanguage::Rust),
        _ => None,
    }
}

/// Blank out the contents of plain string literals so identifiers that only
/// appear inside quoted text are not mistaken for data flow. Interpolated
/// parts (`${...}` in JS template literals, `{...}` in Python f-strings) are
/// kept because they do carry values into the string.
#[allow(clippy::items_after_test_module)]
fn blank_plain_strings(text: &str, language: FlowLanguage) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        // Rust has no single-quoted strings (`'a` is a lifetime, `'x'` a
        // rare char literal); blanking on them would eat code.
        let is_quote = c == '"'
            || (c == '\'' && language != FlowLanguage::Rust)
            || (c == '`' && matches!(language, FlowLanguage::JavaScript | FlowLanguage::Go));
        if !is_quote {
            out.push(c);
            i += 1;
            continue;
        }
        let python_fstring = language == FlowLanguage::Python
            && i > 0
            && matches!(chars[i - 1], 'f' | 'F')
            && (i < 2
                || !(chars[i - 2].is_ascii_alphanumeric() || chars[i - 2] == '_')
                || matches!(chars[i - 2], 'r' | 'R'));
        let js_template = language == FlowLanguage::JavaScript && c == '`';
        // Rust `format!("{name}")`-family macro strings interpolate inline
        // `{ident}` arguments; keep those visible like f-string contents.
        let rust_format = language == FlowLanguage::Rust
            && c == '"'
            && i > 1
            && chars[i - 1] == '('
            && chars[i - 2] == '!'
            && i > 2
            && (chars[i - 3].is_ascii_alphanumeric() || chars[i - 3] == '_');
        out.push(c);
        i += 1;
        let mut depth = 0usize;
        while i < chars.len() {
            let ch = chars[i];
            if ch == '\\' && c != '`' {
                out.push(' ');
                i += 1;
                if i < chars.len() {
                    out.push(' ');
                    i += 1;
                }
                continue;
            }
            if depth == 0 && ch == c {
                break;
            }
            let opens = ((python_fstring || rust_format) && ch == '{')
                || (js_template && ch == '$' && chars.get(i + 1) == Some(&'{'));
            if opens {
                if js_template {
                    out.push(' ');
                    i += 1;
                }
                depth += 1;
                out.push(' ');
                i += 1;
                continue;
            }
            if depth > 0 && ch == '}' {
                depth -= 1;
                out.push(' ');
                i += 1;
                continue;
            }
            out.push(if depth > 0 { ch } else { ' ' });
            i += 1;
        }
        if i < chars.len() {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Split the argument list of the call whose opening parenthesis is at
/// `open` (a byte index into `text`) into top-level arguments.
#[allow(clippy::items_after_test_module)]
fn call_arguments(text: &str, open: usize) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    for ch in text[open + 1..].chars() {
        match ch {
            '(' | '[' | '{' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' | '}' if depth == 0 => {
                args.push(current.trim().to_string());
                return args;
            }
            ')' | ']' | '}' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                args.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    args.push(current.trim().to_string());
    args
}

/// True when the call whose argument list starts at `open` has no closing
/// bracket at depth zero before the end of `text`: the call's arguments
/// continue on later lines.
#[allow(clippy::items_after_test_module)]
fn call_unterminated(text: &str, open: usize) -> bool {
    let mut depth = 0usize;
    for ch in text[open + 1..].chars() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' if depth == 0 => return false,
            ')' | ']' | '}' => depth -= 1,
            _ => {}
        }
    }
    true
}

/// Join continuation lines onto an unterminated call's text so its argument
/// list can be read by `call_arguments`. Bounded at eight extra lines; each
/// continuation gets the same comment stripping and string blanking the flow
/// pass applies per line, so brackets inside string literals do not skew the
/// balance.
#[allow(clippy::items_after_test_module)]
fn extend_call_text(
    lines: &[&str],
    line_index: usize,
    visible: &str,
    language: FlowLanguage,
    open: usize,
) -> String {
    let balance = |text: &str| -> i32 {
        text.chars().fold(0, |acc, ch| match ch {
            '(' | '[' | '{' => acc + 1,
            ')' | ']' | '}' => acc - 1,
            _ => acc,
        })
    };
    let mut joined = visible.to_string();
    let mut open_brackets = balance(&visible[open..]);
    for next in lines.iter().skip(line_index + 1).take(8) {
        if open_brackets <= 0 {
            break;
        }
        let raw = if language == FlowLanguage::Python {
            next.split('#').next().unwrap_or("")
        } else {
            next
        };
        let code = raw.trim();
        if code.is_empty() {
            continue;
        }
        let blanked = blank_plain_strings(code, language);
        joined.push(' ');
        joined.push_str(&blanked);
        open_brackets += balance(&blanked);
    }
    joined
}

/// Request-input sources for each language, matching the ones proven in the
/// path-traversal flow models.
#[allow(clippy::items_after_test_module)]
fn flow_source_regex(language: FlowLanguage) -> Option<Regex> {
    let pattern = match language {
        FlowLanguage::JavaScript => {
            r#"(?i)^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:[A-Za-z_$][A-Za-z0-9_$]*\s*\(\s*)?(?:req|request)\.(?:params|query|body|headers|cookies)(?:\.[A-Za-z_$][A-Za-z0-9_$]*|\s*\[[^\]]+\])"#
        }
        FlowLanguage::Python => {
            r#"(?i)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:[A-Za-z_][A-Za-z0-9_.]*\s*\(\s*)?(?:request\.(?:args|form|values|GET|POST|headers|cookies|json|data)(?:\.get\s*\([^)]*\)|\s*\[[^\]]+\])|request\.path)"#
        }
        FlowLanguage::Java => {
            r#"(?i)^\s*(?:final\s+)?(?:[A-Za-z_][A-Za-z0-9_.<>\[\]]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:[A-Za-z_][A-Za-z0-9_.]*\s*\(\s*)?(?:req|request)\s*\.\s*(?:getParameter|getHeader|getPathInfo|getQueryString)\s*\("#
        }
        FlowLanguage::Go => {
            r#"^\s*(?:(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:\s+string)?\s*(?::=|=)\s*(?:(?:r|req|request)\s*\.\s*(?:URL\s*\.\s*Query\s*\(\s*\)\s*\.\s*Get\s*\(|FormValue\s*\(|PostFormValue\s*\(|URL\s*\.\s*Path\b)|(?:c|ctx)\s*\.\s*(?:Param|Query|DefaultQuery|QueryArray|PostForm|DefaultPostForm|PostFormArray|FormValue|QueryParam|GetHeader|Cookie)\s*\()|(?:if\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\s*:?=\s*)?(?:c|ctx)\s*\.\s*(?:Bind|BindJSON|BindQuery|BindUri|ShouldBind|ShouldBindJSON|ShouldBindQuery|ShouldBindUri|ShouldBindWith)\s*\(\s*&\s*([A-Za-z_][A-Za-z0-9_]*))"#
        }
        FlowLanguage::Rust => {
            r#"^\s*let\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^=]+)?=\s*(?:(?:req|request)\s*\.\s*(?:match_info|query_params|query_string|param|params)\s*\(|(?:params|query|form)\s*(?:\.\s*get\s*\(|\[))"#
        }
    };
    Regex::new(pattern).ok()
}

/// Unanchored request-read patterns, used to catch reads embedded inside a
/// larger expression (an f-string, template literal, or concatenation)
/// rather than at the start of a binding. Applied per expression (a binding
/// right-hand side or a single sink argument), never per line, so a read
/// passed as a separate parameter argument is not treated as embedded in
/// the query. Go covers the net/http receiver shapes (r/req/request); Gin
/// ctx reads inline are not modeled (binding-position reads already seed).
/// Rust extractor maps (params/query/form) require a string-literal key so
/// unrelated `.get(index)` / `[range]` uses on lookalike names stay clean.
#[allow(clippy::items_after_test_module)]
fn flow_inline_read_regex(language: FlowLanguage) -> Option<Regex> {
    let pattern = match language {
        FlowLanguage::Python => {
            r#"(?i)request\.(?:args|form|values|GET|POST|headers|cookies|json|data)(?:\.get\s*\([^)]*\)|\s*\[[^\]]+\])|request\.path"#
        }
        FlowLanguage::JavaScript => {
            r#"(?i)(?:req|request)\.(?:params|query|body|headers|cookies)(?:\.[A-Za-z_$][A-Za-z0-9_$]*|\s*\[[^\]]+\])"#
        }
        FlowLanguage::Java => {
            r#"(?i)(?:req|request)\s*\.\s*(?:getParameter|getHeader|getPathInfo|getQueryString)\s*\("#
        }
        FlowLanguage::Go => {
            r#"(?:r|req|request)\s*\.\s*(?:URL\s*\.\s*Query\s*\(\s*\)\s*\.\s*Get\s*\(|FormValue\s*\(|PostFormValue\s*\(|URL\s*\.\s*Path\b)"#
        }
        FlowLanguage::Rust => {
            r#"(?:req|request)\s*\.\s*(?:match_info|query_params|query_string|param|params)\s*\(|(?:params|query|form)\s*(?:\.\s*get\s*\(\s*"|\[\s*")"#
        }
    };
    Regex::new(pattern).ok()
}

/// Plain local bindings (`lhs = rhs`) for each language.
#[allow(clippy::items_after_test_module)]
fn flow_binding_regex(language: FlowLanguage) -> Option<Regex> {
    let pattern = match language {
        FlowLanguage::JavaScript => {
            r#"^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([^=].*?);?\s*$"#
        }
        FlowLanguage::Python => r#"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^=].*?)\s*$"#,
        FlowLanguage::Java => {
            r#"^\s*(?:final\s+)?(?:[A-Za-z_][A-Za-z0-9_.<>\[\]]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^=].*?);?\s*$"#
        }
        FlowLanguage::Go => {
            r#"^\s*(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)?(?:\s+[A-Za-z_][A-Za-z0-9_.]*)?\s*(?::=|=)\s*([^=].*?)\s*$"#
        }
        FlowLanguage::Rust => {
            r#"^\s*(?:let\s+(?:mut\s+)?)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^=]+)?=\s*([^=].*?);?\s*$"#
        }
    };
    Regex::new(pattern).ok()
}

/// A sink for the shared flow engine: a call pattern whose match ends at the
/// call's opening parenthesis, and which argument positions carry the
/// dangerous value.
struct FlowSink {
    call: Regex,
    arguments: FlowArguments,
    /// Optional whole-line condition checked against the raw code (string
    /// literals included), e.g. `shell=True` or a `"sh", "-c"` prefix.
    line_requires: Option<Regex>,
}

/// Maps a matched sink name to the argument positions that carry the
/// dangerous value.
type FlowArguments = fn(&str) -> Vec<usize>;

/// Straight-line, same-file request flow shared by the SQL injection,
/// command injection, and SSRF models.
///
/// Tracks request-input variables through direct aliases and string
/// construction, drops taint when a variable is rebound to a sanitized or
/// untainted value, and reports a sink line only when a tainted identifier
/// appears in one of the sink's dangerous argument positions. Plain string
/// literal contents are ignored so text that merely looks like a variable
/// name does not count.
///
/// On top of that straight-line pass, calls to functions defined in the same
/// file are followed: when a tainted argument is passed in a parameter
/// position whose value reaches a sink inside the callee (directly or through
/// further same-file calls), the callee's sink line is reported as well. See
/// [`flow_functions`] for which definitions and calls are recognized. This
/// does not follow branches, dynamic dispatch, or other files.
#[allow(clippy::items_after_test_module)]
fn request_flow_sink_lines(
    content: &str,
    language: FlowLanguage,
    sinks: &[FlowSink],
    sanitized: fn(&str) -> bool,
    mongo_where: bool,
) -> std::collections::HashSet<usize> {
    let lines: Vec<&str> = content.lines().collect();
    let functions = flow_functions(&lines, language);
    let summaries = flow_summaries(&lines, language, sinks, sanitized, mongo_where, &functions);
    let calls = FlowCalls {
        functions: &functions,
        summaries: &summaries,
        imports: &[],
    };
    let (mut sink_lines, callee_sink_lines, _) = flow_pass(
        &lines,
        0..lines.len(),
        language,
        sinks,
        sanitized,
        mongo_where,
        &[],
        true,
        Some(&calls),
    );
    sink_lines.extend(callee_sink_lines);
    for (body, seeds) in spring_annotated_seeds(&lines, language, &functions)
        .into_iter()
        .chain(python_route_seeds(&lines, language, &functions))
    {
        let (seeded, seeded_callee, _) = flow_pass(
            &lines,
            body,
            language,
            sinks,
            sanitized,
            mongo_where,
            &seeds,
            true,
            Some(&calls),
        );
        sink_lines.extend(seeded);
        sink_lines.extend(seeded_callee);
    }
    sink_lines
}

/// A function defined in the file, as seen by the interprocedural pass.
struct FlowFunction {
    name: String,
    params: Vec<String>,
    /// Line index of the definition header.
    header: usize,
    /// First line index after the signature: `header + 1` for a single-line
    /// header, or the line after a multi-line signature's opening brace.
    signature_end: usize,
    /// Line indices of the function body.
    body: std::ops::Range<usize>,
    /// Methods are only resolved through `this.` / `self.` (JS, Python).
    method: bool,
}

/// For each function (by index) and parameter position, the sink lines a
/// value passed in that position reaches.
type FlowSummaries = Vec<Vec<std::collections::HashSet<usize>>>;

struct FlowCalls<'a> {
    functions: &'a [FlowFunction],
    summaries: &'a FlowSummaries,
    /// Functions in other project files reachable through this file's imports.
    imports: &'a [ImportedCallee],
}

/// A function in another project file that a call in this file can resolve
/// to through an import.
struct ImportedCallee {
    /// Module binding for `binding.name(...)` calls; `None` for a function
    /// imported by name and called bare.
    receiver: Option<String>,
    /// Name used at the call site.
    name: String,
    /// Index of the file that defines the function.
    target: usize,
    /// Parameter count of the target function.
    params: usize,
    /// Per parameter, the `(file index, sink line)` pairs a value passed in
    /// that position reaches. Pairs point at the defining file of each
    /// sink, so a callee whose own imports forward the value onward
    /// contributes sink lines in those files as well.
    summaries: Vec<std::collections::HashSet<(usize, usize)>>,
}

/// Compute parameter-to-sink summaries for every recognized function. Each
/// parameter is seeded as the only tainted value and the function body is
/// run through the same flow pass; calls to other same-file functions use the
/// summaries from the previous round, so helper chains resolve over a
/// bounded number of rounds.
#[allow(clippy::items_after_test_module)]
fn flow_summaries(
    lines: &[&str],
    language: FlowLanguage,
    sinks: &[FlowSink],
    sanitized: fn(&str) -> bool,
    mongo_where: bool,
    functions: &[FlowFunction],
) -> FlowSummaries {
    let mut summaries: FlowSummaries = functions
        .iter()
        .map(|function| vec![std::collections::HashSet::new(); function.params.len()])
        .collect();
    for _ in 0..functions.len().max(6) {
        let calls = FlowCalls {
            functions,
            summaries: &summaries,
            imports: &[],
        };
        let next: FlowSummaries = functions
            .iter()
            .map(|function| {
                function
                    .params
                    .iter()
                    .map(|param| {
                        let (mut reached, via_calls, _) = flow_pass(
                            lines,
                            function.body.clone(),
                            language,
                            sinks,
                            sanitized,
                            mongo_where,
                            std::slice::from_ref(param),
                            false,
                            Some(&calls),
                        );
                        reached.extend(via_calls);
                        reached
                    })
                    .collect()
            })
            .collect();
        if next == summaries {
            break;
        }
        summaries = next;
    }
    summaries
}

/// Flask route captures and Django view keyword arguments enter the view
/// already attacker-controlled from the URL pattern, mirroring
/// `spring_annotated_seeds` for Python. A `@<something>.route(".../<name>")`
/// decorator in the few lines above the function seeds the named parameter
/// unless its converter renders a canonical safe type (`int`, `float`,
/// `uuid`). Any function whose first parameter is literally `request` is
/// treated as a Django-style view, seeding the remaining parameters (URL
/// captures); Flask's global `request` object needs no seeding.
#[allow(clippy::items_after_test_module)]
fn python_route_seeds(
    lines: &[&str],
    language: FlowLanguage,
    functions: &[FlowFunction],
) -> Vec<(std::ops::Range<usize>, Vec<String>)> {
    if language != FlowLanguage::Python {
        return Vec::new();
    }
    let Ok(route) = Regex::new(r#"@[A-Za-z_][A-Za-z0-9_.]*\.route\s*\(\s*['\"]([^'\"]*)['\"]"#)
    else {
        return Vec::new();
    };
    let Ok(capture) = Regex::new(r"<(?:([A-Za-z_][A-Za-z0-9_]*):)?([A-Za-z_][A-Za-z0-9_]*)>")
    else {
        return Vec::new();
    };
    functions
        .iter()
        .filter(|function| !function.params.is_empty())
        .filter_map(|function| {
            let mut seeds: Vec<String> = Vec::new();
            let window_start = function.header.saturating_sub(5);
            for line in &lines[window_start..function.header] {
                if let Some(pattern) = route.captures(line).and_then(|c| c.get(1)) {
                    for cap in capture.captures_iter(pattern.as_str()) {
                        let converter = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                        let name = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                        if !matches!(converter, "int" | "float" | "uuid")
                            && function.params.iter().any(|param| param == name)
                        {
                            seeds.push(name.to_string());
                        }
                    }
                }
            }
            if function
                .params
                .first()
                .is_some_and(|param| param == "request")
            {
                seeds.extend(function.params[1..].iter().cloned());
            }
            (!seeds.is_empty()).then(|| (function.body.clone(), seeds))
        })
        .collect()
}

