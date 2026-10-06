/// Spring-style handler parameters (`@RequestParam`, `@PathVariable`,
/// `@RequestBody`, and friends) enter the controller already
/// attacker-controlled at the framework boundary. Returns each annotated
/// Java function's body range with its parameter names, so callers can run
/// an extra seeded pass. Only single-line headers are considered (the same
/// headers `flow_functions` parses); parameter annotations on their own
/// line are a documented gap.
#[allow(clippy::items_after_test_module)]
fn spring_annotated_seeds(
    lines: &[&str],
    language: FlowLanguage,
    functions: &[FlowFunction],
) -> Vec<(std::ops::Range<usize>, Vec<String>)> {
    if language != FlowLanguage::Java {
        return Vec::new();
    }
    // Extract only the parameter names an annotation directly marks, from the
    // whole signature window (the header line through the line before the
    // body), so annotated parameters on their own lines are seeded and an
    // unannotated parameter on the same line is not tainted by association.
    let Ok(annotated_param) = Regex::new(
        r"@(?:RequestParam|PathVariable|RequestBody|RequestHeader|ModelAttribute|CookieValue)\b\s*(?:\([^()]*\))?\s*(?:final\s+)?[A-Za-z_][A-Za-z0-9_.<>\[\], ?]*?\s+([A-Za-z_$][A-Za-z0-9_$]*)",
    ) else {
        return Vec::new();
    };
    functions
        .iter()
        .filter(|function| !function.params.is_empty())
        .filter_map(|function| {
            let seeds: Vec<String> = lines[function.header..function.signature_end]
                .iter()
                .flat_map(|line| {
                    annotated_param
                        .captures_iter(line)
                        .filter_map(|captures| {
                            captures.get(1).map(|name| name.as_str().to_string())
                        })
                        .collect::<Vec<_>>()
                })
                .collect();
            (!seeds.is_empty()).then(|| (function.body.clone(), seeds))
        })
        .collect()
}

/// Report only a request-selected object accessed by an unguarded HTTP
/// handler. A repository helper, lookup in a test, or bare `findById` is not
/// evidence that an object was returned to an unauthorized caller. This
/// deliberately leaves unresolved cross-file ownership checks unreported.
#[allow(clippy::items_after_test_module)]
fn idor_sink_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    let Some(language @ (FlowLanguage::Java | FlowLanguage::JavaScript | FlowLanguage::Python)) =
        flow_language(extension)
    else {
        return std::collections::HashSet::new();
    };
    let Ok(call) = Regex::new(
        r"\b(?:[A-Za-z_][A-Za-z0-9_]*(?:Repository|Model)|[A-Z][A-Za-z0-9_]*|db)\s*\.\s*(?i:findById|getById|find_by_id|get_by_id|find_by_pk)\s*\(",
    ) else {
        return std::collections::HashSet::new();
    };
    let tainted_lookups = request_flow_sink_lines(
        content,
        language,
        &[FlowSink {
            call,
            arguments: first_argument,
            line_requires: None,
        }],
        |_| false,
        false,
    );
    if tainted_lookups.is_empty() {
        return tainted_lookups;
    }
    let lines: Vec<&str> = content.lines().collect();
    let functions = flow_functions(&lines, language);
    let Ok(route) = Regex::new(
        r"(?i)@(?:GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping|(?:app|router)\.route)\b|\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete)\s*\(|\b(?:exports\.|module\.exports\.)[A-Za-z_][A-Za-z0-9_]*\s*=",
    ) else {
        return std::collections::HashSet::new();
    };
    let Ok(guard) = Regex::new(
        r"(?i)\b(?:canWrite\w*|canRead\w*|hasPermission|isAuthorized|authorize\w*|checkPermission|checkOwnership|isOwner|ownerId|owner_id|userId\s*===|user_id\s*==|currentUser\s*\.\s*id\s*==|current_user\s*\.\s*id\s*==)\b",
    ) else {
        return std::collections::HashSet::new();
    };
    let Ok(exposure) = Regex::new(
        r"(?i)\b(?:ResponseEntity\s*\.\s*ok|res\s*\.\s*(?:json|send|render)|jsonify|return\s+\w+|\w+Repository\s*\.\s*(?:remove|delete|save|update)|\w+\.delete\s*\()",
    ) else {
        return std::collections::HashSet::new();
    };
    // Express-style exported arrow handlers are not in flow_functions, but
    // request_flow_sink_lines still traces their local request reads.
    let js_handlers: Vec<std::ops::Range<usize>> = if language == FlowLanguage::JavaScript {
        lines
            .iter()
            .enumerate()
            .filter(|(_, text)| route.is_match(text) && text.contains("=>") && text.contains('{'))
            .filter_map(|(start, _)| {
                let mut depth = 0i64;
                for (index, text) in lines.iter().enumerate().skip(start) {
                    let code = blank_plain_strings(text, language);
                    depth += code.matches('{').count() as i64 - code.matches('}').count() as i64;
                    if depth == 0 {
                        return Some(start..index + 1);
                    }
                }
                None
            })
            .collect()
    } else {
        Vec::new()
    };
    tainted_lookups
        .into_iter()
        .filter(|&line| {
            let index = line - 1;
            let js_access = js_handlers.iter().any(|handler| {
                handler.contains(&index) && {
                    let body = lines[handler.clone()].join(" ");
                    !guard.is_match(&body) && exposure.is_match(&body)
                }
            });
            js_access
                || functions.iter().any(|function| {
                    if !function.body.contains(&index) {
                        return false;
                    }
                    let preceding = function.header.saturating_sub(3);
                    let header = lines[preceding..function.signature_end].join(" ");
                    if !route.is_match(&header) {
                        return false;
                    }
                    let body = lines[function.body.clone()].join(" ");
                    // An explicit guard in this handler defeats a speculative
                    // missing-check finding. The check can follow the lookup.
                    !guard.is_match(&body) && exposure.is_match(&body)
                })
        })
        .collect()
}

/// Template name/source is the first argument. Values supplied as render
/// context are data, not template programs. Route parameters and request
/// reads reach these sinks through the shared flow pass, while fixed names
/// and finite local allowlists stay untainted.
#[allow(clippy::items_after_test_module)]
fn ssti_sink_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    let Some(language @ (FlowLanguage::JavaScript | FlowLanguage::Python)) =
        flow_language(extension)
    else {
        return std::collections::HashSet::new();
    };
    let call = match language {
        FlowLanguage::JavaScript => {
            r"\b(?:res|response|pug|ejs|handlebars)\s*\.\s*(?:render|compile)\s*\("
        }
        FlowLanguage::Python => {
            r"\b(?:render_template|render_template_string|Template|from_string|render_to_string)\s*\("
        }
        _ => unreachable!(),
    };
    let Ok(call) = Regex::new(call) else {
        return std::collections::HashSet::new();
    };
    request_flow_sink_lines(
        content,
        language,
        &[FlowSink {
            call,
            arguments: first_argument,
            line_requires: None,
        }],
        |_| false,
        false,
    )
}

/// Go HTML writes require an HTML response and a request-derived interpolation.
#[allow(clippy::items_after_test_module)]
fn go_html_xss_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    if extension != "go" || !content.contains("text/html") {
        return std::collections::HashSet::new();
    }
    let Ok(call) = Regex::new(r"\bfmt\.Fprintf\s*\(") else {
        return std::collections::HashSet::new();
    };
    let Ok(html) = Regex::new(r#"(?i)<(?:html|body|h[1-6]|div|p|span|script|a)\b"#) else {
        return std::collections::HashSet::new();
    };
    let candidates = request_flow_sink_lines(
        content,
        FlowLanguage::Go,
        &[FlowSink {
            call,
            arguments: go_format_argument,
            line_requires: Some(html),
        }],
        contains_go_html_escape,
        false,
    );
    candidates
        .into_iter()
        .filter(|line| {
            let lines: Vec<&str> = content.lines().collect();
            lines[..*line]
                .iter()
                .rev()
                .take_while(|s| !s.trim_start().starts_with("func "))
                .any(|s| s.contains("Content-Type") && s.contains("text/html"))
        })
        .collect()
}

#[allow(clippy::items_after_test_module)]
fn go_format_argument(_name: &str) -> Vec<usize> {
    vec![2, 3, 4, 5, 6]
}

#[allow(clippy::items_after_test_module)]
fn contains_go_html_escape(text: &str) -> bool {
    text.contains("html.EscapeString(") || text.contains("template.HTMLEscapeString(")
}

#[allow(clippy::items_after_test_module)]
fn go_xpath_sink_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    if extension != "go" {
        return std::collections::HashSet::new();
    }
    let Ok(call) = Regex::new(r"\bxmlquery\.Find\s*\(") else {
        return std::collections::HashSet::new();
    };
    request_flow_sink_lines(
        content,
        FlowLanguage::Go,
        &[FlowSink {
            call,
            arguments: go_second_argument,
            line_requires: None,
        }],
        |_| false,
        false,
    )
}

#[allow(clippy::items_after_test_module)]
fn go_second_argument(_name: &str) -> Vec<usize> {
    vec![1]
}

#[allow(clippy::items_after_test_module)]
fn go_template_source_sink_lines(
    content: &str,
    extension: &str,
) -> std::collections::HashSet<usize> {
    if extension != "go" || !content.contains("template") {
        return std::collections::HashSet::new();
    }
    let Ok(call) = Regex::new(r"\btemplate\.New\s*\([^)]*\)\s*\.\s*Parse\s*\(") else {
        return std::collections::HashSet::new();
    };
    request_flow_sink_lines(
        content,
        FlowLanguage::Go,
        &[FlowSink {
            call,
            arguments: first_argument,
            line_requires: None,
        }],
        |_| false,
        false,
    )
}

/// Only the raw header construction counts: envelope recipients and body data do not.
#[allow(clippy::items_after_test_module)]
/// A jwt.Parse/jwt.ParseWithClaims call in a file that never validates the
/// token's signing method accepts alg=none and algorithm-confusion tokens
/// (the key function is invoked for every algorithm). Files that pin the
/// method via the standard type assertion or jwt.WithValidMethods are
/// suppressed.
fn go_jwt_unpinned_parse_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    let mut found = std::collections::HashSet::new();
    if extension != "go" || !content.contains("jwt.Parse") {
        return found;
    }
    if content.contains("token.Method.(*jwt.SigningMethod") || content.contains("WithValidMethods")
    {
        return found;
    }
    for (index, line) in content.lines().enumerate() {
        let text = line.trim_start();
        if text.starts_with("//") {
            continue;
        }
        if text.contains("jwt.Parse(") || text.contains("jwt.ParseWithClaims(") {
            found.insert(index + 1);
        }
    }
    found
}

fn go_email_header_sink_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    if extension != "go" || !content.contains("smtp.SendMail(") {
        return std::collections::HashSet::new();
    }
    let Some(source) = flow_source_regex(FlowLanguage::Go) else {
        return std::collections::HashSet::new();
    };
    let Ok(header) = Regex::new(
        r#"^\s*"(?:To|Subject|Cc|Bcc|Reply-To|From):\s*"\s*\+\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+"#,
    ) else {
        return std::collections::HashSet::new();
    };
    let mut tainted = std::collections::HashSet::new();
    let mut found = std::collections::HashSet::new();
    for (index, line) in content.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        if line.trim_start().starts_with("func ") {
            tainted.clear();
        }
        if let Some(name) = source.captures(line).and_then(|c| c.get(1)) {
            tainted.insert(name.as_str().to_string());
        }
        if let Some(value) = header.captures(line).and_then(|c| c.get(1)) {
            if tainted.contains(value.as_str()) {
                found.insert(index + 1);
            }
        }
    }
    found
}

/// Python `a, b, c = f(...)`: two or more plain names unpacked from one call.
/// A right side with a top-level comma (`a, b = x, y`) is a pairwise
/// assignment, not an unpack, and is left to the single-name binding rule.
fn python_call_tuple_unpack(line: &str) -> Option<(Vec<String>, &str)> {
    let (left, right) = line.split_once('=')?;
    if right.starts_with('=') || left.ends_with(['!', '<', '>', '=', '+', '-', '*', '/', '%']) {
        return None;
    }
    let left = left.trim().trim_start_matches('(').trim_end_matches(')');
    let names: Vec<&str> = left.split(',').map(str::trim).collect();
    if names.len() < 2
        || !names.iter().all(|name| {
            !name.is_empty()
                && name
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                && !name.starts_with(|ch: char| ch.is_ascii_digit())
        })
    {
        return None;
    }
    let right = right.trim();
    let open = right.find('(')?;
    let callee = &right[..open];
    if callee.is_empty()
        || !callee
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '.')
        || !right.ends_with(')')
    {
        return None;
    }
    let mut depth = 0i32;
    for (index, ch) in right.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 && index + 1 != right.len() {
                    return None;
                }
            }
            _ => {}
        }
    }
    Some((names.into_iter().map(str::to_string).collect(), right))
}

/// One flow pass over `range`. Returns the sink lines reached directly, the
/// callee sink lines reached through same-file calls, and `(file index, sink
/// line)` pairs reached through calls into imported functions.
#[allow(clippy::items_after_test_module, clippy::too_many_arguments)]
fn flow_pass(
    lines: &[&str],
    range: std::ops::Range<usize>,
    language: FlowLanguage,
    sinks: &[FlowSink],
    sanitized: fn(&str) -> bool,
    mongo_where: bool,
    seeds: &[String],
    track_sources: bool,
    calls: Option<&FlowCalls>,
) -> (
    std::collections::HashSet<usize>,
    std::collections::HashSet<usize>,
    Vec<(usize, usize)>,
) {
    let mut sink_lines = std::collections::HashSet::new();
    let mut callee_sink_lines = std::collections::HashSet::new();
    let mut imported_sink_lines = Vec::new();
    let (Some(source), Some(binding)) = (flow_source_regex(language), flow_binding_regex(language))
    else {
        return (sink_lines, callee_sink_lines, imported_sink_lines);
    };
    let inline_read = flow_inline_read_regex(language);
    let destructure = Regex::new(
        r#"^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:req|request)\s*\.\s*(?:params|query|body|headers|cookies)\s*;?\s*$"#,
    )
    .ok();

    let mut tainted: std::collections::HashSet<String> = seeds.iter().cloned().collect();
    let mut destructuring_names: Option<String> = None;
    let mut in_block_comment = false;
    for line_index in range {
        let Some(line) = lines.get(line_index) else {
            break;
        };
        let raw = if language == FlowLanguage::Python {
            line.split('#').next().unwrap_or("")
        } else {
            line
        };
        let code = raw.trim();
        if language == FlowLanguage::JavaScript {
            if in_block_comment {
                if code.contains("*/") {
                    in_block_comment = false;
                }
                continue;
            }
            if code.starts_with("/*") {
                in_block_comment = !code.contains("*/");
                continue;
            }
        }
        if code.is_empty()
            || code.starts_with("//")
            || code.starts_with("/*")
            || code.starts_with('*')
        {
            continue;
        }

        if track_sources && language == FlowLanguage::JavaScript {
            if let Some(names) = destructuring_names.as_mut() {
                names.push(' ');
                names.push_str(code);
                if names.contains('}') {
                    if let Some(captures) = destructure.as_ref().and_then(|re| re.captures(names)) {
                        if let Some(members) = captures.get(1) {
                            for part in members.as_str().split(',') {
                                let local = part
                                    .split('=')
                                    .next()
                                    .unwrap_or("")
                                    .rsplit(':')
                                    .next()
                                    .unwrap_or("")
                                    .trim();
                                if !local.is_empty() {
                                    tainted.insert(local.to_string());
                                }
                            }
                        }
                    }
                    destructuring_names = None;
                }
                continue;
            }
            if code.contains('{')
                && !code.contains('}')
                && (code.trim_start().starts_with("const {")
                    || code.trim_start().starts_with("let {")
                    || code.trim_start().starts_with("var {"))
            {
                destructuring_names = Some(code.to_string());
                continue;
            }
            if let Some(names) = destructure
                .as_ref()
                .and_then(|re| re.captures(code))
                .and_then(|captures| captures.get(1))
            {
                for part in names.as_str().split(',') {
                    let local = part.split('=').next().unwrap_or("");
                    let local = local.rsplit(':').next().unwrap_or("").trim();
                    if !local.is_empty()
                        && local
                            .chars()
                            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
                    {
                        tainted.insert(local.to_string());
                    }
                }
                continue;
            }
        }

        if track_sources {
            if let Some(name) = source
                .captures(code)
                .and_then(|captures| captures.get(1).or_else(|| captures.get(2)))
                .map(|capture| capture.as_str().to_string())
            {
                if sanitized(code) {
                    tainted.remove(&name);
                } else {
                    tainted.insert(name);
                }
                continue;
            }
        }

        let visible = blank_plain_strings(code, language);
        let tuple_unpack = if language == FlowLanguage::Python {
            python_call_tuple_unpack(&visible)
        } else {
            None
        };
        if let Some((names, rhs)) = tuple_unpack {
            // `a, b = f(tainted)`: every unpacked name carries the call's taint.
            let derives = tainted.iter().any(|name| identifier_in(rhs, name))
                || inline_read.as_ref().is_some_and(|re| re.is_match(rhs));
            for name in names {
                if derives && !sanitized(rhs) {
                    tainted.insert(name);
                } else {
                    tainted.remove(&name);
                }
            }
        } else if let Some(captures) = binding.captures(&visible) {
            if let (Some(lhs), Some(rhs)) = (captures.get(1), captures.get(2)) {
                let rhs = rhs.as_str();
                let derives = tainted.iter().any(|name| identifier_in(rhs, name))
                    || inline_read.as_ref().is_some_and(|re| re.is_match(rhs));
                if derives && !sanitized(rhs) {
                    tainted.insert(lhs.as_str().to_string());
                } else {
                    tainted.remove(lhs.as_str());
                }
            }
        }
        if tainted.is_empty() && !inline_read.as_ref().is_some_and(|re| re.is_match(code)) {
            continue;
        }

        let reaches_mongo_where = mongo_where
            && language == FlowLanguage::JavaScript
            && code.contains("$where")
            && (tainted.iter().any(|name| identifier_in(code, name))
                || inline_read.as_ref().is_some_and(|re| re.is_match(code)));
        let reaches_sink = reaches_mongo_where
            || sinks.iter().any(|sink| {
                if sink
                    .line_requires
                    .as_ref()
                    .is_some_and(|required| !required.is_match(code))
                {
                    return false;
                }
                sink.call.captures_iter(&visible).any(|captures| {
                    let Some(whole) = captures.get(0) else {
                        return false;
                    };
                    let name = captures.get(1).map(|m| m.as_str()).unwrap_or("");
                    let open = whole.end() - 1;
                    let extended;
                    let text = if call_unterminated(&visible, open) {
                        extended = extend_call_text(lines, line_index, &visible, language, open);
                        extended.as_str()
                    } else {
                        visible.as_str()
                    };
                    let args = call_arguments(text, open);
                    (sink.arguments)(name).into_iter().any(|position| {
                        args.get(position).is_some_and(|arg| {
                            !sanitized(arg)
                                && (tainted.iter().any(|name| identifier_in(arg, name))
                                    || inline_read.as_ref().is_some_and(|re| re.is_match(arg)))
                        })
                    })
                })
            });
        if reaches_sink {
            sink_lines.insert(line_index + 1);
        }

        if let Some(calls) = calls {
            for (function_index, args) in
                same_file_calls(&visible, lines, line_index, language, calls)
            {
                let Some(params) = calls.summaries.get(function_index) else {
                    continue;
                };
                for (position, arg) in args.iter().enumerate() {
                    let carries_taint =
                        !sanitized(arg) && tainted.iter().any(|name| identifier_in(arg, name));
                    if carries_taint {
                        if let Some(reached) = params.get(position) {
                            callee_sink_lines.extend(reached.iter().copied());
                        }
                    }
                }
            }
            for (import_index, args) in imported_calls(&visible, lines, line_index, language, calls)
            {
                let callee = &calls.imports[import_index];
                for (position, arg) in args.iter().enumerate() {
                    let carries_taint =
                        !sanitized(arg) && tainted.iter().any(|name| identifier_in(arg, name));
                    if carries_taint {
                        if let Some(reached) = callee.summaries.get(position) {
                            imported_sink_lines.extend(reached.iter().copied());
                        }
                    }
                }
            }
        }
    }
    (sink_lines, callee_sink_lines, imported_sink_lines)
}

/// Arguments of the call whose `(` is at `open`. A call that continues on the
/// following lines is joined first, the same way sink calls are read.
fn wrapped_call_arguments(
    lines: &[&str],
    line_index: usize,
    visible: &str,
    language: FlowLanguage,
    open: usize,
) -> Vec<String> {
    if call_unterminated(visible, open) {
        let extended = extend_call_text(lines, line_index, visible, language, open);
        call_arguments(&extended, open)
    } else {
        call_arguments(visible, open)
    }
}

/// Calls on one line that resolve to an imported function: `binding.name(...)`
/// for a module binding, or a bare `name(...)` for a function imported by
/// name. A same-file definition with the same name shadows the import.
/// `this.repo.name(...)` / `self.repo.name(...)` resolve when the
/// instance variable was assigned an imported class (`new Repo(...)` for
/// JS, `Repo(...)` or `repo.Repo(...)` for Python). Longer receiver
/// chains, keyword or spread arguments, and extra arguments are
/// skipped.
#[allow(clippy::items_after_test_module)]
fn imported_calls(
    visible: &str,
    lines: &[&str],
    line_index: usize,
    language: FlowLanguage,
    calls: &FlowCalls,
) -> Vec<(usize, Vec<String>)> {
    let mut found = Vec::new();
    if calls.imports.is_empty() {
        return found;
    }
    let Ok(call) = Regex::new(r#"([A-Za-z_$][A-Za-z0-9_$]*)\s*\("#) else {
        return found;
    };
    let keyword_argument = Regex::new(r#"^[A-Za-z_][A-Za-z0-9_]*\s*=[^=]"#).ok();
    let is_word = |ch: char| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$';
    for captures in call.captures_iter(visible) {
        let (Some(whole), Some(name)) = (captures.get(0), captures.get(1)) else {
            continue;
        };
        let before = visible[..name.start()].trim_end();
        let receiver = if language == FlowLanguage::Rust && before.ends_with("::") {
            let rest = before[..before.len() - 2].trim_end();
            let segments: Vec<&str> = rest.split("::").map(str::trim).collect();
            // `a::f(...)` resolves through a module binding; `a::b::f(...)`
            // and longer chains resolve through nested hops when each
            // module declares the next.
            if segments.is_empty()
                || segments
                    .iter()
                    .any(|word| word.is_empty() || !word.chars().all(&is_word))
            {
                continue;
            }
            Some(segments.join("::"))
        } else {
            match before.strip_suffix('.') {
                Some(rest) => {
                    let rest = rest.trim_end();
                    let word: String = rest
                        .rsplit(|ch: char| !is_word(ch))
                        .next()
                        .unwrap_or("")
                        .to_string();
                    if word.is_empty() {
                        continue;
                    }
                    let ahead = rest[..rest.len() - word.len()].trim_end();
                    if let Some(stripped) = ahead.strip_suffix('.') {
                        // One instance-variable hop: `this.repo.find(...)`
                        // / `self.repo.find(...)`. Longer chains stay
                        // unresolved.
                        if language != FlowLanguage::JavaScript && language != FlowLanguage::Python
                        {
                            continue;
                        }
                        let owner = stripped
                            .trim_end()
                            .rsplit(|ch: char| !is_word(ch))
                            .next()
                            .unwrap_or("");
                        if owner != "this" && owner != "self" {
                            continue;
                        }
                        Some(format!("{owner}.{word}"))
                    } else {
                        Some(word)
                    }
                }
                None => {
                    if before.chars().last().is_some_and(is_word) {
                        let keyword: String = before
                            .rsplit(|ch: char| !is_word(ch))
                            .next()
                            .unwrap_or("")
                            .to_string();
                        if keyword != "return" && keyword != "await" {
                            continue;
                        }
                    }
                    if calls
                        .functions
                        .iter()
                        .any(|function| function.name == name.as_str())
                    {
                        continue;
                    }
                    None
                }
            }
        };
        let Some(import_index) = calls
            .imports
            .iter()
            .position(|callee| callee.receiver == receiver && callee.name == name.as_str())
        else {
            continue;
        };
        let args = wrapped_call_arguments(lines, line_index, visible, language, whole.end() - 1);
        let args: Vec<String> = if args.len() == 1 && args[0].is_empty() {
            Vec::new()
        } else {
            args
        };
        let unsupported = args.len() > calls.imports[import_index].params
            || args.iter().any(|arg| {
                arg.starts_with('*')
                    || arg.starts_with("...")
                    || keyword_argument
                        .as_ref()
                        .is_some_and(|re| language == FlowLanguage::Python && re.is_match(arg))
            });
        if unsupported {
            continue;
        }
        found.push((import_index, args));
    }
    found
}

/// Calls on one line that resolve to a recognized same-file function,
/// with their positional arguments. A bare `name(...)` resolves to a
/// function (in Java, also to a method of the file); `this.name(...)` /
/// `self.name(...)` resolves to a method. Calls on any other receiver, calls
/// with keyword, spread, or extra arguments, and the definition header
/// itself are skipped.
#[allow(clippy::items_after_test_module)]
fn same_file_calls(
    visible: &str,
    lines: &[&str],
    line_index: usize,
    language: FlowLanguage,
    calls: &FlowCalls,
) -> Vec<(usize, Vec<String>)> {
    let mut found = Vec::new();
    let Ok(call) = Regex::new(r#"([A-Za-z_$][A-Za-z0-9_$]*)\s*\("#) else {
        return found;
    };
    let keyword_argument = Regex::new(r#"^[A-Za-z_][A-Za-z0-9_]*\s*=[^=]"#).ok();
    for captures in call.captures_iter(visible) {
        let (Some(whole), Some(name)) = (captures.get(0), captures.get(1)) else {
            continue;
        };
        let Some(function_index) = calls
            .functions
            .iter()
            .position(|function| function.name == name.as_str())
        else {
            continue;
        };
        let function = &calls.functions[function_index];
        if function.header == line_index {
            continue;
        }
        let before = visible[..name.start()].trim_end();
        let is_word = |ch: char| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$';
        let last_word = |text: &str| -> String {
            text.rsplit(|ch: char| !is_word(ch))
                .next()
                .unwrap_or("")
                .to_string()
        };
        if before.chars().last().is_some_and(is_word) {
            // `function name(`, `def name(`, `new name(` and similar are not
            // calls; `return name(` and `await name(` are.
            let keyword = last_word(before);
            if keyword != "return" && keyword != "await" {
                continue;
            }
        }
        // For `recv.name(`: the receiver word, and whether the receiver is
        // itself reached through another `.` (e.g. `other.this.name(`).
        let receiver = before.strip_suffix('.').map(|rest| {
            let rest = rest.trim_end();
            let word = last_word(rest);
            let chained = rest[..rest.len() - word.len()].trim_end().ends_with('.');
            (word, chained)
        });
        let resolves = match (&receiver, language) {
            (None, FlowLanguage::Java) => true,
            (None, _) => !function.method,
            (Some((word, chained)), FlowLanguage::JavaScript) => {
                word == "this" && !chained && function.method
            }
            (Some((word, chained)), FlowLanguage::Java) => word == "this" && !chained,
            (Some((word, chained)), FlowLanguage::Python) => {
                word == "self" && !chained && function.method
            }
            (Some((word, chained)), FlowLanguage::Rust) if word == "self" && !chained => {
                function.method
            }
            (Some(_), FlowLanguage::Go | FlowLanguage::Rust) => false,
        };
        if !resolves {
            continue;
        }
        let args = wrapped_call_arguments(lines, line_index, visible, language, whole.end() - 1);
        let args: Vec<String> = if args.len() == 1 && args[0].is_empty() {
            Vec::new()
        } else {
            args
        };
        let unsupported = args.len() > function.params.len()
            || args.iter().any(|arg| {
                arg.starts_with('*')
                    || arg.starts_with("...")
                    || keyword_argument
                        .as_ref()
                        .is_some_and(|re| language == FlowLanguage::Python && re.is_match(arg))
            });
        if unsupported {
            continue;
        }
        found.push((function_index, args));
    }
    found
}

