fn flow_imports(
    lines: &[&str],
    language: FlowLanguage,
    path: &Path,
    root: &Path,
    index_of: &std::collections::HashMap<std::path::PathBuf, usize>,
) -> Vec<ImportBinding> {
    let mut bindings = Vec::new();
    let Some(dir) = path.parent() else {
        return bindings;
    };
    let lookup = |candidate: std::path::PathBuf| {
        std::fs::canonicalize(candidate)
            .ok()
            .and_then(|canonical| index_of.get(&canonical).copied())
    };
    let is_identifier = |text: &str| {
        !text.is_empty()
            && text
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
    };
    match language {
        FlowLanguage::JavaScript => {
            let resolve = |spec: &str| {
                resolve_js_specifier(dir, spec, index_of)
                    .or_else(|| resolve_js_package(dir, root, spec, index_of))
            };
            let (
                Ok(module_require),
                Ok(named_require),
                Ok(property_require),
                Ok(namespace_import),
                Ok(named_import),
                Ok(default_import),
                Ok(mixed_import),
            ) = (
                Regex::new(
                    r#"^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)\s*;?\s*$"#,
                ),
                Regex::new(
                    r#"^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)\s*;?\s*$"#,
                ),
                Regex::new(
                    r#"^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)\.([A-Za-z_$][A-Za-z0-9_$]*)\s*;?\s*$"#,
                ),
                Regex::new(
                    r#"^\s*import\s+\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+['"]([^'"]+)['"]\s*;?\s*$"#,
                ),
                Regex::new(r#"^\s*import\s*\{([^}]*)\}\s*from\s+['"]([^'"]+)['"]\s*;?\s*$"#),
                Regex::new(
                    r#"^\s*import\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+['"]([^'"]+)['"]\s*;?\s*$"#,
                ),
                Regex::new(
                    r#"^\s*import\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*\{([^}]*)\}\s*from\s+['"]([^'"]+)['"]\s*;?\s*$"#,
                ),
            )
            else {
                return bindings;
            };
            for statement in js_declarations(lines) {
                let line = statement.as_str();
                for (re, module) in [(&module_require, true), (&namespace_import, true)] {
                    if let Some(captures) = re.captures(line) {
                        if let (Some(binding), Some(spec)) = (captures.get(1), captures.get(2)) {
                            if let Some(target) = resolve(spec.as_str()) {
                                if module {
                                    bindings.push(ImportBinding::Module {
                                        binding: binding.as_str().to_string(),
                                        target,
                                        exported_only: false,
                                    });
                                }
                            }
                        }
                    }
                }
                if let Some(captures) = property_require.captures(line) {
                    if let (Some(local), Some(spec), Some(exported)) =
                        (captures.get(1), captures.get(2), captures.get(3))
                    {
                        if let Some(target) = resolve(spec.as_str()) {
                            bindings.push(ImportBinding::Function {
                                local: local.as_str().to_string(),
                                exported: exported.as_str().to_string(),
                                target,
                            });
                        }
                    }
                }
                // `import f from './x'` binds the local name to the target's
                // `default` export; `import f, { g } from './x'` binds both.
                // `import type ...` lines are skipped: they never produce a
                // callable binding.
                if !line.trim_start().starts_with("import type") {
                    if let Some(captures) = mixed_import.captures(line) {
                        if let (Some(local), Some(names), Some(spec)) =
                            (captures.get(1), captures.get(2), captures.get(3))
                        {
                            if let Some(target) = resolve(spec.as_str()) {
                                bindings.push(ImportBinding::Function {
                                    local: local.as_str().to_string(),
                                    exported: "default".to_string(),
                                    target,
                                });
                                for entry in names.as_str().split(',') {
                                    let entry = entry.trim();
                                    let (exported, local) = match entry.split_once(" as ") {
                                        Some((left, right)) => (left.trim(), right.trim()),
                                        None => (entry, entry),
                                    };
                                    if is_identifier(exported) && is_identifier(local) {
                                        bindings.push(ImportBinding::Function {
                                            local: local.to_string(),
                                            exported: exported.to_string(),
                                            target,
                                        });
                                    }
                                }
                            }
                        }
                    } else if let Some(captures) = default_import.captures(line) {
                        if let (Some(local), Some(spec)) = (captures.get(1), captures.get(2)) {
                            if let Some(target) = resolve(spec.as_str()) {
                                bindings.push(ImportBinding::Function {
                                    local: local.as_str().to_string(),
                                    exported: "default".to_string(),
                                    target,
                                });
                            }
                        }
                    }
                }
                for (re, separator) in [(&named_require, ":"), (&named_import, " as ")] {
                    if let Some(captures) = re.captures(line) {
                        if let (Some(names), Some(spec)) = (captures.get(1), captures.get(2)) {
                            let Some(target) = resolve(spec.as_str()) else {
                                continue;
                            };
                            for entry in names.as_str().split(',') {
                                let entry = entry.trim();
                                let (exported, local) = match entry.split_once(separator) {
                                    Some((left, right)) => (left.trim(), right.trim()),
                                    None => (entry, entry),
                                };
                                if is_identifier(exported) && is_identifier(local) {
                                    bindings.push(ImportBinding::Function {
                                        local: local.to_string(),
                                        exported: exported.to_string(),
                                        target,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        FlowLanguage::Python => {
            let resolve_module = |dots: usize, dotted: &str| -> Option<usize> {
                let relative: std::path::PathBuf =
                    dotted.split('.').filter(|p| !p.is_empty()).collect();
                let bases: Vec<std::path::PathBuf> = if dots > 0 {
                    let mut base = dir.to_path_buf();
                    for _ in 1..dots {
                        base = base.parent()?.to_path_buf();
                    }
                    vec![base]
                } else {
                    vec![dir.to_path_buf(), root.to_path_buf()]
                };
                bases.into_iter().find_map(|base| {
                    let target = base.join(&relative);
                    [
                        std::path::PathBuf::from(format!("{}.py", target.to_string_lossy())),
                        target.join("__init__.py"),
                    ]
                    .into_iter()
                    .filter(|candidate| candidate.is_file())
                    .find_map(lookup)
                })
            };
            let (Ok(from_import), Ok(plain_import), Ok(star_import)) = (
                Regex::new(
                    r#"^from\s+(\.*)([A-Za-z_][A-Za-z0-9_.]*)?\s+import\s+([A-Za-z_][A-Za-z0-9_,\s]*)$"#,
                ),
                Regex::new(
                    r#"^import\s+([A-Za-z_][A-Za-z0-9_.]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*$"#,
                ),
                Regex::new(r#"^from\s+(\.*)([A-Za-z_][A-Za-z0-9_.]*)?\s+import\s+\*\s*$"#),
            ) else {
                return bindings;
            };
            // Parenthesized from-imports (`from .x import (\n a,\n b\n)`,
            // black's format, and single-line `from .x import (a)`) are
            // flattened to the plain shape first: lines join until the
            // parens balance (bounded 40 lines), then the parens drop.
            let mut normalized: Vec<String> = Vec::with_capacity(lines.len());
            {
                let mut index = 0;
                while index < lines.len() {
                    let code = lines[index].split('#').next().unwrap_or("").trim();
                    if !(code.starts_with("from ") && code.contains(" import (")) {
                        normalized.push(code.to_string());
                        index += 1;
                        continue;
                    }
                    let mut joined = code.to_string();
                    let mut balance =
                        joined.matches('(').count() as i64 - joined.matches(')').count() as i64;
                    let mut used = 1;
                    while balance > 0 && used < 40 && index + used < lines.len() {
                        let next = lines[index + used].split('#').next().unwrap_or("").trim();
                        joined.push(' ');
                        joined.push_str(next);
                        balance =
                            joined.matches('(').count() as i64 - joined.matches(')').count() as i64;
                        used += 1;
                    }
                    normalized.push(joined.replace(['(', ')'], ""));
                    index += used;
                }
            }
            for code in &normalized {
                let code = code.as_str();
                if let Some(captures) = star_import.captures(code) {
                    let dots = captures.get(1).map_or(0, |m| m.as_str().len());
                    let dotted = captures.get(2).map_or("", |m| m.as_str());
                    if dots == 0 && dotted.is_empty() {
                        continue;
                    }
                    if let Some(target) = resolve_module(dots, dotted) {
                        bindings.push(ImportBinding::Star { target });
                    }
                    continue;
                }
                if let Some(captures) = from_import.captures(code) {
                    let dots = captures.get(1).map_or(0, |m| m.as_str().len());
                    let dotted = captures.get(2).map_or("", |m| m.as_str());
                    let names = captures.get(3).map_or("", |m| m.as_str());
                    if dots == 0 && dotted.is_empty() {
                        continue;
                    }
                    let module_target = if dotted.is_empty() {
                        None
                    } else {
                        resolve_module(dots, dotted)
                    };
                    for entry in names.split(',') {
                        let entry = entry.trim();
                        let (exported, local) = match entry.split_once(" as ") {
                            Some((left, right)) => (left.trim(), right.trim()),
                            None => (entry, entry),
                        };
                        if !is_identifier(exported) || !is_identifier(local) {
                            continue;
                        }
                        // `from .pkg import service` may name a module.
                        let submodule = if dotted.is_empty() {
                            resolve_module(dots, exported)
                        } else {
                            resolve_module(dots, &format!("{dotted}.{exported}"))
                        };
                        if let Some(target) = submodule {
                            bindings.push(ImportBinding::Module {
                                binding: local.to_string(),
                                target,
                                exported_only: false,
                            });
                        } else if let Some(target) = module_target {
                            bindings.push(ImportBinding::Function {
                                local: local.to_string(),
                                exported: exported.to_string(),
                                target,
                            });
                        }
                    }
                    continue;
                }
                if let Some(captures) = plain_import.captures(code) {
                    let dotted = captures.get(1).map_or("", |m| m.as_str());
                    let binding = match captures.get(2) {
                        Some(alias) => alias.as_str().to_string(),
                        None if !dotted.contains('.') => dotted.to_string(),
                        None => continue,
                    };
                    if let Some(target) = resolve_module(0, dotted) {
                        bindings.push(ImportBinding::Module {
                            binding,
                            target,
                            exported_only: false,
                        });
                    }
                }
            }
        }
        _ => {}
    }
    bindings
}

#[allow(clippy::items_after_test_module)]
fn first_argument(_name: &str) -> Vec<usize> {
    vec![0]
}

/// `http.Redirect(w, r, target, status)`: only the destination argument.
#[allow(clippy::items_after_test_module)]
fn redirect_target_argument(_name: &str) -> Vec<usize> {
    vec![2]
}

#[allow(clippy::items_after_test_module)]
fn go_sql_query_argument(name: &str) -> Vec<usize> {
    if name.ends_with("Context") {
        vec![1]
    } else {
        vec![0]
    }
}

#[allow(clippy::items_after_test_module)]
fn contains_numeric_conversion(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "int(",
        "float(",
        "number(",
        "parseint(",
        "parsefloat(",
        "integer.parseint(",
        "integer.valueof(",
        "double.parsedouble(",
        "float.parsefloat(",
        "long.parselong(",
        "long.valueof(",
        "uuid.fromstring(",
        "uuid.uuid(",
        "strconv.atoi(",
        "strconv.parseint(",
        "strconv.parseuint(",
        "strconv.parsefloat(",
        "parse::<i",
        "parse::<u",
        "parse::<f",
    ]
    .iter()
    .any(|marker| {
        lower.match_indices(marker).any(|(index, _)| {
            index == 0 || {
                let before = lower.as_bytes()[index - 1];
                !(before.is_ascii_alphanumeric() || before == b'_')
            }
        })
    }) || {
        // Rust's `.parse()` relies on the target type for safety; only a
        // numeric type annotation on the same line makes it a sanitizer.
        lower.contains(".parse()")
            && [
                ": i8", ": i16", ": i32", ": i64", ": i128", ": isize", ": u8", ": u16", ": u32",
                ": u64", ": u128", ": usize", ": f32", ": f64",
            ]
            .iter()
            .any(|annotation| lower.contains(annotation))
    }
}

/// Find SQL query sinks whose query argument is built from request input in
/// the same file.
///
/// Sources are the request inputs used by the path-traversal models (plus JS
/// destructuring from `req.query`/`req.body`/`req.params`). Taint follows
/// aliases and string construction (concatenation, template literals,
/// f-strings, `format`/`String.format`/`fmt.Sprintf`) and is stopped by
/// numeric conversions. A tainted value passed only as a bind parameter of a
/// parameterized query is not reported. The model is same-file and
/// straight-line only; it makes no interprocedural claim.
#[allow(clippy::items_after_test_module)]
fn sql_injection_sink_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    let Some(language) = flow_language(extension) else {
        return std::collections::HashSet::new();
    };
    request_flow_sink_lines(
        content,
        language,
        &sql_flow_sinks(language),
        contains_numeric_conversion,
        true,
    )
}

#[allow(clippy::items_after_test_module)]
fn code_injection_sink_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    let Some(language) = flow_language(extension) else {
        return std::collections::HashSet::new();
    };
    let sinks = code_injection_flow_sinks(language);
    if sinks.is_empty() {
        return std::collections::HashSet::new();
    }
    request_flow_sink_lines(content, language, &sinks, |_| false, false)
}

#[allow(clippy::items_after_test_module)]
fn code_injection_flow_sinks(language: FlowLanguage) -> Vec<FlowSink> {
    if language != FlowLanguage::JavaScript {
        return Vec::new();
    }
    [
        (
            r#"(?:^|[^.\w$])(eval)\s*\("#,
            first_argument as FlowArguments,
        ),
        (
            r#"\bnew\s+(Function)\s*\("#,
            first_argument as FlowArguments,
        ),
    ]
    .iter()
    .filter_map(|(pattern, arguments)| {
        Regex::new(pattern).ok().map(|call| FlowSink {
            call,
            arguments: *arguments,
            line_requires: None,
        })
    })
    .collect()
}

#[allow(clippy::items_after_test_module)]
fn sql_flow_sinks(language: FlowLanguage) -> Vec<FlowSink> {
    let patterns: &[(&str, FlowArguments)] = match language {
        FlowLanguage::Python => &[
            (
                r#"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(execute|executemany|executescript)\s*\("#,
                first_argument,
            ),
            (r#"\.\s*objects\s*\.\s*(raw)\s*\("#, first_argument),
        ],
        FlowLanguage::JavaScript => &[(
            r#"\b(?:db|conn|connection|pool|client|knex|sequelize|database|sql|tx|trx)\s*\.\s*(query|execute|prepare|exec|raw)\s*\("#,
            first_argument,
        )],
        FlowLanguage::Java => &[
            (
                r#"\.\s*(executeQuery|executeUpdate|executeLargeUpdate|execute|addBatch|prepareStatement|prepareCall|create(?:Native|SQL)?Query)\s*\("#,
                first_argument,
            ),
            (
                r#"\b[A-Za-z_]*[Jj]dbc[Tt]emplate\s*\.\s*(query[A-Za-z]*|update|execute)\s*\("#,
                first_argument,
            ),
        ],
        FlowLanguage::Go => &[(
            r#"\b[A-Za-z_][A-Za-z0-9_]*\s*\.\s*(Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Prepare|PrepareContext)\s*\("#,
            go_sql_query_argument,
        )],
        FlowLanguage::Rust => &[
            (
                r#"\bsqlx\s*::\s*(query|query_as|query_scalar|raw_sql)\s*\("#,
                first_argument,
            ),
            (
                r#"\b(?:conn|db|tx|pool|client|connection)\s*\.\s*(execute|query|query_row|query_map|query_one|query_opt|query_and_then|prepare|batch_execute)\s*\("#,
                first_argument,
            ),
        ],
    };
    patterns
        .iter()
        .filter_map(|(pattern, arguments)| {
            Regex::new(pattern).ok().map(|call| FlowSink {
                call,
                arguments: *arguments,
                line_requires: None,
            })
        })
        .collect()
}

#[allow(clippy::items_after_test_module)]
fn shell_command_argument(name: &str) -> Vec<usize> {
    match name {
        "Command" => vec![2],
        "CommandContext" => vec![3],
        _ => vec![2],
    }
}

#[allow(clippy::items_after_test_module)]
fn contains_command_sanitizer(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("shlex.quote(")
        || lower.contains("pipes.quote(")
        || contains_numeric_conversion(text)
}

/// A public Ruby method that takes parameters: parameter names, the index of
/// the `def` line, and the exclusive end index of the body.
struct RubyMethod {
    params: Vec<String>,
    def_index: usize,
    end: usize,
}

/// Public Ruby methods with at least one parameter. Not public: after a bare
/// `private`/`protected` in the class or module scope, `private def`, or an
/// underscore name. The end of a method is the next `end` at the same
/// indentation as its `def`.
fn ruby_public_methods(lines: &[&str]) -> Vec<RubyMethod> {
    let mut methods = Vec::new();
    let (Ok(def_re), Ok(scope_re)) = (
        Regex::new(
            r#"^(\s*)def\s+(?:self\s*\.\s*)?([A-Za-z_][A-Za-z0-9_]*[?!=]?)\s*(?:\(([^)]*)\))?"#,
        ),
        Regex::new(r#"^\s*(?:class|module)\s"#),
    ) else {
        return methods;
    };
    let mut private_scope = false;
    // Each open `class`/`module` saves the visibility of the scope around it,
    // so a nested class does not reset an outer `private`.
    let mut scopes: Vec<(usize, bool)> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let line_indent = line.len() - line.trim_start().len();
        if trimmed == "end"
            && scopes
                .last()
                .is_some_and(|(indent, _)| *indent == line_indent)
        {
            if let Some((_, saved)) = scopes.pop() {
                private_scope = saved;
            }
        } else if scope_re.is_match(line) {
            let one_line = trimmed.ends_with(" end") || trimmed.contains("; end");
            if !one_line {
                scopes.push((line_indent, private_scope));
            }
            private_scope = false;
        } else if matches!(trimmed, "private" | "protected") {
            private_scope = true;
        } else if trimmed == "public" {
            private_scope = false;
        }
        let Some(captures) = def_re.captures(line) else {
            continue;
        };
        let indent = captures.get(1).map_or(0, |m| m.as_str().len());
        let name = captures.get(2).map_or("", |m| m.as_str());
        let inline_private = trimmed.starts_with("private ") || trimmed.starts_with("protected ");
        if private_scope || inline_private || name.starts_with('_') {
            continue;
        }
        let mut end = index + 1;
        while end < lines.len() {
            let l = lines[end];
            if l.trim() == "end" && l.len() - l.trim_start().len() == indent {
                break;
            }
            end += 1;
        }
        let params: Vec<String> = captures
            .get(3)
            .map(|m| {
                m.as_str()
                    .split(',')
                    .filter_map(|part| {
                        let part = part.trim().trim_start_matches(['*', '&']);
                        let part = part.split('=').next().unwrap_or("").trim();
                        let part = part.trim_end_matches(':').trim();
                        (!part.is_empty()
                            && part
                                .chars()
                                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_'))
                        .then(|| part.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        if !params.is_empty() {
            methods.push(RubyMethod {
                params,
                def_index: index,
                end: end.min(lines.len()),
            });
        }
    }
    methods
}

/// Ruby `Kernel.open` / bare `open` whose path is a parameter of a public
/// method. `Kernel#open` runs a command when the string starts with `|`, so a
/// library method that opens a caller-supplied path with it is a command
/// injection sink for any caller that forwards untrusted input. Explicit
/// receivers other than `Kernel` (`File.open`, `IO.popen`, `URI.open`) are
/// quiet; a bare `open` in a file that defines its own `open` is quiet; a
/// private or protected method, an underscore method and a body that tests
/// for a leading `|` are quiet. Only the first argument counts, and only as a
/// bare parameter name. Same method body, straight-line only.
#[allow(clippy::items_after_test_module)]
fn ruby_parameter_open_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    let mut found = std::collections::HashSet::new();
    if extension != "rb" {
        return found;
    }
    let (Ok(open_re), Ok(pipe_guard), Ok(own_open)) = (
        Regex::new(
            r#"(?:^|[^.\w:@$])(Kernel\s*\.\s*)?open\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*[,)]"#,
        ),
        Regex::new(r#"start_with\?\s*\(?\s*["']\||=~\s*/\\A\\\||include\?\s*\(?\s*["']\|"#),
        Regex::new(r#"(?m)^\s*def\s+(?:self\s*\.\s*)?open\b"#),
    ) else {
        return found;
    };
    let defines_open = own_open.is_match(content);
    let lines: Vec<&str> = content.lines().collect();
    for method in ruby_public_methods(&lines) {
        let body = lines[method.def_index + 1..method.end].join("\n");
        if pipe_guard.is_match(&body) {
            continue;
        }
        for (offset, text) in lines
            .iter()
            .enumerate()
            .take(method.end)
            .skip(method.def_index + 1)
        {
            if text.trim().starts_with('#') {
                continue;
            }
            for c in open_re.captures_iter(text) {
                let kernel = c.get(1).is_some();
                let arg = c.get(2).map_or("", |m| m.as_str());
                if (kernel || !defines_open) && method.params.iter().any(|p| p == arg) {
                    found.insert(offset + 1);
                }
            }
        }
    }
    found
}

/// Ruby shell-string sinks built from a public method parameter: a backtick
/// string, `%x(...)`, or a single-string `system`/`exec`/`IO.popen`/`Open3`
/// call whose text interpolates or concatenates a value derived from a
/// parameter. Taint follows local assignments in order, through calls and
/// array literals joined into a string (`File.basename(path)` is not a shell
/// quote); a multi-line assignment is read as one statement. A method that
/// mentions `shellescape`, `Shellwords` or a numeric conversion of the value
/// is quiet, argument-vector calls (`system("ls", path)`) are not sinks, and
/// private, protected and underscore methods are not the caller boundary.
/// Same method body, straight-line only.
#[allow(clippy::items_after_test_module)]
fn ruby_parameter_shell_lines(content: &str, extension: &str) -> std::collections::HashSet<usize> {
    let mut found = std::collections::HashSet::new();
    if extension != "rb" {
        return found;
    }
    let (Ok(assign_re), Ok(call_re), Ok(clear_re), Ok(heredoc_re)) = (
        Regex::new(r#"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^=~>].*)$"#),
        Regex::new(
            r#"(?:^|[^.\w:@$])(?:Kernel\s*\.\s*)?(?:system|exec|spawn)\s*\(|\bIO\s*\.\s*popen\s*\(|\bOpen3\s*\.\s*\w+\s*\("#,
        ),
        Regex::new(r#"shellescape|Shellwords|shelljoin|\.to_i\b|Integer\s*\("#),
        Regex::new(r#"<<[~-]?["']?([A-Z_][A-Z0-9_]*)["']?"#),
    ) else {
        return found;
    };
    let lines: Vec<&str> = content.lines().collect();
    for method in ruby_public_methods(&lines) {
        let body = lines[method.def_index + 1..method.end].join("\n");
        if clear_re.is_match(&body) {
            continue;
        }
        let mut tainted: Vec<String> = method.params.clone();
        let mut index = method.def_index + 1;
        let mut heredoc: Option<String> = None;
        while index < method.end {
            let line = lines[index];
            if let Some(id) = heredoc.as_ref() {
                if line.trim() == id {
                    heredoc = None;
                }
                index += 1;
                continue;
            }
            if let Some(c) = heredoc_re.captures(line) {
                heredoc = c.get(1).map(|m| m.as_str().to_string());
            }
            if line.trim().starts_with('#') {
                index += 1;
                continue;
            }
            // Join a statement that spans lines (open brackets or a trailing
            // operator or comma) into one text.
            let mut statement = line.to_string();
            let mut last = index;
            while last + 1 < method.end
                && (statement.matches(['[', '(', '{']).count()
                    > statement.matches([']', ')', '}']).count()
                    || statement.trim_end().ends_with([',', '+', '\\']))
            {
                last += 1;
                statement.push(' ');
                statement.push_str(lines[last].trim());
            }
            let uses = |text: &str| tainted.iter().any(|name| contains_identifier(text, name));
            let mut sink = false;
            // Only code outside string literals counts: a backtick or
            // `system(` inside a quoted message is text, not a command.
            let masked = ruby_mask_strings(&statement);
            // Backtick strings and %x: the interpolation must carry taint.
            if let Some(open) = masked.find('`') {
                if let Some(close) = masked[open + 1..].find('`') {
                    let inner = &statement[open + 1..open + 1 + close];
                    if inner.contains("#{") && interpolations(inner).iter().any(|e| uses(e)) {
                        sink = true;
                    }
                }
            }
            if let Some(start) = masked.find("%x") {
                let rest = &statement[start + 2..];
                if rest.starts_with(['(', '{', '[']) && interpolations(rest).iter().any(|e| uses(e))
                {
                    sink = true;
                }
            }
            if let Some(m) = call_re.find(&masked) {
                let args = ruby_call_arguments(&statement, m.end() - 1);
                // A splat (`popen3(*args)`) is an argument vector, not a string.
                if args.len() == 1 && !args[0].trim().starts_with('*') {
                    let arg = args[0].trim();
                    let composed = (arg.contains("#{")
                        && interpolations(arg).iter().any(|e| uses(e)))
                        || (arg.contains('+') && uses(arg))
                        || (!arg.starts_with(['"', '\'', '[']) && uses(arg));
                    if composed {
                        sink = true;
                    }
                }
            }
            if sink {
                found.extend(index + 1..=last + 1);
            }
            if let Some(c) = assign_re.captures(&statement) {
                let name = c.get(1).map_or("", |m| m.as_str()).to_string();
                let rhs = c.get(2).map_or("", |m| m.as_str());
                if uses(rhs) {
                    if !tainted.contains(&name) {
                        tainted.push(name);
                    }
                } else {
                    tainted.retain(|t| *t != name);
                }
            }
            index = last + 1;
        }
    }
    found
}

/// The statement with the contents of quoted strings (and their `#{}`
/// interpolations) blanked out, byte for byte, so offsets match the original.
/// Used to tell code from text: a backtick inside `"..."` is not a command.
fn ruby_mask_strings(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut interp = 0i32;
    for ch in text.chars() {
        let blank = |out: &mut String, ch: char| {
            for _ in 0..ch.len_utf8() {
                out.push(' ');
            }
        };
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if interp > 0 {
                    if ch == '{' {
                        interp += 1;
                    } else if ch == '}' {
                        interp -= 1;
                    }
                } else if q == '"' && ch == '#' {
                    // `#{` is detected on the next char via a pending marker.
                    interp = -1;
                } else if ch == q {
                    quote = None;
                    out.push(ch);
                    continue;
                }
                if interp == -1 && ch != '#' {
                    interp = if ch == '{' { 1 } else { 0 };
                }
                blank(&mut out, ch);
            }
            None => {
                if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                }
                out.push(ch);
            }
        }
    }
    out
}

/// The expressions inside every `#{...}` of a Ruby string.
fn interpolations(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("#{") {
        let after = &rest[start + 2..];
        let mut depth = 1;
        let mut end = after.len();
        for (i, ch) in after.char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push(after[..end].to_string());
        rest = &after[(end + 1).min(after.len())..];
    }
    out
}

/// Top-level arguments of the Ruby call whose `(` is at byte `open`.
fn ruby_call_arguments(text: &str, open: usize) -> Vec<String> {
    let mut args = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for ch in text[open..].chars() {
        if let Some(q) = quote {
            current.push(ch);
            if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                quote = Some(ch);
                current.push(ch);
            }
            '(' | '[' | '{' => {
                depth += 1;
                if depth > 1 {
                    current.push(ch);
                }
            }
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    args.push(current.clone());
                    return args.into_iter().filter(|a| !a.trim().is_empty()).collect();
                }
                current.push(ch);
            }
            ',' if depth == 1 => {
                args.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    args.into_iter().filter(|a| !a.trim().is_empty()).collect()
}

/// Find OS command sinks whose command text is built from request input in
/// the same file.
///
/// Sources and propagation match the SQL injection model. Sinks are calls that
/// hand a command string to a shell: Python `os.system`/`os.popen`,
/// `subprocess.getoutput`, and `subprocess` calls with `shell=True`; Node
/// `child_process` `exec`/`execSync`; Java `Runtime.exec` and
/// `ProcessBuilder("sh", "-c", ...)`; Go `exec.Command("sh", "-c", ...)`;
/// Rust `Command::new("sh").arg("-c").arg(cmd)` single-line chains.
/// Argument-vector process calls without a shell are not sinks.
/// `shlex.quote` and numeric conversions stop the flow. Same-file and
/// straight-line only; no interprocedural claim.
#[allow(clippy::items_after_test_module)]
fn command_injection_sink_lines(
    content: &str,
    extension: &str,
) -> std::collections::HashSet<usize> {
    let Some(language) = flow_language(extension) else {
        return std::collections::HashSet::new();
    };
    let mut lines = request_flow_sink_lines(
        content,
        language,
        &command_flow_sinks(language),
        contains_command_sanitizer,
        false,
    );
    lines.extend(library_parameter_command_lines(content, extension));
    lines
}

