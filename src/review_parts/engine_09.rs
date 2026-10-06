/// Function definitions the interprocedural pass can summarize.
///
/// Recognized: JS/TS `function name(...) {`, `const name = function (...) {`,
/// `const name = (...) => {`, and class methods `name(...) {`; Python
/// `def name(...):` (methods when the first parameter is `self`/`cls`); Java
/// methods and constructors whose header ends with `{`; Go `func name(...)
/// ... {` (methods with receivers are skipped); Rust `fn name(...) ->
/// ... {` (methods when the first parameter is `self`). Only simple
/// positional
/// parameters are accepted: destructuring, rest/variadic-star parameters,
/// and headers split across lines make a definition unsupported. A name
/// defined more than once in the file (overloads, redefinitions, the same
/// method name on two classes) is dropped so a call never resolves to the
/// wrong body.
#[allow(clippy::items_after_test_module)]
fn flow_functions(lines: &[&str], language: FlowLanguage) -> Vec<FlowFunction> {
    let mut functions: Vec<FlowFunction> = Vec::new();
    let mut unsupported_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    let keywords = [
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "function",
        "return",
        "with",
        "else",
        "new",
        "synchronized",
        "try",
        "do",
        "super",
        "this",
    ];
    let headers: Vec<(Regex, bool)> = match language {
        FlowLanguage::JavaScript => vec![
            (
                r#"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^()]*)\)\s*(?::\s*[^{]+)?\{\s*$"#,
                false,
            ),
            (
                r#"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::\s*[^=]+)?=\s*(?:async\s+)?(?:function\s*[A-Za-z0-9_$]*\s*\(([^()]*)\)|\(([^()]*)\)\s*(?::\s*[^=]+)?=>)\s*\{\s*$"#,
                false,
            ),
            (
                r#"^\s*(?:(?:public|private|protected|static|async|readonly)\s+)*([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^()]*)\)\s*(?::\s*[^{]+)?\{\s*$"#,
                true,
            ),
        ],
        FlowLanguage::Python => vec![(
            r#"^(\s*)(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]*)\)\s*(?:->\s*[^:]+)?:\s*$"#,
            false,
        )],
        FlowLanguage::Java => vec![(
            r#"^\s*(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)*(?:<[^>]+>\s+)?(?:[A-Za-z_][A-Za-z0-9_.<>\[\], ?]*?\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]*)\)\s*(?:throws\s+[A-Za-z0-9_.,\s]+?)?\s*\{\s*$"#,
            false,
        )],
        FlowLanguage::Go => vec![(
            r#"^\s*func\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]*)\)[^{]*\{\s*$"#,
            false,
        )],
        FlowLanguage::Rust => vec![(
            r#"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\(([^()]*)\)\s*(?:->\s*[^{]+?)?\{\s*$"#,
            false,
        )],
    }
    .into_iter()
    .filter_map(|(pattern, method)| Regex::new(pattern).ok().map(|re| (re, method)))
    .collect();
    let annotation = Regex::new(r#"@[A-Za-z_][A-Za-z0-9_.]*(?:\([^()]*\))?\s*"#).ok();
    let header_start = Regex::new(
        r#"^\s*(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)*(?:[A-Za-z_][A-Za-z0-9_.<>\[\], ?]*?\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\([^()]*$"#,
    )
    .ok();
    let definition_like = Regex::new(
        r#"^\s*(?:(?:export\s+)?(?:async\s+)?function\s*\*?\s*|(?:async\s+)?def\s+|func\s+|(?:pub\s+)?(?:async\s+)?fn\s+)([A-Za-z_$][A-Za-z0-9_$]*)\s*\("#,
    )
    .ok();
    let assigned_arrow_pattern = (language == FlowLanguage::JavaScript)
        .then(|| {
            Regex::new(
                r"^\s*this\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(([^()]*)\)\s*=>\s*\{",
            )
        })
        .and_then(Result::ok);

    for (index, line) in lines.iter().enumerate() {
        let code = if language == FlowLanguage::Python {
            line.split('#').next().unwrap_or("")
        } else {
            line
        };
        let visible = blank_plain_strings(code, language);
        let header_text = match (language, annotation.as_ref()) {
            (FlowLanguage::Java, Some(annotation)) => {
                annotation.replace_all(&visible, "").to_string()
            }
            _ => visible.clone(),
        };
        // Java method signatures may span several lines (annotations on their
        // own parameter lines). Assemble a bounded join of the following lines
        // when the stripped line opens a parameter list it does not close, and
        // match the header against the joined text. Line indexes are kept:
        // `header` stays the first line and the brace scan below still finds
        // the body.
        let mut joined: Option<String> = None;
        let mut joined_end: Option<usize> = None;
        if language == FlowLanguage::Java {
            if let (Some(start), Some(annotation)) = (header_start.as_ref(), annotation.as_ref()) {
                if start.is_match(&header_text) {
                    let mut text = header_text.clone();
                    let mut depth = header_text.matches('(').count() as i64
                        - header_text.matches(')').count() as i64;
                    let mut next_index = index;
                    while depth > 0 && next_index + 1 < lines.len() && next_index - index < 8 {
                        next_index += 1;
                        let following = blank_plain_strings(lines[next_index], language);
                        let following = annotation.replace_all(&following, "");
                        depth += following.matches('(').count() as i64
                            - following.matches(')').count() as i64;
                        text.push(' ');
                        text.push_str(&following);
                    }
                    if depth == 0 {
                        joined = Some(text);
                        joined_end = Some(next_index + 1);
                    }
                }
            }
        }
        let assigned_arrow = assigned_arrow_pattern.as_ref().and_then(|re| {
            re.captures(&header_text)
                .map(|c| (c[1].to_string(), c[2].to_string()))
        });
        if let Some((name, raw_params)) = assigned_arrow {
            if let Some(params) = flow_parameters(&raw_params, language) {
                let mut depth = 0i64;
                let mut opened = false;
                let mut end = None;
                for (offset, next) in lines.iter().enumerate().skip(index) {
                    for ch in blank_plain_strings(next, language).chars() {
                        match ch {
                            '{' => depth += 1,
                            '}' => depth -= 1,
                            _ => {}
                        }
                    }
                    if depth > 0 {
                        opened = true;
                    }
                    if opened && depth <= 0 {
                        end = Some(offset);
                        break;
                    }
                }
                if let Some(end) = end {
                    functions.push(FlowFunction {
                        name,
                        params,
                        header: index,
                        signature_end: index + 1,
                        body: index + 1..end,
                        method: true,
                    });
                    continue;
                }
            }
        }
        let matched = headers.iter().find_map(|(re, method)| {
            re.captures(joined.as_deref().unwrap_or(&header_text))
                .map(|captures| {
                    if language == FlowLanguage::Python {
                        let indent = captures.get(1).map_or(0, |m| m.as_str().len());
                        (
                            captures.get(2).map(|m| m.as_str().to_string()),
                            captures.get(3).map(|m| m.as_str().to_string()),
                            *method,
                            indent,
                        )
                    } else {
                        let params = captures.get(2).or_else(|| captures.get(3));
                        (
                            captures.get(1).map(|m| m.as_str().to_string()),
                            params.map(|m| m.as_str().to_string()),
                            *method,
                            0,
                        )
                    }
                })
        });
        let Some((Some(name), Some(params), mut method, indent)) = matched else {
            // A definition this pass cannot parse still shadows the name.
            if let Some(name) = definition_like
                .as_ref()
                .and_then(|re| re.captures(&visible))
                .and_then(|captures| captures.get(1))
            {
                unsupported_names.insert(name.as_str().to_string());
            }
            continue;
        };
        if keywords.contains(&name.as_str()) {
            continue;
        }
        let Some(mut params) = flow_parameters(&params, language) else {
            unsupported_names.insert(name);
            continue;
        };
        if language == FlowLanguage::Python
            && params
                .first()
                .is_some_and(|first| first == "self" || first == "cls")
        {
            params.remove(0);
            method = true;
        }
        if language == FlowLanguage::Rust && params.first().is_some_and(|first| first == "self") {
            params.remove(0);
            method = true;
        }
        let body = match language {
            FlowLanguage::Python => {
                let mut end = index + 1;
                for (offset, next) in lines.iter().enumerate().skip(index + 1) {
                    let trimmed = next.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let next_indent = next.len() - next.trim_start().len();
                    if next_indent <= indent {
                        break;
                    }
                    end = offset + 1;
                }
                index + 1..end
            }
            _ => {
                let mut depth = 0i64;
                let mut opened = false;
                let mut end = None;
                for (offset, next) in lines.iter().enumerate().skip(index) {
                    let text = blank_plain_strings(next, language);
                    let text = text.split("//").next().unwrap_or("");
                    for ch in text.chars() {
                        match ch {
                            '{' => depth += 1,
                            '}' => depth -= 1,
                            _ => {}
                        }
                    }
                    // Multi-line signatures contribute no brace on the header
                    // line, so only close once the opening brace was seen.
                    if depth > 0 {
                        opened = true;
                    }
                    if opened && depth <= 0 {
                        end = Some(offset);
                        break;
                    }
                }
                match end {
                    Some(end) if end > index => index + 1..end,
                    _ => {
                        unsupported_names.insert(name);
                        continue;
                    }
                }
            }
        };
        functions.push(FlowFunction {
            name,
            params,
            header: index,
            signature_end: joined_end.unwrap_or(index + 1),
            body,
            method,
        });
    }

    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for function in &functions {
        *counts.entry(function.name.clone()).or_default() += 1;
    }
    functions.retain(|function| {
        counts.get(&function.name) == Some(&1) && !unsupported_names.contains(&function.name)
    });
    functions
}

/// Parse a parameter list into plain names, or `None` when any parameter is
/// not a simple positional identifier.
#[allow(clippy::items_after_test_module)]
fn flow_parameters(list: &str, language: FlowLanguage) -> Option<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    for ch in list.chars() {
        match ch {
            '<' | '[' | '{' | '(' => {
                depth += 1;
                current.push(ch);
            }
            '>' | ']' | '}' | ')' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                parts.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    parts.push(current);
    let parts: Vec<String> = parts
        .into_iter()
        .map(|part| part.trim().to_string())
        .collect();
    if parts.len() == 1 && parts[0].is_empty() {
        return Some(Vec::new());
    }
    let is_identifier = |name: &str| {
        !name.is_empty()
            && !name.starts_with(|ch: char| ch.is_ascii_digit())
            && name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
    };
    let mut names = Vec::new();
    for part in parts {
        if part.is_empty() || part.starts_with('*') || part.starts_with("...") {
            return None;
        }
        let name = match language {
            FlowLanguage::JavaScript | FlowLanguage::Python => {
                let name = part.split('=').next().unwrap_or("");
                let name = name.split(':').next().unwrap_or("").trim();
                let name = name.trim_end_matches('?');
                name.to_string()
            }
            FlowLanguage::Java => {
                let part = part.trim_start_matches("final ").trim();
                if part.contains("...") {
                    return None;
                }
                part.rsplit(char::is_whitespace)
                    .next()
                    .unwrap_or("")
                    .to_string()
            }
            FlowLanguage::Go => {
                if part.contains("...") {
                    return None;
                }
                part.split_whitespace().next().unwrap_or("").to_string()
            }
            FlowLanguage::Rust => {
                let part = part.trim();
                if matches!(part, "self" | "&self" | "&mut self" | "mut self") {
                    "self".to_string()
                } else {
                    part.trim_start_matches("mut ")
                        .split(':')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string()
                }
            }
        };
        if !is_identifier(&name) {
            return None;
        }
        names.push(name);
    }
    Some(names)
}

/// Sink lines found in one file through calls from other project files, per
/// flow family.
#[derive(Default)]
struct CrossFileSinkLines {
    sql: std::collections::HashSet<usize>,
    command: std::collections::HashSet<usize>,
    ssrf: std::collections::HashSet<usize>,
    code: std::collections::HashSet<usize>,
}

/// How a caller file binds an imported file.
enum ImportBinding {
    /// `const service = require('../service')`, `import * as s from`,
    /// `import service` / `from . import service`: calls look like
    /// `binding.name(...)`. `exported_only` restricts the visible names to
    /// capitalized ones (Go cross-package calls).
    Module {
        binding: String,
        target: usize,
        exported_only: bool,
    },
    /// `const { f } = require(...)`, `import { f as g } from`,
    /// `from .service import f as g`: calls look like `local(...)`.
    Function {
        local: String,
        exported: String,
        target: usize,
    },
    /// `from .service import *`, Go `import . "pkg"`: every exported
    /// name of `target` is callable bare. Expanded into Function bindings
    /// once exports are known, so later passes never see this variant.
    Star { target: usize },
}

