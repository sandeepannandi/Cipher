use crate::groq::GroqClient;
use crate::scan;
use crate::zeroday::{extract_function_name, is_function_signature};
use anyhow::Result;
use colored::*;
use ignore::WalkBuilder;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

// ── Constants ───────────────────────────────────────────────────────

/// Variable/API names that introduce untrusted data into a program.
const TAINT_SOURCES: &[&str] = &[
    "request", "req", "params", "body", "query", "input",
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER",
    "ctx.request", "self.request", "this.request",
    "request.data", "request.json", "request.form",
    "req.body", "req.query", "req.params",
    "getParameter", "getQueryString", "HttpServletRequest",
    "args", "argv", "stdin",
];

/// Dangerous operations that untrusted data should never reach.
const TAINT_SINKS: &[&str] = &[
    "exec", "system", "popen", "eval", "assert",
    "query", "execute", "raw_query", "rawQuery",
    "shell_exec", "passthru", "proc_open",
    "os.system", "subprocess.call", "subprocess.Popen",
    "runtime.exec", "ProcessBuilder",
    "is_admin", "isAdmin", "admin", "grant", "role", "permission",
    "authorize", "privilege", "sudo",
    "open(", "write", "delete", "chmod", "unlink",
];

/// Sanitization functions that break taint propagation.
const SANITIZERS: &[&str] = &[
    "sanitize", "validate", "escape", "filter",
    "htmlspecialchars", "strip_tags", "escapeHtml",
    "escapeShellArg", "escapeshellarg",
    "parseInt", "parseFloat", "intval", "floatval",
    "is_numeric", "ctype_digit", "preg_match",
];

/// Default max recursion depth for cross-file call tracing.
const DEFAULT_DEPTH: usize = 4;

/// Functions scanned per run (prevents hangs on huge repos).
const MAX_SCAN_FUNCTIONS: usize = 20_000;

// ── Data structures ─────────────────────────────────────────────────

/// A single hop in a taint path.
#[derive(Debug, Clone, Serialize)]
pub struct TraceStep {
    /// File the hop occurred in
    pub file: String,
    /// 1-based line number
    pub line: usize,
    /// Enclosing function name
    pub function: String,
    /// What happened: "source", "flow", "call", or "sink"
    pub action: String,
    /// Short description of the hop
    pub detail: String,
}

/// A complete source→sink data-flow path, possibly spanning multiple files.
#[derive(Debug, Clone, Serialize)]
pub struct TaintPath {
    pub id: String,
    /// Human-readable title, e.g. "user input reaches is_admin()"
    pub title: String,
    /// Narrative description of the flow
    pub description: String,
    /// Risk score 0–10
    pub risk_score: f64,
    /// Entry point (source) summary
    pub source: String,
    /// Final sink summary
    pub sink: String,
    /// Ordered steps of the path
    pub steps: Vec<TraceStep>,
}

/// A parsed function definition.
#[derive(Debug, Clone)]
struct FunctionDef {
    name: String,
    file: String,
    start_line: usize,
    params: Vec<String>,
    /// (line_number, trimmed source) pairs for the function body
    body: Vec<(usize, String)>,
}

impl FunctionDef {
    /// Parameter name at a given position (for caller→callee taint mapping).
    fn param_at(&self, index: usize) -> Option<&str> {
        self.params.get(index).map(|s| s.as_str())
    }
}

// ── Collection ──────────────────────────────────────────────────────

/// Walk the project and parse every function in every supported source file.
fn collect_functions(project_path: &Path) -> Vec<FunctionDef> {
    let walker = WalkBuilder::new(project_path)
        .git_ignore(true)
        .git_global(true)
        .hidden(false)
        .max_depth(Some(scan::MAX_WALK_DEPTH))
        .build();

    let mut functions = Vec::new();
    let mut file_count = 0usize;

    for result in walker {
        if file_count >= scan::MAX_SCAN_FILES {
            break;
        }
        let Ok(entry) = result else { continue };
        let path = entry.path();
        if !path.is_file() || scan::should_exclude(path) || scan::is_binary(path) {
            continue;
        }
        let ext = path
            .extension()
            .map(|e| e.to_str().unwrap_or("").to_lowercase())
            .unwrap_or_default();
        if ext.is_empty() || !is_trace_ext(&ext) {
            continue;
        }
        file_count += 1;

        let Ok(content) = std::fs::read_to_string(path) else { continue };
        let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        functions.extend(parse_functions(&lines, &path.to_string_lossy(), &ext));

        if functions.len() >= MAX_SCAN_FUNCTIONS {
            break;
        }
    }

    functions
}

/// Split a file into function definitions.
fn parse_functions(lines: &[String], file: &str, ext: &str) -> Vec<FunctionDef> {
    let mut functions = Vec::new();
    let mut current: Option<FunctionDef> = None;
    let mut brace_depth = 0i32;

    for (i, line) in lines.iter().enumerate() {
        let line_num = i + 1;
        let trimmed = line.trim();

        // Start a new function when we see a signature line. If one is still
        // open (e.g. a Python def that never closed via braces), flush it first
        // so consecutive definitions are each parsed — this matters for files
        // with many auth/helper functions. For brace-based languages we only
        // flush when the brace depth is 0 (the outer function already closed),
        // so nested declarations/arrow functions inside a body don't truncate it.
        if is_function_signature(trimmed, ext) && (brace_depth <= 0 || ext == "py") {
            if let Some(f) = current.take() {
                functions.push(f);
            }
            let mut name = extract_function_name(trimmed);
            if name == "<anonymous>" {
                name = extract_arrow_name(trimmed).unwrap_or(name);
            }
            let params = extract_params(trimmed);
            current = Some(FunctionDef {
                name,
                file: file.to_string(),
                start_line: line_num,
                params,
                body: Vec::new(),
            });
        }

        if let Some(f) = current.as_mut() {
            // Skip the signature line itself, comments, and pure closing braces
            // (e.g. `}` / `};` / `})`) from the body — the closing delimiter that
            // ends this function is not a statement to analyze.
            if line_num != f.start_line
                && !trimmed.is_empty()
                && !is_comment(trimmed)
                && !is_pure_closing(trimmed)
            {
                f.body.push((line_num, trimmed.to_string()));
            }
        }

        // Track brace depth to find the end of the current function
        for ch in trimmed.chars() {
            match ch {
                '{' => brace_depth += 1,
                '}' => {
                    brace_depth -= 1;
                    if brace_depth <= 0 && current.is_some() {
                        let f = current.take().unwrap();
                        functions.push(f);
                    }
                }
                _ => {}
            }
        }

        // Python uses indentation, not braces. Close a def when a line at
        // column 0 that is not a new def appears after the body started.
        if ext == "py" {
            if let Some(f) = current.as_ref() {
                let body_started = f.body.iter().any(|(ln, _)| *ln > f.start_line);
                if body_started
                    && line_num > f.start_line
                    && indent_of(line) == 0
                    && !trimmed.is_empty()
                    && !trimmed.starts_with("def ")
                    && !is_comment(trimmed)
                {
                    let f = current.take().unwrap();
                    functions.push(f);
                }
            }
        }

        if brace_depth < 0 {
            brace_depth = 0;
        }
    }

    // Flush any unclosed function (Python defs, single-line bodies)
    if let Some(f) = current.take() {
        functions.push(f);
    }

    functions
}

/// True if the line is only closing delimiters (e.g. `}` / `};` / `})` / `},`).
fn is_pure_closing(line: &str) -> bool {
    let t = line.trim();
    if !t.starts_with('}') {
        return false;
    }
    t.trim_start_matches(|c| c == '}' || c == ')' || c == ',' || c == ';')
        .trim()
        .is_empty()
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with('#') || t.starts_with("/*") || t.starts_with('*')
}

/// Extract an arrow-function name: `const foo = (...) => {` → "foo".
fn extract_arrow_name(line: &str) -> Option<String> {
    let t = line.trim();
    if let Some(eq) = t.find('=') {
        let lhs = t[..eq].trim();
        let name = lhs.split_whitespace().last().unwrap_or("").trim();
        if !name.is_empty()
            && !name.contains('(')
            && name.chars().next().map(|c| c.is_alphabetic() || c == '_').unwrap_or(false)
        {
            return Some(name.to_string());
        }
    }
    None
}

/// Extract parameter names from a function signature line.
fn extract_params(line: &str) -> Vec<String> {
    let Some(open) = line.find('(') else {
        return Vec::new();
    };
    let rest = &line[open + 1..];
    let Some(close) = find_matching_paren(rest) else {
        return Vec::new();
    };
    let inner = &rest[..close];
    let mut params = Vec::new();
    for part in inner.split(',') {
        let p = part.trim();
        if p.is_empty() || p == "..." {
            continue;
        }
        // Strip `mut`, type annotations (`x: String`), defaults (`x = 1`),
        // and pointer/ref prefixes.
        let mut name = p;
        for prefix in ["mut ", "let ", "const ", "var ", "&", "*"] {
            if name.starts_with(prefix) && name.len() > prefix.len() {
                name = name[prefix.len()..].trim_start();
            }
        }
        if name == "self" || name == "this" || name.is_empty() {
            continue;
        }
        if let Some(eq) = name.find('=') {
            name = &name[..eq];
        }
        if let Some(colon) = name.find(':') {
            name = &name[..colon];
        }
        let name = name.trim().trim_matches(|c| c == '\'' || c == '"').to_string();
        if !name.is_empty()
            && name.chars().next().map(|c| c.is_alphabetic() || c == '_').unwrap_or(false)
            && !name.contains(' ')
        {
            params.push(name);
        }
    }
    params
}

/// Find the index of the matching `)` for a `(`-opened substring.
fn find_matching_paren(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn is_trace_ext(ext: &str) -> bool {
    matches!(
        ext,
        "rs" | "js" | "jsx" | "ts" | "tsx" | "py" | "go" | "rb" | "java" | "kt"
            | "swift" | "c" | "cpp" | "h" | "hpp" | "cs" | "php" | "vue" | "svelte"
    )
}

// ── Taint engine ────────────────────────────────────────────────────

/// A variable that is currently tainted, with its origin.
#[derive(Debug, Clone)]
struct TaintedVar {
    name: String,
    origin_line: usize,
    origin_file: String,
    origin_func: String,
}

/// Cross-file tracer. Holds references into the parsed function list.
struct Tracer<'a> {
    functions: &'a [FunctionDef],
    by_name: HashMap<String, Vec<&'a FunctionDef>>,
    query_focus: Vec<String>,
    max_depth: usize,
}

impl<'a> Tracer<'a> {
    fn new(functions: &'a [FunctionDef], query: &str, max_depth: usize) -> Self {
        let mut by_name: HashMap<String, Vec<&FunctionDef>> = HashMap::new();
        for f in functions {
            by_name.entry(f.name.to_lowercase()).or_default().push(f);
        }
        Self {
            functions,
            by_name,
            query_focus: focus_keywords(query),
            max_depth,
        }
    }

    /// Trace all taint paths across the whole codebase.
    fn trace_all(&self) -> Vec<TaintPath> {
        let mut paths = Vec::new();
        let mut visited: HashSet<(String, String)> = HashSet::new();
        for func in self.functions {
            let found = self.trace_function(func, Vec::new(), 0, &mut visited);
            paths.extend(found);
        }
        paths
    }

    /// Analyze one function body given optionally-pre-tainted params.
    /// Returns every path found starting from this function.
    fn trace_function(
        &self,
        func: &'a FunctionDef,
        pre_tainted: Vec<TaintedVar>,
        depth: usize,
        visited: &mut HashSet<(String, String)>,
    ) -> Vec<TaintPath> {
        let mut result = Vec::new();
        let mut tainted: Vec<TaintedVar> = pre_tainted;
        let mut steps: Vec<TraceStep> = Vec::new();

        for (line_num, line) in &func.body {
            let line = line.clone();
            let lower = line.to_lowercase();

            // 1. New sources
            if let Some(var) = source_var(&line) {
                if !tainted.iter().any(|t| t.name == var) {
                    tainted.push(TaintedVar {
                        name: var.clone(),
                        origin_line: *line_num,
                        origin_file: func.file.clone(),
                        origin_func: func.name.clone(),
                    });
                    steps.push(TraceStep {
                        file: func.file.clone(),
                        line: *line_num,
                        function: func.name.clone(),
                        action: "source".to_string(),
                        detail: format!("untrusted input enters '{}'", var),
                    });
                }
                continue;
            }

            // 2. Propagation through assignments (never through sanitizers)
            let sanitized_line = SANITIZERS.iter().any(|s| lower.contains(s));
            if !sanitized_line {
                if let Some((lhs, _rhs)) = split_assignment(&line) {
                    // Clone the source so we don't hold a borrow into `tainted`
                    // while pushing the propagated variable (E0502).
                    let src = tainted
                        .iter()
                        .find(|t| line_uses(&line, &t.name) && !line_uses(&lhs, &t.name))
                        .cloned();
                    if let Some(src) = src {
                        if !tainted.iter().any(|t| t.name == lhs) {
                            tainted.push(TaintedVar {
                                name: lhs.clone(),
                                origin_line: src.origin_line,
                                origin_file: src.origin_file.clone(),
                                origin_func: src.origin_func.clone(),
                            });
                            steps.push(TraceStep {
                                file: func.file.clone(),
                                line: *line_num,
                                function: func.name.clone(),
                                action: "flow".to_string(),
                                detail: format!("'{}' ← tainted '{}'", lhs, src.name),
                            });
                        }
                    }
                }
            }

            // 3. Direct sink check (skip sanitizer lines)
            if !SANITIZERS.iter().any(|s| lower.contains(s)) {
                if let Some(sink) = sink_hit(&line, &tainted, &self.query_focus) {
                    let source_summary = steps
                        .first()
                        .map(|s| format!("{}:{} — {}", s.file, s.line, s.detail))
                        .unwrap_or_else(|| format!("{}:{}", func.file, func.start_line));
                    let mut path_steps = steps.clone();
                    path_steps.push(TraceStep {
                        file: func.file.clone(),
                        line: *line_num,
                        function: func.name.clone(),
                        action: "sink".to_string(),
                        detail: format!("tainted data reaches '{}'", sink),
                    });
                    result.push(TaintPath {
                        id: String::new(), // assigned at dedup time
                        title: format!("user input reaches {}", sink),
                        description: format!(
                            "Untrusted data flows to '{}' at {}:{}. No sanitization was detected on this path.",
                            sink, func.file, line_num
                        ),
                        risk_score: risk_for_sink(&sink, steps.len()),
                        source: source_summary,
                        sink: format!("{}:{} — {}", func.file, line_num, sink),
                        steps: path_steps,
                    });
                    continue;
                }
            }

            // 4. Cross-file call tracing
            if depth < self.max_depth {
                for call in extract_calls(&line) {
                    let (callee, args) = call;
                    let callee_lower = callee.to_lowercase();
                    // Only follow if a tainted variable is among the args
                    let tainted_args: Vec<usize> = args
                        .iter()
                        .enumerate()
                        .filter_map(|(idx, arg)| {
                            tainted.iter().any(|t| line_uses(arg, &t.name)).then_some(idx)
                        })
                        .collect();
                    if tainted_args.is_empty() {
                        continue;
                    }
                    // Resolve the callee (prefer same file, then others)
                    let candidates: Vec<&FunctionDef> = self
                        .by_name
                        .get(&callee_lower)
                        .cloned()
                        .unwrap_or_default();
                    let same_file: Vec<&FunctionDef> = candidates
                        .iter()
                        .copied()
                        .filter(|c| c.file == func.file)
                        .collect();
                    let chosen: Vec<&FunctionDef> = if same_file.is_empty() {
                        candidates
                    } else {
                        same_file
                    };

                    for candidate in chosen.into_iter().take(2) {
                        // Map tainted args to callee params by position
                        let mut pre = Vec::new();
                        for &idx in &tainted_args {
                            if let Some(param) = candidate.param_at(idx) {
                                if let Some(t) = tainted.iter().find(|t| line_uses(&args[idx], &t.name)).cloned() {
                                    pre.push(TaintedVar {
                                        name: param.to_string(),
                                        origin_line: t.origin_line,
                                        origin_file: t.origin_file,
                                        origin_func: t.origin_func,
                                    });
                                }
                            }
                        }
                        if pre.is_empty() {
                            continue;
                        }
                        // Cycle guard
                        let key = (candidate.name.to_lowercase(), pre[0].name.clone());
                        if !visited.insert(key) {
                            continue;
                        }

                        // Record the call hop, then recurse
                        let mut call_steps = steps.clone();
                        call_steps.push(TraceStep {
                            file: func.file.clone(),
                            line: *line_num,
                            function: func.name.clone(),
                            action: "call".to_string(),
                            detail: format!(
                                "calls {}({}) with tainted data",
                                callee,
                                args.iter()
                                    .enumerate()
                                    .filter_map(|(i, a)| tainted_args.contains(&i).then_some(a.as_str()))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                        });

                        let child_paths = self.trace_function(candidate, pre, depth + 1, visited);
                        for mut p in child_paths {
                            let mut combined = call_steps.clone();
                            combined.extend(p.steps.clone());
                            p.steps = combined;
                            result.push(p);
                        }
                    }
                }
            }
        }

        result
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Extract a variable that is assigned directly from a taint source.
fn source_var(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.contains('=')
        && !trimmed.contains("==")
        && !trimmed.contains("!=")
        && !trimmed.contains(">=")
        && !trimmed.contains("<=")
    {
        if let Some(eq) = trimmed.find('=') {
            let lhs = trimmed[..eq].trim();
            let rhs = trimmed[eq + 1..].trim();
            let rhs_lower = rhs.to_lowercase();
            if TAINT_SOURCES.iter().any(|s| rhs_lower.contains(s)) {
                let var = lhs
                    .split_whitespace()
                    .last()
                    .unwrap_or("")
                    .trim_matches(|c| c == ';' || c == ',')
                    .to_string();
                // Must be a plain identifier: starts with a letter/_ and has no
                // operators — rejects junk like "!" or ">=" from != / >= lines.
                let is_identifier = !var.is_empty()
                    && var.chars().all(|c| c.is_alphanumeric() || c == '_')
                    && var
                        .chars()
                        .next()
                        .map(|c| c.is_alphabetic() || c == '_')
                        .unwrap_or(false);
                if is_identifier && var != "let" && var != "const" && var != "var" {
                    return Some(var);
                }
            }
        }
    }
    None
}

/// Split `x = y` into (lhs, rhs), ignoring comparisons.
fn split_assignment(line: &str) -> Option<(String, String)> {
    let t = line.trim();
    if t.contains('=') && !t.contains("==") && !t.contains(">=") && !t.contains("<=") {
        if let Some(eq) = t.find('=') {
            let lhs = t[..eq].trim();
            let rhs = t[eq + 1..].trim();
            let lhs_var = lhs
                .split_whitespace()
                .last()
                .unwrap_or("")
                .trim_matches(';')
                .to_string();
            if !lhs_var.is_empty() && !lhs_var.contains('(') {
                return Some((lhs_var, rhs.to_string()));
            }
        }
    }
    None
}

/// Does `line` reference `var` as a whole word?
fn line_uses(line: &str, var: &str) -> bool {
    if var.is_empty() {
        return false;
    }
    let lower_line = line.to_lowercase();
    let lower_var = var.to_lowercase();
    lower_line
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|w| w == lower_var)
}

/// Extract `callee(arg1, arg2, ...)` calls from a line.
fn extract_calls(line: &str) -> Vec<(String, Vec<String>)> {
    let mut calls = Vec::new();
    let bytes: Vec<char> = line.chars().collect();
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == '(' {
            // Walk back to the callee name
            let mut j = i;
            let mut name = String::new();
            while j > 0 {
                j -= 1;
                let c = bytes[j];
                if c.is_alphanumeric() || c == '_' || c == '.' || c == ':' {
                    name.insert(0, c);
                } else {
                    break;
                }
            }
            let name = name.trim_matches('.').to_string();
            if !name.is_empty() && name.chars().next().map(|c| c.is_alphabetic()).unwrap_or(false) {
                // Find matching close paren
                let mut depth = 0i32;
                let mut end = i;
                let mut args = Vec::new();
                let mut current = String::new();
                let mut done = false;
                for (k, c) in bytes.iter().enumerate().skip(i + 1) {
                    match c {
                        '(' => depth += 1,
                        ')' => {
                            if depth == 0 {
                                end = k;
                                if !current.trim().is_empty() {
                                    args.push(current.trim().to_string());
                                }
                                done = true;
                                break;
                            }
                            depth -= 1;
                        }
                        ',' if depth == 0 => {
                            if !current.trim().is_empty() {
                                args.push(current.trim().to_string());
                            }
                            current.clear();
                            continue;
                        }
                        _ => {}
                    }
                    if depth >= 0 {
                        current.push(*c);
                    }
                }
                if done {
                    calls.push((name, args));
                    i = end + 1;
                    continue;
                }
            }
        }
        i += 1;
    }

    calls
}

/// Check if a line hits a sink with tainted data. Returns the sink token.
fn sink_hit(line: &str, tainted: &[TaintedVar], focus: &[String]) -> Option<String> {
    let lower = line.to_lowercase();
    let mut candidates: Vec<&str> = Vec::new();
    if !focus.is_empty() {
        for kw in focus {
            if lower.contains(&kw.to_lowercase()) {
                candidates.push(kw.as_str());
            }
        }
    }
    for sink in TAINT_SINKS {
        if lower.contains(sink) {
            candidates.push(sink);
        }
    }
    if candidates.is_empty() {
        return None;
    }
    if tainted.iter().any(|t| line_uses(line, &t.name)) {
        candidates.first().map(|s| s.to_string())
    } else {
        None
    }
}

/// Map a natural-language query to sink keywords.
fn focus_keywords(query: &str) -> Vec<String> {
    let q = query.to_lowercase();
    let mut focus = Vec::new();
    let admin_terms = [
        "admin", "privilege", "escalat", "become", "role", "permission", "is_admin",
        "authorize", "sudo", "access control",
    ];
    let injection_terms = [
        "inject", "sql", "command", "exec", "eval", "shell", "xss", "ssrf",
    ];
    let data_terms = [
        "exfil", "leak", "data", "read", "write", "delete", "file", "payment", "secret",
    ];
    for kw in admin_terms {
        if q.contains(kw) {
            focus.extend([
                "is_admin".to_string(),
                "admin".to_string(),
                "grant".to_string(),
                "role".to_string(),
                "permission".to_string(),
            ]);
            break;
        }
    }
    for kw in injection_terms {
        if q.contains(kw) {
            focus.extend([
                "exec".to_string(),
                "eval".to_string(),
                "query".to_string(),
                "system".to_string(),
            ]);
            break;
        }
    }
    for kw in data_terms {
        if q.contains(kw) {
            focus.extend([
                "write".to_string(),
                "open".to_string(),
                "delete".to_string(),
                "query".to_string(),
            ]);
            break;
        }
    }
    focus
}

/// Risk score for a sink given path length.
fn risk_for_sink(sink: &str, hops: usize) -> f64 {
    let base = if sink == "exec" || sink == "system" || sink == "eval" {
        9.0
    } else if sink == "is_admin" || sink == "admin" || sink == "grant" {
        8.5
    } else if sink.contains("query") || sink == "open" || sink == "write" {
        7.5
    } else {
        6.0
    };
    (base + hops as f64 * 0.3).min(10.0)
}

// ── Public API ──────────────────────────────────────────────────────

/// Run the `cipher-ai trace` command — cross-file taint-flow reasoning.
pub async fn run_trace(
    project_path: &Path,
    query: &str,
    depth: usize,
    json_output: bool,
    use_ai: bool,
) -> Result<()> {
    let canonical_path = std::fs::canonicalize(project_path)?;
    let max_depth = if depth == 0 { DEFAULT_DEPTH } else { depth };

    println!(
        "{} {}\n",
        "[FLOW]".bright_cyan().bold(),
        "CipherAI Cross-File Taint Trace".bold()
    );
    if !query.is_empty() {
        println!("  {} Query: {}\n", "[?]".yellow(), query.yellow().bold());
    }

    println!("  {} Parsing functions across the codebase...", "[*]".cyan());
    let functions = collect_functions(&canonical_path);
    println!(
        "  {} Found {} functions",
        "[OK]".green(),
        functions.len().to_string().bold()
    );

    if functions.is_empty() {
        println!("  {} No source files to analyze.", "[-]".yellow());
        return Ok(());
    }

    println!(
        "  {} Tracing untrusted data → dangerous sinks (depth: {})...\n",
        "[*]".cyan(),
        max_depth
    );

    let tracer = Tracer::new(&functions, query, max_depth);
    let mut paths = tracer.trace_all();

    // Sort by risk first, then deduplicate by (source, sink). dedup_by only
    // removes *consecutive* duplicates, so sorting ensures all copies of the
    // same path sit next to each other and only the highest-risk one survives.
    paths.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    paths.dedup_by(|a, b| a.source == b.source && a.sink == b.sink);
    for (i, p) in paths.iter_mut().enumerate() {
        p.id = format!("TRACE-{}", i + 1);
    }

    if paths.is_empty() {
        println!(
            "  {} No taint paths found for '{}'. Data may be sanitized, isolated, or the codebase doesn't touch these APIs.",
            "[OK]".green(),
            query
        );
        println!("  Tip: try a more specific query like 'user input reaches admin check'.");
        return Ok(());
    }

    if use_ai {
        println!("  {} Enriching top paths with AI analysis...", "[AI]".cyan());
        if let Err(e) = enrich_paths_ai(&mut paths, query).await {
            eprintln!(
                "  {} AI enrichment failed: {} (continuing with rule-based results)",
                "[!]".yellow(),
                e
            );
        }
    }

    if json_output {
        display_paths_json(&paths, query);
    } else {
        display_paths(&paths);
    }

    println!();
    println!("  {}", "-".repeat(50).dimmed());
    println!(
        "  {} Discovered {} taint path(s) — {} reach the highest-risk sinks",
        "[STATS]".bold(),
        paths.len().to_string().bold().red(),
        paths
            .iter()
            .filter(|p| p.risk_score >= 8.0)
            .count()
            .to_string()
            .bold()
    );
    if let Some(top) = paths.first() {
        println!();
        println!("  {} Priority path:", "[TARGET]".bold());
        println!("    {} {}", "[FLOW]".cyan(), top.title.bold());
        println!(
            "    {} {}  →  {}",
            "->".bold(),
            top.source.yellow(),
            top.sink.red().bold()
        );
    }

    Ok(())
}

/// Enrich path descriptions with AI analysis.
async fn enrich_paths_ai(paths: &mut [TaintPath], query: &str) -> Result<()> {
    let client = match GroqClient::from_env() {
        Ok(c) => c,
        Err(_) => return Ok(()), // no API key — skip
    };

    let to_enrich = paths.len().min(5);
    for i in 0..to_enrich {
        let path = &paths[i];
        let steps_text: Vec<String> = path
            .steps
            .iter()
            .map(|s| {
                format!(
                    "- {}:{} [{}] {}",
                    s.file.rsplit('/').next().unwrap_or(&s.file),
                    s.line,
                    s.action,
                    s.detail
                )
            })
            .collect();

        let system_prompt = "You are Cipher, an expert application security engineer. You analyze taint-flow paths traced across a codebase and explain the security impact of each path. Respond with JSON only: {\"explanation\": \"...\"} (2-3 sentences: what an attacker controls, what they reach, and how to fix it).";
        let user_prompt = format!(
            "Question: {query}\n\nTaint path (source → sink):\n{steps}\n\nExplain the security impact and remediation. JSON only.\n",
            query = query,
            steps = steps_text.join("\n")
        );

        if let Ok(response) = client.chat(system_prompt, &user_prompt, None).await {
            if let Some(explanation) = parse_explanation(&response) {
                paths[i].description = explanation;
            }
        }
    }

    Ok(())
}

fn parse_explanation(response: &str) -> Option<String> {
    let json_str = if let Some(start) = response.find('{') {
        let end = response[start..]
            .rfind('}')
            .map(|i| start + i + 1)
            .unwrap_or(response.len());
        &response[start..end]
    } else {
        return None;
    };

    #[derive(serde::Deserialize)]
    struct Enrichment {
        explanation: Option<String>,
    }

    serde_json::from_str::<Enrichment>(json_str)
        .ok()
        .and_then(|e| e.explanation)
}

/// Display taint paths in pretty terminal format.
fn display_paths(paths: &[TaintPath]) {
    println!();
    println!(
        "{} {}\n",
        "[FLOW]".bold(),
        "Taint Paths Discovered".bold().red()
    );

    for (i, path) in paths.iter().enumerate() {
        let risk_color = if path.risk_score >= 8.0 {
            "red"
        } else if path.risk_score >= 5.0 {
            "yellow"
        } else {
            "green"
        };
        println!("  {}", "=".repeat(60).dimmed());
        println!(
            "  {} {} {}  Risk: {:.1}/10",
            "#".bold().dimmed(),
            (i + 1).to_string().bold(),
            path.title.bold().color(risk_color),
            path.risk_score
        );

        println!();
        println!("    {} Data Flow:", "[SYNC]".bold());
        for (idx, step) in path.steps.iter().enumerate() {
            let file_short = step.file.rsplit('/').next().unwrap_or(&step.file);
            let label = match step.action.as_str() {
                "source" => format!("[SOURCE] {}", step.detail).yellow().to_string(),
                "sink" => format!("[SINK] {}", step.detail).red().bold().to_string(),
                "call" => format!("[CALL] {}", step.detail).cyan().to_string(),
                _ => format!("[FLOW] {}", step.detail).dimmed().to_string(),
            };
            let arrow = if idx == 0 {
                "  +-".cyan().to_string()
            } else if idx == path.steps.len() - 1 {
                "  +->".cyan().to_string()
            } else {
                "  | ".cyan().to_string()
            };
            println!(
                "      {} {}{}:{}",
                arrow,
                label,
                file_short.yellow(),
                step.line.to_string().dimmed()
            );
        }

        println!();
        println!("    {} Description:", "[NOTE]".bold());
        for line in path.description.lines() {
            println!("      {}", line);
        }
        println!();
    }
}

/// Display taint paths as JSON.
fn display_paths_json(paths: &[TaintPath], query: &str) {
    #[derive(Serialize)]
    struct PathsOutput<'a> {
        total_paths: usize,
        query: &'a str,
        paths: &'a [TaintPath],
    }

    let output = PathsOutput {
        total_paths: paths.len(),
        query,
        paths,
    };
    match serde_json::to_string_pretty(&output) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("{} JSON serialization failed: {}", "[ERR]".red(), e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_params_simple() {
        assert_eq!(extract_params("fn foo(a, b: String, mut c) -> i32 {"), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_extract_params_python() {
        assert_eq!(extract_params("def login(username, password):"), vec!["username", "password"]);
    }

    #[test]
    fn test_extract_params_js() {
        assert_eq!(extract_params("function checkRole(user, role) {"), vec!["user", "role"]);
    }

    #[test]
    fn test_source_var() {
        assert_eq!(source_var("let name = request.body.name"), Some("name".to_string()));
        assert_eq!(source_var("const uid = req.query.uid"), Some("uid".to_string()));
        assert_eq!(source_var("let x = 5;"), None);
    }

    #[test]
    fn test_line_uses() {
        assert!(line_uses("admin(user_id)", "user_id"));
        assert!(!line_uses("admin(user_id)", "user"));
    }

    #[test]
    fn test_extract_calls() {
        let calls = extract_calls("let ok = is_admin(user_id, role);");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "is_admin");
        assert_eq!(calls[0].1, vec!["user_id", "role"]);
    }

    #[test]
    fn test_extract_calls_multiple() {
        let calls = extract_calls("foo(a); bar(b, c);");
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn test_focus_keywords_admin() {
        let focus = focus_keywords("can users become admin?");
        assert!(focus.contains(&"is_admin".to_string()));
        assert!(focus.contains(&"admin".to_string()));
    }

    #[test]
    fn test_focus_keywords_injection() {
        let focus = focus_keywords("is this SQL injectable?");
        assert!(focus.contains(&"exec".to_string()));
    }

    #[test]
    fn test_risk_for_sink() {
        assert!(risk_for_sink("exec", 1) > risk_for_sink("query", 1));
        assert!(risk_for_sink("exec", 1) <= 10.0);
    }

    #[test]
    fn test_parse_functions_basic() {
        let lines = vec![
            "fn main() {".to_string(),
            "    let x = request.body;".to_string(),
            "    foo(x);".to_string(),
            "}".to_string(),
        ];
        let fns = parse_functions(&lines, "app.rs", "rs");
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].name, "main");
        assert_eq!(fns[0].body.len(), 2);
    }

    #[test]
    fn test_trace_single_file_source_to_sink() {
        let lines = vec![
            "fn handle(req) {".to_string(),
            "    let name = req.body.name;".to_string(),
            "    exec(name);".to_string(),
            "}".to_string(),
        ];
        let fns = parse_functions(&lines, "app.js", "js");
        let tracer = Tracer::new(&fns, "injection", 3);
        let paths = tracer.trace_all();
        assert!(!paths.is_empty(), "expected at least one taint path");
        assert_eq!(paths[0].steps[0].action, "source");
        assert_eq!(paths[0].steps.last().unwrap().action, "sink");
    }

    #[test]
    fn test_trace_cross_file() {
        // app.js: handle() takes req, passes name into validateAndExec in lib.js
        let app = vec![
            "fn handle(req) {".to_string(),
            "    let name = req.body.name;".to_string(),
            "    validateAndExec(name);".to_string(),
            "}".to_string(),
        ];
        let lib = vec![
            "fn validateAndExec(name) {".to_string(),
            "    exec(name);".to_string(),
            "}".to_string(),
        ];
        let mut fns = parse_functions(&app, "app.js", "js");
        fns.extend(parse_functions(&lib, "lib.js", "js"));
        let tracer = Tracer::new(&fns, "injection", 4);
        let paths = tracer.trace_all();
        assert!(!paths.is_empty(), "expected cross-file taint path");
        assert!(
            paths.iter().any(|p| p.steps.iter().any(|s| s.action == "call")),
            "expected a cross-file call hop in the path"
        );
    }

    #[test]
    fn test_arrow_function_name() {
        let lines = vec![
            "const checkAdmin = (user) => {".to_string(),
            "  let role = user.role;".to_string(),
            "  is_admin(user, role);".to_string(),
            "}".to_string(),
        ];
        let fns = parse_functions(&lines, "auth.js", "js");
        assert_eq!(fns.len(), 1);
        assert_eq!(fns[0].name, "checkAdmin");
    }
}
