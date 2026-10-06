/// Exported function names of a file, mapped to their index in `functions`.
/// JS/TS: `module.exports = { a, b: c }`, `exports.a = b`, `export function
/// a`, `export { a, b as c }`, `export default function a` / `export default
/// a` (under the conventional `default` key). Python: every top-level function. Go: every
/// package-level function (same-package visibility; cross-package callers
/// see only capitalized names, filtered at the binding). Java: the static,
/// non-private methods of the file's class. Rust: the `pub` free functions.
#[allow(clippy::items_after_test_module)]
fn flow_exports(
    lines: &[&str],
    language: FlowLanguage,
    functions: &[FlowFunction],
) -> std::collections::HashMap<String, usize> {
    let mut exported = std::collections::HashMap::new();
    let find = |local: &str| {
        functions
            .iter()
            .position(|function| function.name == local && !function.method)
    };
    if language == FlowLanguage::Python {
        for (index, function) in functions.iter().enumerate() {
            let top_level = lines
                .get(function.header)
                .is_some_and(|line| !line.starts_with(char::is_whitespace));
            if top_level && !function.method {
                exported.insert(function.name.clone(), index);
            }
        }
        return exported;
    }
    if language == FlowLanguage::Go {
        for (index, function) in functions.iter().enumerate() {
            exported.insert(function.name.clone(), index);
        }
        return exported;
    }
    if language == FlowLanguage::Java {
        for (index, function) in functions.iter().enumerate() {
            let Some(header) = lines.get(function.header) else {
                continue;
            };
            let words: std::collections::HashSet<&str> = header
                .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                .collect();
            if words.contains("static") && !words.contains("private") {
                exported.insert(function.name.clone(), index);
            }
        }
        return exported;
    }
    let is_identifier = |text: &str| {
        !text.is_empty()
            && text
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
    };
    if language == FlowLanguage::Rust {
        for (index, function) in functions.iter().enumerate() {
            let Some(header) = lines.get(function.header) else {
                continue;
            };
            let words: std::collections::HashSet<&str> = header
                .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                .collect();
            if words.contains("pub") && !function.method {
                exported.insert(function.name.clone(), index);
            }
        }
        return exported;
    }
    let (
        Ok(object_start),
        Ok(property),
        Ok(export_decl),
        Ok(export_list),
        Ok(export_default_fn),
        Ok(export_default_ref),
    ) = (
        Regex::new(r#"^\s*module\s*\.\s*exports\s*=\s*\{(.*)$"#),
        Regex::new(
            r#"^\s*(?:module\s*\.\s*)?exports\s*\.\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*;?\s*$"#,
        ),
        Regex::new(
            r#"^\s*export\s+(?:async\s+)?(?:function\s*\*?\s*|const\s+|let\s+|var\s+)([A-Za-z_$][A-Za-z0-9_$]*)"#,
        ),
        Regex::new(r#"^\s*export\s*\{([^}]*)\}"#),
        Regex::new(
            r#"^\s*export\s+default\s+(?:async\s+)?function\s*\*?\s*([A-Za-z_$][A-Za-z0-9_$]*)"#,
        ),
        Regex::new(r#"^\s*export\s+default\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*;?\s*$"#),
    )
    else {
        return exported;
    };
    let add_entries =
        |text: &str, separator: &str, exported: &mut std::collections::HashMap<String, usize>| {
            for entry in text.split(',') {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                let (left, right) = match entry.split_once(separator) {
                    Some((left, right)) => (left.trim(), right.trim()),
                    None => (entry, entry),
                };
                // `module.exports = { key: local }` / `export { local as key }`.
                let (key, local) = if separator == ":" {
                    (left, right)
                } else {
                    (right, left)
                };
                if is_identifier(key) && is_identifier(local) {
                    if let Some(index) = find(local) {
                        exported.insert(key.to_string(), index);
                    }
                }
            }
        };
    let mut in_object = false;
    for line in lines {
        let code = line.split("//").next().unwrap_or("");
        if in_object {
            let (body, done) = match code.split_once('}') {
                Some((body, _)) => (body, true),
                None => (code, false),
            };
            add_entries(body, ":", &mut exported);
            in_object = !done;
            continue;
        }
        if let Some(rest) = object_start.captures(code).and_then(|c| c.get(1)) {
            let rest = rest.as_str();
            match rest.split_once('}') {
                Some((body, _)) => add_entries(body, ":", &mut exported),
                None => {
                    add_entries(rest, ":", &mut exported);
                    in_object = true;
                }
            }
            continue;
        }
        if let Some(captures) = property.captures(code) {
            if let (Some(key), Some(local)) = (captures.get(1), captures.get(2)) {
                if let Some(index) = find(local.as_str()) {
                    exported.insert(key.as_str().to_string(), index);
                }
            }
            continue;
        }
        // `export default function f` / `export default f` register the
        // function under the conventional `default` key that default imports
        // look up.
        if let Some(name) = export_default_fn.captures(code).and_then(|c| c.get(1)) {
            if let Some(index) = find(name.as_str()) {
                exported.insert("default".to_string(), index);
            }
            continue;
        }
        if let Some(name) = export_default_ref.captures(code).and_then(|c| c.get(1)) {
            if let Some(index) = find(name.as_str()) {
                exported.insert("default".to_string(), index);
            }
            continue;
        }
        if let Some(name) = export_decl.captures(code).and_then(|c| c.get(1)) {
            if let Some(index) = find(name.as_str()) {
                exported.insert(name.as_str().to_string(), index);
            }
            continue;
        }
        if let Some(list) = export_list.captures(code).and_then(|c| c.get(1)) {
            add_entries(list.as_str(), " as ", &mut exported);
        }
    }
    exported
}

/// The directory a Rust file's `mod name;` declarations and `self::` paths
/// resolve against: `main.rs`/`lib.rs`/`mod.rs` use their own directory,
/// any other file uses a same-named subdirectory.
#[allow(clippy::items_after_test_module)]
fn rust_module_dir(path: &Path) -> Option<std::path::PathBuf> {
    let dir = path.parent()?;
    let stem = path.file_stem()?.to_string_lossy();
    if matches!(stem.as_ref(), "main" | "lib" | "mod") {
        Some(dir.to_path_buf())
    } else {
        Some(dir.join(stem.as_ref()))
    }
}

/// The crate root of a Rust file: the nearest ancestor directory, within the
/// project root, that holds `main.rs` or `lib.rs`.
#[allow(clippy::items_after_test_module)]
fn rust_crate_root(dir: &Path, root: &Path) -> Option<std::path::PathBuf> {
    let mut candidate = Some(dir);
    while let Some(path) = candidate {
        if path.join("main.rs").is_file() || path.join("lib.rs").is_file() {
            return Some(path.to_path_buf());
        }
        if path == root {
            break;
        }
        candidate = path.parent();
    }
    None
}

/// A Rust `mod name;` declaration or `use` path found in one file.
enum RustDeclaration {
    Mod(String),
    Use {
        segments: Vec<String>,
        alias: Option<String>,
        reexport: bool,
    },
}

/// The `mod`/`use` declarations of a Rust file. Grouped `use a::{b, c}`
/// items are expanded to one declaration each (`as` aliases and a `*` glob
/// item included); nested groups (`use a::{b::{c, d}}`) and nested path
/// items (`use a::{b::c, d}`) flatten to their full segment lists, a
/// tree spanning several lines is joined before flattening (bounded, so
/// an unterminated tree is skipped), and `pub use` re-exports are
/// recognized and flagged so the cross-file pass can resolve one hop
/// through them.
#[allow(clippy::items_after_test_module)]
fn rust_declarations(lines: &[&str]) -> Vec<RustDeclaration> {
    let mut declarations = Vec::new();
    let (Ok(mod_decl), Ok(use_decl)) = (
        Regex::new(r#"^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;"#),
        Regex::new(r#"^\s*(pub\s+)?use\s+(.+?)\s*;"#),
    ) else {
        return declarations;
    };
    let use_start = Regex::new(r#"^\s*(?:pub\s+)?use\s"#).ok();
    let mut index = 0;
    while index < lines.len() {
        let code = lines[index].split("//").next().unwrap_or("");
        if let Some(name) = mod_decl.captures(code).and_then(|c| c.get(1)) {
            declarations.push(RustDeclaration::Mod(name.as_str().to_string()));
            index += 1;
            continue;
        }
        if use_start.as_ref().is_some_and(|re| re.is_match(code)) {
            // A `use` tree may span several lines: join comment-stripped
            // lines with spaces until the braces balance and the final
            // `;` appears, bounded so an unterminated tree is skipped.
            let mut joined = String::new();
            let mut balance = 0i32;
            let mut end = index;
            while end < lines.len() && end - index < 40 {
                let piece = lines[end].split("//").next().unwrap_or("");
                balance += piece.matches('{').count() as i32;
                balance -= piece.matches('}').count() as i32;
                if !joined.is_empty() {
                    joined.push(' ');
                }
                joined.push_str(piece.trim_end());
                end += 1;
                if balance <= 0 && piece.contains(';') {
                    break;
                }
            }
            if let Some(captures) = use_decl.captures(&joined) {
                let reexport = captures.get(1).is_some();
                let body = captures.get(2).map(|m| m.as_str()).unwrap_or("");
                for (segments, alias) in expand_use_tree(body) {
                    declarations.push(RustDeclaration::Use {
                        segments,
                        alias,
                        reexport,
                    });
                }
            }
            index = end.max(index + 1);
            continue;
        }
        index += 1;
    }
    declarations
}

/// Every leaf of one `use` tree: the full segment list plus an optional
/// `as` alias. `body` is the text between `use` and the final `;`.
fn expand_use_tree(body: &str) -> Vec<(Vec<String>, Option<String>)> {
    let mut leaves = Vec::new();
    let mut cursor = body.trim();
    expand_use_tree_at(&mut Vec::new(), &mut cursor, &mut leaves);
    leaves
}

/// Parses one tree from the front of `cursor`, appending each leaf reached
/// to `leaves`. `prefix` carries the segments enclosing groups already
/// consumed; a malformed tail abandons only its own branch.
fn expand_use_tree_at(
    prefix: &mut Vec<String>,
    cursor: &mut &str,
    leaves: &mut Vec<(Vec<String>, Option<String>)>,
) {
    loop {
        *cursor = cursor.trim_start();
        if let Some(rest) = cursor.strip_prefix('{') {
            *cursor = rest;
            expand_use_group_at(prefix, cursor, leaves);
            return;
        }
        let Some(name) = take_use_ident(cursor) else {
            return;
        };
        prefix.push(name);
        *cursor = cursor.trim_start();
        if let Some(rest) = cursor.strip_prefix("as") {
            if rest.chars().next().is_some_and(char::is_whitespace) {
                *cursor = rest.trim_start();
                if let Some(alias) = take_use_ident(cursor) {
                    leaves.push((prefix.clone(), Some(alias)));
                }
                return;
            }
        }
        if let Some(rest) = cursor.strip_prefix("::") {
            *cursor = rest;
            continue;
        }
        leaves.push((prefix.clone(), None));
        return;
    }
}

/// Parses the comma-separated trees of one `{ ... }` group, each extending
/// `prefix`, through the closing brace.
fn expand_use_group_at(
    prefix: &[String],
    cursor: &mut &str,
    leaves: &mut Vec<(Vec<String>, Option<String>)>,
) {
    loop {
        *cursor = cursor.trim_start();
        if let Some(rest) = cursor.strip_prefix('}') {
            *cursor = rest;
            return;
        }
        if cursor.is_empty() {
            return;
        }
        let mut branch = prefix.to_owned();
        expand_use_tree_at(&mut branch, cursor, leaves);
        *cursor = cursor.trim_start();
        if let Some(rest) = cursor.strip_prefix(',') {
            *cursor = rest;
            continue;
        }
        if let Some(rest) = cursor.strip_prefix('}') {
            *cursor = rest;
        }
        return;
    }
}

/// Takes one tree item (`*` or an identifier) from the front of `cursor`.
fn take_use_ident(cursor: &mut &str) -> Option<String> {
    if let Some(rest) = cursor.strip_prefix('*') {
        *cursor = rest;
        return Some("*".to_string());
    }
    let len: usize = cursor
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .map(char::len_utf8)
        .sum();
    let ident = &cursor[..len];
    if ident
        .chars()
        .next()
        .is_none_or(|c| !(c.is_ascii_alphabetic() || c == '_'))
    {
        return None;
    }
    let ident = ident.to_string();
    *cursor = &cursor[len..];
    Some(ident)
}

/// The `package` clause of a Go file; files sharing it in one directory
/// share a namespace.
#[allow(clippy::items_after_test_module)]
fn go_package_clause(lines: &[&str]) -> Option<String> {
    let package = Regex::new(r#"^\s*package\s+([A-Za-z_][A-Za-z0-9_]*)"#).ok()?;
    lines.iter().find_map(|line| {
        package
            .captures(line.split("//").next().unwrap_or(""))
            .and_then(|captures| captures.get(1))
            .map(|name| name.as_str().to_string())
    })
}

/// The `package` statement of a Java file; `None` for the default package.
#[allow(clippy::items_after_test_module)]
fn java_package_clause(lines: &[&str]) -> Option<String> {
    static PACKAGE: std::sync::LazyLock<Option<Regex>> = std::sync::LazyLock::new(|| {
        Regex::new(r#"^\s*package\s+([A-Za-z_][A-Za-z0-9_.]*)\s*;"#).ok()
    });
    let package = PACKAGE.as_ref()?;
    lines.iter().find_map(|line| {
        package
            .captures(line.split("//").next().unwrap_or(""))
            .and_then(|captures| captures.get(1))
            .map(|name| name.as_str().to_string())
    })
}

/// The first declared type name of a Java file, falling back to the file
/// stem (`UserService.java` conventionally declares `UserService`).
#[allow(clippy::items_after_test_module)]
fn java_class_name(lines: &[&str], path: &Path) -> Option<String> {
    static CLASS: std::sync::LazyLock<Option<Regex>> = std::sync::LazyLock::new(|| {
        Regex::new(r#"(?:^|\s)(?:class|interface|enum|record)\s+([A-Za-z_][A-Za-z0-9_]*)"#).ok()
    });
    let class = CLASS.as_ref()?;
    for line in lines {
        let code = line.split("//").next().unwrap_or("");
        if let Some(name) = class.captures(code).and_then(|captures| captures.get(1)) {
            return Some(name.as_str().to_string());
        }
    }
    path.file_stem()
        .map(|stem| stem.to_string_lossy().to_string())
}

/// Import specs of a Go file as `(alias, path)` pairs, from both
/// `import "path"` and the grouped `import ( ... )` form. Blank and dot
/// imports are skipped.
#[allow(clippy::items_after_test_module)]
fn go_import_specs(lines: &[&str]) -> Vec<(Option<String>, String)> {
    let mut specs = Vec::new();
    let (Ok(single), Ok(group_start), Ok(entry)) = (
        Regex::new(r#"^\s*import\s+(?:([A-Za-z_][A-Za-z0-9_]*|[._])\s+)?"([^"]+)""#),
        Regex::new(r#"^\s*import\s*\(\s*$"#),
        Regex::new(r#"^\s*(?:([A-Za-z_][A-Za-z0-9_]*|[._])\s+)?"([^"]+)""#),
    ) else {
        return specs;
    };
    let mut in_group = false;
    for line in lines {
        let code = line.split("//").next().unwrap_or("").trim();
        if in_group {
            if code.starts_with(')') {
                in_group = false;
                continue;
            }
            if let Some(captures) = entry.captures(code) {
                let alias = captures.get(1).map(|name| name.as_str().to_string());
                if !matches!(alias.as_deref(), Some("_")) {
                    let path = captures.get(2).map_or("", |spec| spec.as_str());
                    specs.push((alias, path.to_string()));
                }
            }
            continue;
        }
        if group_start.is_match(code) {
            in_group = true;
            continue;
        }
        if let Some(captures) = single.captures(code) {
            let alias = captures.get(1).map(|name| name.as_str().to_string());
            if !matches!(alias.as_deref(), Some("_")) {
                let path = captures.get(2).map_or("", |spec| spec.as_str());
                specs.push((alias, path.to_string()));
            }
        }
    }
    specs
}

/// One Java `import` statement.
enum JavaImport {
    /// `import a.b.C;`
    Class { package: String, class: String },
    /// `import a.b.*;`
    PackageWildcard { package: String },
    /// `import static a.b.C.f;`
    StaticMember {
        package: String,
        class: String,
        member: String,
    },
    /// `import static a.b.C.*;`
    StaticWildcard { package: String, class: String },
}

/// The imports of a Java file. The package/class boundary uses the same
/// convention as `import a.b.C;` resolution: the last dotted segment is the
/// class (or, for `import static`, the member and the segment before it).
#[allow(clippy::items_after_test_module)]
fn java_imports(lines: &[&str]) -> Vec<JavaImport> {
    let mut imports = Vec::new();
    let Ok(import) =
        Regex::new(r#"^\s*import\s+(static\s+)?([A-Za-z_][A-Za-z0-9_.]*?)(\.\*)?\s*;"#)
    else {
        return imports;
    };
    for line in lines {
        let code = line.split("//").next().unwrap_or("").trim();
        let Some(captures) = import.captures(code) else {
            continue;
        };
        let is_static = captures.get(1).is_some();
        let dotted = captures.get(2).map_or("", |name| name.as_str());
        let wildcard = captures.get(3).is_some();
        let Some((path, last)) = dotted.rsplit_once('.') else {
            continue;
        };
        let parsed = match (is_static, wildcard) {
            (false, false) => Some(JavaImport::Class {
                package: path.to_string(),
                class: last.to_string(),
            }),
            (false, true) => Some(JavaImport::PackageWildcard {
                package: dotted.to_string(),
            }),
            (true, false) => {
                path.rsplit_once('.')
                    .map(|(package, class)| JavaImport::StaticMember {
                        package: package.to_string(),
                        class: class.to_string(),
                        member: last.to_string(),
                    })
            }
            (true, true) => {
                dotted
                    .rsplit_once('.')
                    .map(|(package, class)| JavaImport::StaticWildcard {
                        package: package.to_string(),
                        class: class.to_string(),
                    })
            }
        };
        if let Some(parsed) = parsed {
            imports.push(parsed);
        }
    }
    imports
}

/// The module path a `go.mod` declares.
#[allow(clippy::items_after_test_module)]
fn go_module_path(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let line = line.split("//").next().unwrap_or("").trim();
        let mut words = line.split_whitespace();
        if words.next() == Some("module") {
            words.next().map(str::to_string)
        } else {
            None
        }
    })
}

/// The directory holding the nearest `go.mod` at or above `dir` (stopping
/// at `root`), and the module path it declares.
#[allow(clippy::items_after_test_module)]
fn go_module_root_and_path(dir: &Path, root: &Path) -> Option<(std::path::PathBuf, String)> {
    let mut base = dir;
    loop {
        let go_mod = base.join("go.mod");
        if go_mod.is_file() {
            let content = std::fs::read_to_string(go_mod).ok()?;
            let module = go_module_path(&content)?;
            return Some((base.to_path_buf(), module));
        }
        if base == root {
            return None;
        }
        base = base.parent()?;
    }
}

/// `replace` directives of a `go.mod` that map a module path to a local
/// directory, as `(module path, target)` pairs where target is relative to
/// the `go.mod` (or absolute). Replacements to another module version have
/// no local directory and are skipped.
#[allow(clippy::items_after_test_module)]
fn go_replace_dirs(go_mod: &Path) -> Vec<(String, std::path::PathBuf)> {
    let Ok(content) = std::fs::read_to_string(go_mod) else {
        return Vec::new();
    };
    let mut dirs = Vec::new();
    let mut in_block = false;
    for line in content.lines() {
        let line = line.split("//").next().unwrap_or("").trim();
        if in_block {
            if line.starts_with(')') {
                in_block = false;
                continue;
            }
            push_replace(&mut dirs, line);
            continue;
        }
        let Some(rest) = line.strip_prefix("replace") else {
            continue;
        };
        let rest = rest.trim_start();
        if rest == "(" {
            in_block = true;
            continue;
        }
        if let Some(body) = rest.strip_prefix('(').map(str::trim_end) {
            // `replace ( old => new )` on one line.
            if let Some(body) = body.strip_suffix(')') {
                push_replace(&mut dirs, body);
            }
            continue;
        }
        push_replace(&mut dirs, rest);
    }
    dirs
}

/// One `old [version] => new [version]` replace body; kept only when `new`
/// is a local path (no version, starting with `.` or `/`).
fn push_replace(dirs: &mut Vec<(String, std::path::PathBuf)>, body: &str) {
    let Some((left, right)) = body.split_once("=>") else {
        return;
    };
    let old = left.split_whitespace().next().unwrap_or("");
    let right: Vec<&str> = right.split_whitespace().collect();
    if old.is_empty() || right.len() != 1 {
        return;
    }
    let new = right[0];
    if new.starts_with('.') || new.starts_with('/') {
        dirs.push((old.to_string(), std::path::PathBuf::from(new)));
    }
}

/// Every `(module dir, module path)` declared by a `go.mod` under `root`,
/// skipping excluded directories (`vendor`, `node_modules`, ...). Bounded so
/// a huge tree cannot stall the scan.
#[allow(clippy::items_after_test_module)]
fn go_nested_modules(root: &Path) -> Vec<(std::path::PathBuf, String)> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0usize;
    while let Some(dir) = pending.pop() {
        if found.len() >= 256 || visited >= 50_000 {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            let path = entry.path();
            if path.is_dir() {
                if !crate::scan::should_exclude_in(&path, root) {
                    pending.push(path);
                }
            } else if path.file_name().is_some_and(|name| name == "go.mod") {
                if let Some(module) = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|content| go_module_path(&content))
                {
                    if let Ok(canonical) = std::fs::canonicalize(&path) {
                        if let Some(parent) = canonical.parent() {
                            found.push((parent.to_path_buf(), module));
                        }
                    }
                }
            }
        }
    }
    found
}

/// Map an import outside the file's own module to a directory: through a
/// `replace` directive to a local directory (resolved against the module
/// root), or through another `go.mod` under the project root whose module
/// path prefixes the import. The longest matching module path wins.
#[allow(clippy::items_after_test_module)]
fn go_external_import_dir(
    spec: &str,
    module_root: &Path,
    replaces: &[(String, std::path::PathBuf)],
    nested: &[(std::path::PathBuf, String)],
) -> Option<std::path::PathBuf> {
    let mut best: Option<(usize, std::path::PathBuf)> = None;
    let mut offer = |module_path: &str, dir: std::path::PathBuf| {
        let relative = match spec.strip_prefix(module_path) {
            Some("") => std::path::PathBuf::new(),
            Some(rest) if rest.starts_with('/') => std::path::PathBuf::from(&rest[1..]),
            _ => return,
        };
        let candidate = dir.join(relative);
        if best
            .as_ref()
            .is_none_or(|(len, _)| module_path.len() > *len)
        {
            best = Some((module_path.len(), candidate));
        }
    };
    for (old, target) in replaces {
        offer(old, module_root.join(target));
    }
    for (dir, module_path) in nested {
        offer(module_path, dir.clone());
    }
    best.map(|(_, dir)| dir)
}

/// Resolve a file's relative imports to other project files.
#[allow(clippy::items_after_test_module)]
/// Resolve a relative JS/TS import specifier (`./x`, `../x`) to a scanned
/// file, trying the plain path, the common extensions, and index files.
#[allow(clippy::items_after_test_module)]
fn resolve_js_specifier(
    dir: &Path,
    spec: &str,
    index_of: &std::collections::HashMap<std::path::PathBuf, usize>,
) -> Option<usize> {
    if !(spec.starts_with("./") || spec.starts_with("../")) {
        return None;
    }
    let base = dir.join(spec);
    let mut candidates = vec![base.clone()];
    for ext in ["js", "ts", "mjs", "cjs"] {
        candidates.push(std::path::PathBuf::from(format!(
            "{}.{ext}",
            base.to_string_lossy()
        )));
        candidates.push(base.join(format!("index.{ext}")));
    }
    candidates
        .into_iter()
        .filter(|candidate| candidate.is_file())
        .find_map(|candidate| {
            std::fs::canonicalize(candidate)
                .ok()
                .and_then(|canonical| index_of.get(&canonical).copied())
        })
}

/// Package name of a bare JS import specifier: `pkg` or `@scope/pkg`.
/// Relative (`./`, `../`) and absolute specs, and subpath imports
/// (`pkg/sub`, `@scope/pkg/sub`), stay unresolved.
fn js_package_name(spec: &str) -> Option<&str> {
    if spec.starts_with('.') || spec.starts_with('/') {
        return None;
    }
    if let Some(rest) = spec.strip_prefix('@') {
        let mut parts = rest.split('/');
        let scope = parts.next()?;
        let name = parts.next()?;
        if scope.is_empty() || name.is_empty() || parts.next().is_some() {
            return None;
        }
        Some(spec)
    } else if spec.contains('/') {
        None
    } else {
        Some(spec)
    }
}

/// Candidate entry files of a package directory: the `package.json` `main`
/// field (with the usual extension and index fallbacks), then the index
/// files directly.
fn js_package_entry(pkg_dir: &Path) -> Option<std::path::PathBuf> {
    let expand = |base: std::path::PathBuf| -> Vec<std::path::PathBuf> {
        let mut candidates = vec![base.clone()];
        for ext in ["js", "cjs", "mjs"] {
            candidates.push(std::path::PathBuf::from(format!(
                "{}.{ext}",
                base.to_string_lossy()
            )));
        }
        for ext in ["js", "cjs", "mjs"] {
            candidates.push(base.join(format!("index.{ext}")));
        }
        candidates
    };
    if let Ok(body) = std::fs::read_to_string(pkg_dir.join("package.json")) {
        if let Ok(re) = Regex::new(r#""main"\s*:\s*"([^"]+)""#) {
            if let Some(captures) = re.captures(&body) {
                let main = captures[1].trim_start_matches("./");
                for candidate in expand(pkg_dir.join(main)) {
                    if candidate.is_file() {
                        return Some(candidate);
                    }
                }
            }
        }
    }
    expand(pkg_dir.join("index"))
        .into_iter()
        .find(|p| p.is_file())
}

/// Find a package's entry file on disk: walk from the importing directory up
/// to the project root; the first `node_modules/<pkg>` with a resolvable
/// entry wins, mirroring Node's lookup.
fn find_js_package_entry(dir: &Path, root: &Path, spec: &str) -> Option<std::path::PathBuf> {
    let package = js_package_name(spec)?;
    let mut current = Some(dir);
    while let Some(base) = current {
        let pkg_dir = base.join("node_modules").join(package);
        if pkg_dir.is_dir() {
            if let Some(entry) = js_package_entry(&pkg_dir) {
                return Some(entry);
            }
        }
        if base == root {
            break;
        }
        current = base.parent();
    }
    None
}

/// Resolve a bare package import to a package entry included in the module
/// set. Returns None when the package is not installed anywhere visible.
fn resolve_js_package(
    dir: &Path,
    root: &Path,
    spec: &str,
    index_of: &std::collections::HashMap<std::path::PathBuf, usize>,
) -> Option<usize> {
    let entry = find_js_package_entry(dir, root, spec)?;
    std::fs::canonicalize(entry)
        .ok()
        .and_then(|canonical| index_of.get(&canonical).copied())
}

/// Specifiers of the import and require declarations in one joined
/// statement: `require('x')`, `import ... from 'x'`, and side-effect
/// `import 'x'`.
fn js_import_specs(statement: &str) -> Vec<String> {
    let mut specs = Vec::new();
    if let Ok(re) = Regex::new(r#"require\(\s*['"]([^'"]+)['"]"#) {
        for captures in re.captures_iter(statement) {
            specs.push(captures[1].to_string());
        }
    }
    if let Ok(re) = Regex::new(r#"(?:from|import)\s+['"]([^'"]+)['"]"#) {
        for captures in re.captures_iter(statement) {
            specs.push(captures[1].to_string());
        }
    }
    specs
}

/// Read a text file, refusing anything over `cap` bytes (generated bundles).
fn read_capped(path: &Path, cap: u64) -> std::io::Result<String> {
    if std::fs::metadata(path)?.len() > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file over size cap",
        ));
    }
    std::fs::read_to_string(path)
}

/// A re-export declaration of a JS/TS ("barrel") file.
enum JsReexport {
    Named {
        spec: String,
        source: String,
        name: String,
    },
    Glob {
        spec: String,
    },
    /// `export * as ns from './x'`: the barrel offers `ns` as a module
    /// (namespace) bound to the target file itself.
    Namespace {
        spec: String,
        name: String,
    },
}

/// Re-export declarations of one JS/TS file: `export { a, b as c } from
/// './x'`, `export * from './x'`, and `export * as ns from './x'`.
#[allow(clippy::items_after_test_module)]
/// JS declaration statements with multi-line ones joined: an `import`,
/// an `export { ... } from` / `export * from` re-export, or a
/// `const`/`let`/`var` destructuring that spans lines is flattened into
/// one space-separated statement so the single-line import and re-export
/// shapes still match. Joining starts only on a declaration opener and
/// stops once braces and parentheses balance and the statement
/// terminates (`;`, a closing quote, or `)`), bounded at 20 lines; every
/// other line passes through untouched. `//` comments are stripped per
/// line, so a specifier containing `//` does not join (relative
/// specifiers never contain one).
fn js_declarations(lines: &[&str]) -> Vec<String> {
    let mut statements = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let code = lines[index].split("//").next().unwrap_or("").trim();
        let destructures = ["const {", "let {", "var {"]
            .iter()
            .any(|head| code.starts_with(head));
        let opens = code.starts_with("import ")
            || code.starts_with("import{")
            || code.starts_with("import*")
            || code.starts_with("export {")
            || code.starts_with("export *")
            || ((code.starts_with("const ")
                || code.starts_with("let ")
                || code.starts_with("var "))
                && (destructures || code.contains("require(")));
        let balance = |text: &str| {
            let braces = text.matches('{').count() as i64 - text.matches('}').count() as i64;
            let parens = text.matches('(').count() as i64 - text.matches(')').count() as i64;
            (braces, parens)
        };
        let terminated = |text: &str, braces: i64, parens: i64| {
            braces <= 0
                && parens <= 0
                && (text.ends_with(';')
                    || text.ends_with('\'')
                    || text.ends_with('"')
                    || text.ends_with(')'))
        };
        if !opens {
            index += 1;
            continue;
        }
        let mut joined = code.to_string();
        let (mut braces, mut parens) = balance(&joined);
        let mut used = 1;
        while !terminated(&joined, braces, parens) && used < 20 && index + used < lines.len() {
            let next = lines[index + used].split("//").next().unwrap_or("").trim();
            if !next.is_empty() {
                joined.push(' ');
                joined.push_str(next);
                let (b, p) = balance(&joined);
                braces = b;
                parens = p;
            }
            used += 1;
        }
        statements.push(joined);
        index += used;
    }
    statements
}

fn js_reexports(lines: &[&str]) -> Vec<JsReexport> {
    let mut declarations = Vec::new();
    let (Ok(named), Ok(glob), Ok(namespace)) = (
        Regex::new(r#"^\s*export\s*\{([^}]*)\}\s*from\s+['"]([^'"]+)['"]\s*;?\s*$"#),
        Regex::new(r#"^\s*export\s*\*\s*from\s+['"]([^'"]+)['"]\s*;?\s*$"#),
        Regex::new(
            r#"^\s*export\s*\*\s*as\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+['"]([^'"]+)['"]\s*;?\s*$"#,
        ),
    ) else {
        return declarations;
    };
    let is_identifier = |text: &str| {
        !text.is_empty()
            && text
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
    };
    for statement in js_declarations(lines) {
        let code = statement.as_str();
        if let Some(captures) = named.captures(code) {
            let names = captures.get(1).map(|m| m.as_str()).unwrap_or("");
            let spec = captures
                .get(2)
                .map(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            for entry in names.split(',') {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                let (source, name) = match entry.split_once(" as ") {
                    Some((left, right)) => (left.trim(), right.trim()),
                    None => (entry, entry),
                };
                if is_identifier(source) && is_identifier(name) {
                    declarations.push(JsReexport::Named {
                        spec: spec.clone(),
                        source: source.to_string(),
                        name: name.to_string(),
                    });
                }
            }
            continue;
        }
        if let Some(captures) = namespace.captures(code) {
            if let (Some(name), Some(spec)) = (captures.get(1), captures.get(2)) {
                declarations.push(JsReexport::Namespace {
                    spec: spec.as_str().to_string(),
                    name: name.as_str().to_string(),
                });
            }
            continue;
        }
        if let Some(spec) = glob.captures(code).and_then(|c| c.get(1)) {
            declarations.push(JsReexport::Glob {
                spec: spec.as_str().to_string(),
            });
        }
    }
    declarations
}

