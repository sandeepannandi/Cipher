/// Cross-file request flow for JS/TS, Python, Java, Go, and Rust projects.
///
/// Each file's functions are summarized with the same per-parameter pass as
/// the same-file engine. JS/TS and Python imports are resolved to project
/// files (`require`/`import` of `./x`, `../x`, `x/index`; Python `from .x
/// import f`, `from .x import *`, `from x import f`, `import x as m` resolved next to the
/// importing file or at the project root; multi-line JS import, require,
/// and re-export declarations are joined before matching, as are
/// parenthesized Python from-imports). Go files in one directory share a
/// package namespace, so a bare call resolves to a function defined in a
/// sibling file; `import "mod/pkg"` (optionally aliased, single or grouped
/// form) resolves through the module path of the nearest `go.mod`, and only
/// exported (capitalized) names are visible across packages. Imports outside
/// the file's own module resolve through `replace` directives that map the
/// module path to a local directory, or through another `go.mod` under the
/// project root whose module path prefixes the import; the module cache and
/// `vendor/` (excluded from scans) are not followed. Java classes in one
/// package refer to each other by class name (`Service.find(...)`), and
/// `import a.b.C;` resolves to the one project file whose package and class
/// name match; `import a.b.*;` resolves every uniquely named class in that
/// package, `import static a.b.C.f;` resolves the bare call `f(...)`, and
/// `import static a.b.C.*;` resolves every static method of `C` the same
/// way. Only static, non-private methods resolve. Rust `mod store;`
/// resolves to the sibling `store.rs`/`store/mod.rs` for `store::f(...)`
/// path calls, `a::b::f(...)` and longer chains resolve through nested
/// hops when each module declares the next, and
/// `use crate::`/`self::`/`super::` paths (with `as`
/// aliases or a trailing `::*` glob) resolve from the nearest ancestor
/// holding `main.rs`/`lib.rs`; only `pub` free functions are visible. A
/// request-tainted
/// argument passed to an exported function of another file in a position
/// that reaches a sink reports the sink line in that file. Import hops are
/// followed through a converging fixpoint: a callee whose own imports
/// forward the value onward contributes the sinks those imports reach, so a
/// call chain across any number of import hops resolves (one propagation
/// round per module bounds the loop); the callee's same-file helpers are
/// included through its summaries, and import cycles simply stop changing.
/// JS/TS re-exports and Rust `pub use` re-exports (named,
/// `as` alias, grouped, or `*` glob, with `crate::`/`self::`/`super::` or
/// bare relative paths) resolve through a bounded fixpoint, so chained
/// re-exports (a barrel re-exporting from another barrel) collapse toward
/// the defining module pass by pass, iterated to convergence; in both
/// languages a name offered by two sources at any pass resolves to neither,
/// and a re-export cycle offers nothing. Calls through instance
/// variables resolve for JS (`this.repo.m(...)` when the variable is
/// assigned `new Repo(...)` and `Repo` is a whole-module or class
/// import) and for Python (`self.repo.m(...)` when the variable is
/// assigned `Repo(...)` from `from .repo import Repo`, or
/// `repo.Repo(...)` with `import repo`); methods match by name within
/// the imported file.
/// Package imports (JS) resolve through the package entry file under
/// `node_modules` (one hop, see above); dynamic `require` and other
/// instance receivers stay unresolved. Go `_test.go` files import their
/// package like any file in it, but are never resolution targets
/// themselves (non-test code cannot see test-only symbols), and a
/// callable name offered by two different files resolves to neither.
#[allow(clippy::items_after_test_module)]
fn cross_file_flow_sinks(
    files: &[std::path::PathBuf],
    project_root: &Path,
) -> std::collections::HashMap<std::path::PathBuf, CrossFileSinkLines> {
    let mut result: std::collections::HashMap<std::path::PathBuf, CrossFileSinkLines> =
        std::collections::HashMap::new();
    struct Module {
        path: std::path::PathBuf,
        language: FlowLanguage,
        content: String,
    }
    let mut modules: Vec<Module> = files
        .iter()
        .filter_map(|path| {
            let language = flow_language(&file_extension(path))?;
            let content = std::fs::read_to_string(path).ok()?;
            Some(Module {
                path: path.clone(),
                language,
                content,
            })
        })
        .collect();
    // JS package imports (`require('pkg')`, `import ... from 'pkg'`) resolve
    // through node_modules: the scanner excludes the directory, so package
    // entry files join the module set here, on demand. Bounded: the entry
    // file only (package.json `main` or an index file), a 512KB cap skips
    // generated bundles, and one hop — the entry's own imports resolve only
    // when they point at another included entry.
    {
        let scan_root =
            std::fs::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());
        let mut seen: std::collections::HashSet<std::path::PathBuf> = modules
            .iter()
            .filter_map(|module| std::fs::canonicalize(&module.path).ok())
            .collect();
        let mut extra = Vec::new();
        for module in &modules {
            if module.language != FlowLanguage::JavaScript {
                continue;
            }
            let Some(dir) = module.path.parent() else {
                continue;
            };
            let module_lines: Vec<&str> = module.content.lines().collect();
            for statement in js_declarations(&module_lines) {
                for spec in js_import_specs(&statement) {
                    if js_package_name(&spec).is_none() {
                        continue;
                    }
                    if let Some(entry) = find_js_package_entry(dir, &scan_root, &spec) {
                        if let Ok(canonical) = std::fs::canonicalize(&entry) {
                            if seen.insert(canonical.clone()) {
                                if let Ok(content) = read_capped(&canonical, 512 * 1024) {
                                    extra.push(Module {
                                        path: canonical,
                                        language: FlowLanguage::JavaScript,
                                        content,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        modules.extend(extra);
    }
    if modules.len() < 2 {
        return result;
    }
    let index_of: std::collections::HashMap<std::path::PathBuf, usize> = modules
        .iter()
        .enumerate()
        .filter_map(|(index, module)| {
            std::fs::canonicalize(&module.path)
                .ok()
                .map(|canonical| (canonical, index))
        })
        .collect();
    let root = std::fs::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());

    let lines: Vec<Vec<&str>> = modules
        .iter()
        .map(|module| module.content.lines().collect())
        .collect();
    let functions: Vec<Vec<FlowFunction>> = modules
        .iter()
        .zip(&lines)
        .map(|(module, lines)| flow_functions(lines, module.language))
        .collect();
    let exports: Vec<std::collections::HashMap<String, usize>> = modules
        .iter()
        .zip(&lines)
        .zip(&functions)
        .map(|((module, lines), functions)| flow_exports(lines, module.language, functions))
        .collect();
    let mut bindings: Vec<Vec<ImportBinding>> = modules
        .iter()
        .zip(&lines)
        .map(|(module, lines)| flow_imports(lines, module.language, &module.path, &root, &index_of))
        .collect();
    // Re-exporting ("barrel") modules: named (`export { f } from './x'`) and
    // glob (`export * from './x'`) re-exports make the source function
    // visible under the barrel's path. Chained barrels (a barrel
    // re-exporting from another barrel) resolve through a bounded fixpoint:
    // each pass collapses one hop toward the defining module. A name
    // offered by two different sources at any pass resolves to neither, a
    // re-export cycle offers nothing, and chains longer than the pass
    // bound stay unresolved.
    let js_reexports_pass = |old: &[std::collections::HashMap<String, (usize, String)>]| {
        modules
            .iter()
            .enumerate()
            .zip(&lines)
            .map(|((index, module), lines)| {
                let mut map = std::collections::HashMap::new();
                if module.language != FlowLanguage::JavaScript {
                    return map;
                }
                let Some(dir) = module.path.parent() else {
                    return map;
                };
                let mut candidates: std::collections::HashMap<String, Vec<(usize, String)>> =
                    std::collections::HashMap::new();
                for declaration in js_reexports(lines) {
                    match declaration {
                        JsReexport::Named { spec, source, name } => {
                            if let Some(target) = resolve_js_specifier(dir, &spec, &index_of) {
                                // A barrel-of-barrel link collapses to the
                                // defining module found in the previous pass.
                                if let Some((definer, original)) = old[target].get(&source) {
                                    candidates
                                        .entry(name)
                                        .or_default()
                                        .push((*definer, original.clone()));
                                } else {
                                    candidates.entry(name).or_default().push((target, source));
                                }
                            }
                        }
                        JsReexport::Namespace { .. } => {
                            // Handled by the namespace map below, which
                            // binds the name as a module, not a function.
                        }
                        JsReexport::Glob { spec } => {
                            if let Some(target) = resolve_js_specifier(dir, &spec, &index_of) {
                                for name in exports[target].keys() {
                                    candidates
                                        .entry(name.clone())
                                        .or_default()
                                        .push((target, name.clone()));
                                }
                                for (name, (definer, original)) in &old[target] {
                                    candidates
                                        .entry(name.clone())
                                        .or_default()
                                        .push((*definer, original.clone()));
                                }
                            }
                        }
                    }
                }
                for (name, mut offers) in candidates {
                    offers.sort();
                    offers.dedup();
                    // A link pointing back at this module is a re-export
                    // cycle: it offers nothing.
                    if offers.len() == 1 && offers[0].0 != index {
                        map.insert(name, offers[0].clone());
                    }
                }
                map
            })
            .collect::<Vec<_>>()
    };
    let empty_maps: Vec<std::collections::HashMap<String, (usize, String)>> = (0..modules.len())
        .map(|_| std::collections::HashMap::new())
        .collect();
    // Iterate until the maps stop changing: each pass collapses one hop
    // toward the defining module, so chains of any depth converge within
    // one pass per module and re-export cycles simply stop changing.
    let mut reexport_maps = js_reexports_pass(&empty_maps);
    for _ in 0..modules.len().max(4) {
        let next = js_reexports_pass(&reexport_maps);
        if next == reexport_maps {
            reexport_maps = next;
            break;
        }
        reexport_maps = next;
    }
    // Namespace re-exports (`export * as ns from './x'`): the barrel
    // offers `ns` as a module bound to the re-exported file, so
    // `import { ns } from './barrel'` followed by `ns.f(...)` resolves
    // like a whole-module import of that file. Single pass: a name
    // offered by two sources, or pointing at the barrel itself,
    // resolves to neither.
    let namespace_maps: Vec<std::collections::HashMap<String, usize>> = modules
        .iter()
        .enumerate()
        .zip(&lines)
        .map(|((index, module), lines)| {
            let mut map = std::collections::HashMap::new();
            if module.language != FlowLanguage::JavaScript {
                return map;
            }
            let Some(dir) = module.path.parent() else {
                return map;
            };
            let mut offers: std::collections::HashMap<String, Vec<usize>> =
                std::collections::HashMap::new();
            for declaration in js_reexports(lines) {
                if let JsReexport::Namespace { spec, name } = declaration {
                    if let Some(target) = resolve_js_specifier(dir, &spec, &index_of) {
                        offers.entry(name).or_default().push(target);
                    }
                }
            }
            for (name, mut targets) in offers {
                targets.sort();
                targets.dedup();
                if targets.len() == 1 && targets[0] != index {
                    map.insert(name, targets[0]);
                }
            }
            map
        })
        .collect();
    for (index, module) in modules.iter().enumerate() {
        if module.language != FlowLanguage::JavaScript {
            continue;
        }
        for binding in &mut bindings[index] {
            let replacement = if let ImportBinding::Function {
                local,
                exported,
                target,
            } = binding
            {
                if modules[*target].language == FlowLanguage::JavaScript
                    && !exports[*target].contains_key(exported)
                {
                    if let Some((new_target, source)) = reexport_maps[*target].get(exported) {
                        *target = *new_target;
                        *exported = source.clone();
                        None
                    } else {
                        namespace_maps[*target].get(exported).map(|ns_target| {
                            ImportBinding::Module {
                                binding: local.clone(),
                                target: *ns_target,
                                exported_only: false,
                            }
                        })
                    }
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(new_binding) = replacement {
                *binding = new_binding;
            }
        }
    }
    let mut by_dir: std::collections::HashMap<std::path::PathBuf, Vec<usize>> =
        std::collections::HashMap::new();
    for (canonical, index) in &index_of {
        if let Some(parent) = canonical.parent() {
            by_dir.entry(parent.to_path_buf()).or_default().push(*index);
        }
    }
    // Rust re-exporting modules: `pub use a::f;` (named, `as` alias,
    // grouped, or a `*` glob) makes the source function visible under the
    // re-exporting module's path. Chained re-exports (a module re-exporting
    // a name it only re-exports) resolve through a bounded fixpoint: each
    // pass collapses one hop toward the defining module. A name offered by
    // two different sources at any pass resolves to neither, and a
    // re-export cycle offers nothing.
    let rust_reexports_pass = |old: &[std::collections::HashMap<String, (usize, String)>]| {
        modules
            .iter()
            .enumerate()
            .zip(&lines)
            .map(|((index, module), lines)| {
                let mut offers: std::collections::HashMap<String, Vec<(usize, String)>> =
                    std::collections::HashMap::new();
                if module.language != FlowLanguage::Rust {
                    return std::collections::HashMap::new();
                }
                let Some(own_dir) = module
                    .path
                    .parent()
                    .and_then(|parent| std::fs::canonicalize(parent).ok())
                else {
                    return std::collections::HashMap::new();
                };
                let Some(module_dir) = rust_module_dir(&module.path) else {
                    return std::collections::HashMap::new();
                };
                let is_mod_rs = module.path.file_stem().is_some_and(|stem| stem == "mod");
                let super_base = if is_mod_rs {
                    own_dir.parent().map(|parent| parent.to_path_buf())
                } else {
                    Some(own_dir.clone())
                };
                let crate_base = rust_crate_root(&own_dir, &root);
                let resolve_module = |base: &Path, segments: &[&str]| -> Option<usize> {
                    let mut target = base.to_path_buf();
                    for segment in segments {
                        target.push(segment);
                    }
                    let candidates: Vec<std::path::PathBuf> = if segments.is_empty() {
                        vec![base.join("lib.rs"), base.join("main.rs")]
                    } else {
                        vec![target.with_extension("rs"), target.join("mod.rs")]
                    };
                    candidates.into_iter().find_map(|candidate| {
                        std::fs::canonicalize(candidate)
                            .ok()
                            .and_then(|canonical| index_of.get(&canonical).copied())
                            .filter(|&found| modules[found].language == FlowLanguage::Rust)
                    })
                };
                for declaration in rust_declarations(lines) {
                    let RustDeclaration::Use {
                        segments,
                        alias,
                        reexport,
                    } = declaration
                    else {
                        continue;
                    };
                    if !reexport {
                        continue;
                    }
                    let skip = usize::from(matches!(
                        segments.first().map(String::as_str),
                        Some("crate" | "self" | "super")
                    ));
                    let Some(base) = (match segments.first().map(String::as_str) {
                        Some("crate") => crate_base.clone(),
                        Some("self") => Some(module_dir.clone()),
                        Some("super") => super_base.clone(),
                        // A bare path is relative to the current module; an
                        // external crate name simply resolves to nothing.
                        _ => Some(module_dir.clone()),
                    }) else {
                        continue;
                    };
                    let rest: Vec<&str> = segments[skip..].iter().map(String::as_str).collect();
                    if rest.last() == Some(&"*") {
                        let module_path = &rest[..rest.len() - 1];
                        if let Some(source) = resolve_module(&base, module_path) {
                            for name in exports[source].keys() {
                                offers
                                    .entry(name.clone())
                                    .or_default()
                                    .push((source, name.clone()));
                            }
                            for (name, (definer, original)) in &old[source] {
                                offers
                                    .entry(name.clone())
                                    .or_default()
                                    .push((*definer, original.clone()));
                            }
                        }
                        continue;
                    }
                    let Some(last) = rest.last().copied() else {
                        continue;
                    };
                    if let Some(source) = resolve_module(&base, &rest[..rest.len() - 1]) {
                        if exports[source].contains_key(last) {
                            offers
                                .entry(alias.clone().unwrap_or_else(|| last.to_string()))
                                .or_default()
                                .push((source, last.to_string()));
                        } else if let Some((definer, original)) = old[source].get(last) {
                            // A chained re-export collapses to the defining
                            // module found in the previous pass.
                            offers
                                .entry(alias.clone().unwrap_or_else(|| last.to_string()))
                                .or_default()
                                .push((*definer, original.clone()));
                        }
                    }
                }
                offers
                    .into_iter()
                    // A link pointing back at this module is a re-export
                    // cycle: it offers nothing.
                    .filter(|(_, found)| found.len() == 1 && found[0].0 != index)
                    .map(|(name, found)| (name, found[0].clone()))
                    .collect()
            })
            .collect::<Vec<_>>()
    };
    let empty_rust_maps: Vec<std::collections::HashMap<String, (usize, String)>> = (0..modules
        .len())
        .map(|_| std::collections::HashMap::new())
        .collect();
    let mut rust_reexport_maps = rust_reexports_pass(&empty_rust_maps);
    for _ in 0..modules.len().max(4) {
        let next = rust_reexports_pass(&rust_reexport_maps);
        if next == rust_reexport_maps {
            rust_reexport_maps = next;
            break;
        }
        rust_reexport_maps = next;
    }
    // Multi-module Go repositories: an import outside a file's own module
    // resolves through a `replace` directive to a local directory or through
    // another go.mod under the project root whose module path prefixes it.
    let go_modules: Vec<(std::path::PathBuf, String)> = if modules
        .iter()
        .any(|module| module.language == FlowLanguage::Go)
    {
        go_nested_modules(&root)
    } else {
        Vec::new()
    };
    // Java package and class names are parsed once per module here, not once
    // per (module, sibling) pair or per import below: those lookups ran
    // inside nested loops and made the pass quadratic in package size.
    let java_packages: Vec<Option<String>> = modules
        .iter()
        .zip(&lines)
        .map(|(module, lines)| {
            if module.language == FlowLanguage::Java {
                java_package_clause(lines)
            } else {
                None
            }
        })
        .collect();
    let java_classes: Vec<Option<String>> = modules
        .iter()
        .zip(&lines)
        .map(|(module, lines)| {
            if module.language == FlowLanguage::Java {
                java_class_name(lines, &module.path)
            } else {
                None
            }
        })
        .collect();
    let mut java_by_class: std::collections::HashMap<(String, String), Vec<usize>> =
        std::collections::HashMap::new();
    let mut java_by_package: std::collections::HashMap<String, Vec<usize>> =
        std::collections::HashMap::new();
    for (index, module) in modules.iter().enumerate() {
        if module.language != FlowLanguage::Java {
            continue;
        }
        if let Some(package) = &java_packages[index] {
            java_by_package
                .entry(package.clone())
                .or_default()
                .push(index);
            if let Some(class) = &java_classes[index] {
                java_by_class
                    .entry((package.clone(), class.clone()))
                    .or_default()
                    .push(index);
            }
        }
    }
    // Same-package siblings need no import statement: Go files in one
    // directory share a namespace, and Java classes in one package refer to
    // each other by class name. Go cross-package imports resolve through the
    // module path of the nearest go.mod; a Java `import a.b.C;` matches the
    // one file whose package and class name line up.
    for (index, module) in modules.iter().enumerate() {
        let Some(own_dir) = module
            .path
            .parent()
            .and_then(|parent| std::fs::canonicalize(parent).ok())
        else {
            continue;
        };
        match module.language {
            FlowLanguage::Go => {
                if let Some(package) = go_package_clause(&lines[index]) {
                    if let Some(siblings) = by_dir.get(&own_dir) {
                        for &sibling in siblings {
                            if sibling == index
                                || modules[sibling].language != FlowLanguage::Go
                                || modules[sibling].path.file_name().is_some_and(|name| {
                                    name.to_string_lossy().ends_with("_test.go")
                                })
                                || go_package_clause(&lines[sibling]).as_deref()
                                    != Some(package.as_str())
                            {
                                continue;
                            }
                            for name in exports[sibling].keys() {
                                bindings[index].push(ImportBinding::Function {
                                    local: name.clone(),
                                    exported: name.clone(),
                                    target: sibling,
                                });
                            }
                        }
                    }
                }
                let Some((module_root, module_path)) = go_module_root_and_path(&own_dir, &root)
                else {
                    continue;
                };
                let replaces = go_replace_dirs(&module_root.join("go.mod"));
                for (alias, spec) in go_import_specs(&lines[index]) {
                    let relative = match spec.strip_prefix(module_path.as_str()) {
                        Some("") => std::path::PathBuf::new(),
                        Some(rest) if rest.starts_with('/') => std::path::PathBuf::from(&rest[1..]),
                        // Outside the file's own module: a `replace` to a
                        // local directory or another go.mod under the project
                        // root can still map the import into the tree.
                        _ => {
                            match go_external_import_dir(
                                &spec,
                                &module_root,
                                &replaces,
                                &go_modules,
                            ) {
                                Some(dir) => dir,
                                None => continue,
                            }
                        }
                    };
                    let Ok(target_dir) = std::fs::canonicalize(module_root.join(&relative)) else {
                        continue;
                    };
                    let Some(targets) = by_dir.get(&target_dir) else {
                        continue;
                    };
                    let targets: Vec<usize> = targets
                        .iter()
                        .copied()
                        .filter(|&target| {
                            modules[target].language == FlowLanguage::Go
                                && !modules[target].path.file_name().is_some_and(|name| {
                                    name.to_string_lossy().ends_with("_test.go")
                                })
                        })
                        .collect();
                    if targets.is_empty() {
                        continue;
                    }
                    let binding = match alias {
                        Some(alias) => alias,
                        None => {
                            let mut clauses = targets
                                .iter()
                                .filter_map(|&target| go_package_clause(&lines[target]));
                            let Some(first) = clauses.next() else {
                                continue;
                            };
                            if clauses.any(|clause| clause != first) {
                                continue;
                            }
                            first
                        }
                    };
                    if binding == "." {
                        // Dot import: the package's exported names are
                        // callable bare. Expanded once exports are known.
                        for target in targets {
                            bindings[index].push(ImportBinding::Star { target });
                        }
                        continue;
                    }
                    for target in targets {
                        bindings[index].push(ImportBinding::Module {
                            binding: binding.clone(),
                            target,
                            exported_only: true,
                        });
                    }
                }
            }
            FlowLanguage::Java => {
                let package = java_packages[index].clone();
                let mut class_counts: std::collections::HashMap<String, usize> =
                    std::collections::HashMap::new();
                let mut siblings = Vec::new();
                if let Some(same_dir) = by_dir.get(&own_dir) {
                    for &sibling in same_dir {
                        if sibling == index
                            || modules[sibling].language != FlowLanguage::Java
                            || java_packages[sibling] != package
                        {
                            continue;
                        }
                        if let Some(class) = java_classes[sibling].clone() {
                            *class_counts.entry(class.clone()).or_default() += 1;
                            siblings.push((class, sibling));
                        }
                    }
                }
                for (class, sibling) in siblings {
                    if class_counts.get(&class) == Some(&1) {
                        bindings[index].push(ImportBinding::Module {
                            binding: class,
                            target: sibling,
                            exported_only: false,
                        });
                    }
                }
                // The one other file declaring `class` in `package`; two
                // files offering the same class resolve to neither.
                let class_file = |package: &str, class: &str| -> Option<usize> {
                    let matches: Vec<usize> = java_by_class
                        .get(&(package.to_string(), class.to_string()))
                        .map(|candidates| {
                            candidates
                                .iter()
                                .copied()
                                .filter(|other| *other != index)
                                .collect()
                        })
                        .unwrap_or_default();
                    // `then`, not `then_some`: the match list is empty for
                    // imports that resolve outside the project (jdk, libraries),
                    // and `then_some` would index it eagerly and panic.
                    if matches.len() == 1 {
                        matches.first().copied()
                    } else {
                        None
                    }
                };
                for import in java_imports(&lines[index]) {
                    match import {
                        JavaImport::Class { package, class } => {
                            if let Some(target) = class_file(&package, &class) {
                                bindings[index].push(ImportBinding::Module {
                                    binding: class,
                                    target,
                                    exported_only: false,
                                });
                            }
                        }
                        JavaImport::PackageWildcard { package } => {
                            // `import a.b.*;` names every class of the
                            // package; a class offered by two files resolves
                            // to neither.
                            let mut by_class: std::collections::HashMap<String, Vec<usize>> =
                                std::collections::HashMap::new();
                            for &other in java_by_package.get(&package).into_iter().flatten() {
                                if other == index {
                                    continue;
                                }
                                if let Some(class) = java_classes[other].clone() {
                                    by_class.entry(class).or_default().push(other);
                                }
                            }
                            for (class, files) in by_class {
                                if files.len() == 1 {
                                    bindings[index].push(ImportBinding::Module {
                                        binding: class,
                                        target: files[0],
                                        exported_only: false,
                                    });
                                }
                            }
                        }
                        JavaImport::StaticMember {
                            package,
                            class,
                            member,
                        } => {
                            // `import static a.b.C.f;` makes the bare call
                            // `f(...)` resolve to the static method; only
                            // static, non-private methods are exported.
                            if let Some(target) = class_file(&package, &class) {
                                if exports[target].contains_key(member.as_str()) {
                                    bindings[index].push(ImportBinding::Function {
                                        local: member.clone(),
                                        exported: member,
                                        target,
                                    });
                                }
                            }
                        }
                        JavaImport::StaticWildcard { package, class } => {
                            if let Some(target) = class_file(&package, &class) {
                                for name in exports[target].keys() {
                                    bindings[index].push(ImportBinding::Function {
                                        local: name.clone(),
                                        exported: name.clone(),
                                        target,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            FlowLanguage::Rust => {
                // `mod store;` names a sibling file (`store.rs` or
                // `store/mod.rs`); calls look like `store::find_user(...)`,
                // or `api::users::lookup(...)` through one nested hop.
                // `use crate::a::b::f;` (also `self::`/`super::`, an `as`
                // alias, or a trailing `::*` glob) resolves from the crate
                // root and makes the bare call `f(...)` resolve; a path
                // whose last segment names a module binds the module
                // instead. Only `pub` free functions are visible.
                let Some(module_dir) = rust_module_dir(&module.path) else {
                    continue;
                };
                let is_mod_rs = module.path.file_stem().is_some_and(|stem| stem == "mod");
                let super_base = if is_mod_rs {
                    own_dir.parent().map(|parent| parent.to_path_buf())
                } else {
                    Some(own_dir.clone())
                };
                let crate_base = rust_crate_root(&own_dir, &root);
                let resolve_module = |base: &Path, segments: &[&str]| -> Option<usize> {
                    let mut target = base.to_path_buf();
                    for segment in segments {
                        target.push(segment);
                    }
                    let candidates: Vec<std::path::PathBuf> = if segments.is_empty() {
                        vec![base.join("lib.rs"), base.join("main.rs")]
                    } else {
                        vec![target.with_extension("rs"), target.join("mod.rs")]
                    };
                    candidates.into_iter().find_map(|candidate| {
                        std::fs::canonicalize(candidate)
                            .ok()
                            .and_then(|canonical| index_of.get(&canonical).copied())
                            .filter(|&found| modules[found].language == FlowLanguage::Rust)
                    })
                };
                for declaration in rust_declarations(&lines[index]) {
                    let (mut segments, alias) = match declaration {
                        RustDeclaration::Mod(name) => {
                            if let Some(target) = resolve_module(&module_dir, &[name.as_str()]) {
                                bindings[index].push(ImportBinding::Module {
                                    binding: name,
                                    target,
                                    exported_only: false,
                                });
                            }
                            continue;
                        }
                        RustDeclaration::Use {
                            segments, alias, ..
                        } => (segments, alias),
                    };
                    let Some(prefix) = segments.first().map(String::as_str) else {
                        continue;
                    };
                    let Some(mut base) = (match prefix {
                        "crate" => crate_base.clone(),
                        "self" => Some(module_dir.clone()),
                        "super" => super_base.clone(),
                        _ => None,
                    }) else {
                        continue;
                    };
                    segments.remove(0);
                    // `super::super::...`: each further `super` climbs one
                    // more directory. A chain past the filesystem root is
                    // left in place and simply resolves to nothing.
                    while segments.first().map(String::as_str) == Some("super") {
                        let Some(parent) = base.parent() else {
                            break;
                        };
                        base = parent.to_path_buf();
                        segments.remove(0);
                    }
                    let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
                    if segments.last() == Some(&"*") {
                        // `use crate::store::*;` imports every `pub fn`.
                        let module_path = &segments[..segments.len() - 1];
                        if let Some(target) = resolve_module(&base, module_path) {
                            for name in exports[target].keys() {
                                bindings[index].push(ImportBinding::Function {
                                    local: name.clone(),
                                    exported: name.clone(),
                                    target,
                                });
                            }
                        }
                        continue;
                    }
                    let Some(last) = segments.last().copied() else {
                        continue;
                    };
                    // A path ending in a module binds the module; otherwise
                    // the last segment is the function and the rest is the
                    // module path.
                    if let Some(target) = resolve_module(&base, &segments) {
                        bindings[index].push(ImportBinding::Module {
                            binding: alias.clone().unwrap_or_else(|| last.to_string()),
                            target,
                            exported_only: false,
                        });
                        continue;
                    }
                    if let Some(target) = resolve_module(&base, &segments[..segments.len() - 1]) {
                        if exports[target].contains_key(last) {
                            bindings[index].push(ImportBinding::Function {
                                local: alias.clone().unwrap_or_else(|| last.to_string()),
                                exported: last.to_string(),
                                target,
                            });
                        } else if let Some((source, original)) =
                            rust_reexport_maps[target].get(last)
                        {
                            bindings[index].push(ImportBinding::Function {
                                local: alias.clone().unwrap_or_else(|| last.to_string()),
                                exported: original.clone(),
                                target: *source,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }
    // Python `from .x import *` and Go `import . "pkg"`: every name the
    // target exports is callable bare in the importing module. Expand
    // eagerly into Function bindings. A name the module defines or binds
    // explicitly stays local; a name offered by two star imports resolves
    // to neither; names that are not visible through a star (private in
    // Python, unexported in Go) are skipped.
    for index in 0..modules.len() {
        if !matches!(
            modules[index].language,
            FlowLanguage::Python | FlowLanguage::Go
        ) {
            continue;
        }
        let star_targets: Vec<usize> = bindings[index]
            .iter()
            .filter_map(|binding| match binding {
                ImportBinding::Star { target } => Some(*target),
                _ => None,
            })
            .collect();
        if star_targets.is_empty() {
            continue;
        }
        bindings[index].retain(|binding| !matches!(binding, ImportBinding::Star { .. }));
        let mut offers: std::collections::HashMap<String, Vec<usize>> =
            std::collections::HashMap::new();
        for target in star_targets {
            for name in exports[target].keys() {
                let visible = match modules[index].language {
                    FlowLanguage::Go => name.chars().next().is_some_and(|ch| ch.is_uppercase()),
                    _ => !name.starts_with('_'),
                };
                if !visible {
                    continue;
                }
                offers.entry(name.clone()).or_default().push(target);
            }
        }
        for (name, mut targets) in offers {
            targets.sort();
            targets.dedup();
            if targets.len() != 1 || exports[index].contains_key(&name) {
                continue;
            }
            let shadowed = bindings[index].iter().any(|binding| match binding {
                ImportBinding::Function { local, .. } => local == &name,
                ImportBinding::Module { binding, .. } => binding == &name,
                ImportBinding::Star { .. } => false,
            });
            if shadowed {
                continue;
            }
            bindings[index].push(ImportBinding::Function {
                local: name.clone(),
                exported: name,
                target: targets[0],
            });
        }
    }
    if bindings.iter().all(|found| found.is_empty()) {
        return result;
    }

    let instance_new = Regex::new(
        r#"^\s*(?:(?:const|let|var)\s+)?(?:this\.)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*new\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\("#,
    );
    let instance_plain =
        Regex::new(r#"^\s*self\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\("#);
    let instance_attr = Regex::new(
        r#"^\s*self\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\("#,
    );
    type Family = (fn(FlowLanguage) -> Vec<FlowSink>, fn(&str) -> bool, u8);
    let families: [Family; 3] = [
        (sql_flow_sinks, contains_numeric_conversion, 0),
        (command_flow_sinks, contains_command_sanitizer, 1),
        (ssrf_flow_sinks, contains_numeric_conversion, 2),
    ];
    for (build_sinks, sanitized, family) in families.into_iter().chain(std::iter::once((
        code_injection_flow_sinks as fn(FlowLanguage) -> Vec<FlowSink>,
        (|_| false) as fn(&str) -> bool,
        3,
    ))) {
        let summaries: Vec<FlowSummaries> = modules
            .iter()
            .enumerate()
            .map(|(index, module)| {
                let sinks = build_sinks(module.language);
                flow_summaries(
                    &lines[index],
                    module.language,
                    &sinks,
                    sanitized,
                    family == 0,
                    &functions[index],
                )
            })
            .collect();
        // Deep callee summaries: per file, function, and parameter, the
        // `(file index, sink line)` pairs a value passed in that position
        // reaches. They start from the shallow summaries pinned to their
        // own file, then iterate: a callee whose own imports forward the
        // value onward also contributes the sinks those imports reach.
        // Iterate until the summaries stop changing: each round propagates
        // one import hop, so chains of any length converge within one round
        // per module, and import cycles simply stop changing.
        // Per parameter, the `(file index, sink line)` pairs reached; per
        // function, one set per parameter; per module, one entry per callee.
        type DeepSummaries = Vec<Vec<std::collections::HashSet<(usize, usize)>>>;
        let mut deep: Vec<DeepSummaries> = modules
            .iter()
            .enumerate()
            .map(|(index, _)| {
                summaries[index]
                    .iter()
                    .map(|function| {
                        function
                            .iter()
                            .map(|lines| lines.iter().map(|line| (index, *line)).collect())
                            .collect()
                    })
                    .collect()
            })
            .collect();
        let build_imports = |caller: usize, deep_map: &[DeepSummaries]| -> Vec<ImportedCallee> {
            let module = &modules[caller];
            let mut imports = Vec::new();
            for binding in &bindings[caller] {
                let (receiver, target, pairs): (Option<String>, usize, Vec<(String, usize)>) =
                    match binding {
                        ImportBinding::Module {
                            binding,
                            target,
                            exported_only,
                        } => (
                            Some(binding.clone()),
                            *target,
                            exports[*target]
                                .iter()
                                .filter(|(name, _)| {
                                    !exported_only
                                        || name.chars().next().is_some_and(|ch| ch.is_uppercase())
                                })
                                .map(|(name, function)| (name.clone(), *function))
                                .collect(),
                        ),
                        ImportBinding::Function {
                            local,
                            exported,
                            target,
                        } => (
                            None,
                            *target,
                            exports[*target]
                                .get(exported)
                                .map(|function| vec![(local.clone(), *function)])
                                .unwrap_or_default(),
                        ),
                        // Star bindings are expanded into Function bindings
                        // before this pass; none remain here.
                        ImportBinding::Star { target } => (None, *target, Vec::new()),
                    };
                // Only resolve within one language family.
                if modules[target].language != module.language {
                    continue;
                }
                for (name, function) in pairs {
                    let params = functions[target][function].params.len();
                    let reached = deep_map[target][function].clone();
                    if reached.iter().all(|lines| lines.is_empty()) {
                        continue;
                    }
                    imports.push(ImportedCallee {
                        receiver: receiver.clone(),
                        name,
                        target,
                        params,
                        summaries: reached,
                    });
                }
            }
            // Chained Rust module paths: with `mod api;` in scope,
            // `pub mod users;` inside api, and so on, `api::users::f(...)`
            // and longer chains resolve by walking one module binding per
            // segment. The walk is bounded by the module count, so module
            // cycles cannot loop.
            if module.language == FlowLanguage::Rust {
                let mut chained = Vec::new();
                let mut frontier: Vec<(String, usize)> = bindings[caller]
                    .iter()
                    .filter_map(|binding| {
                        if let ImportBinding::Module {
                            binding: first,
                            target,
                            ..
                        } = binding
                        {
                            (modules[*target].language == FlowLanguage::Rust)
                                .then(|| (first.clone(), *target))
                        } else {
                            None
                        }
                    })
                    .collect();
                let mut depth = 1;
                while !frontier.is_empty() && depth < modules.len() {
                    depth += 1;
                    let mut next_frontier = Vec::new();
                    for (prefix, middle) in frontier {
                        for inner in &bindings[middle] {
                            let ImportBinding::Module {
                                binding: segment,
                                target,
                                exported_only,
                            } = inner
                            else {
                                continue;
                            };
                            if modules[*target].language != FlowLanguage::Rust {
                                continue;
                            }
                            let receiver = format!("{prefix}::{segment}");
                            for (name, function) in exports[*target].iter() {
                                if *exported_only
                                    && !name.chars().next().is_some_and(|ch| ch.is_uppercase())
                                {
                                    continue;
                                }
                                let reached = deep_map[*target][*function].clone();
                                if reached.iter().all(|lines| lines.is_empty()) {
                                    continue;
                                }
                                chained.push(ImportedCallee {
                                    receiver: Some(receiver.clone()),
                                    name: name.clone(),
                                    target: *target,
                                    params: functions[*target][*function].params.len(),
                                    summaries: reached,
                                });
                            }
                            next_frontier.push((receiver, *target));
                        }
                    }
                    frontier = next_frontier;
                }
                imports.extend(chained);
            }
            // JS instance variables: `this.repo = new Repo(...)` where
            // `Repo` is imported - a whole-module import (`const Repo =
            // require('./repo')`, `import * as Repo from './repo'`) or a
            // class import (`import Repo from './repo'`, `import { Repo }
            // from './repo'`, optionally `as`-aliased) - lets
            // `this.repo.m(...)` resolve to a method of the imported
            // file. Methods match by name within that file, whichever of
            // its classes defines them.
            if module.language == FlowLanguage::JavaScript {
                let Ok(instance_new) = instance_new.as_ref() else {
                    return imports;
                };
                for caller_function in &functions[caller] {
                    // Instance construction commonly lives in a constructor
                    // while the imported method call lives in a field arrow
                    // assigned inside that constructor. Inspect the containing
                    // function body, not only the arrow-function body.
                    let body_start = caller_function.body.start;
                    let body_end = caller_function.body.end;
                    for line in &lines[caller][body_start..body_end] {
                        let Some(captures) = instance_new.captures(line) else {
                            continue;
                        };
                        let (Some(variable), Some(class)) = (captures.get(1), captures.get(2))
                        else {
                            continue;
                        };
                        let target = bindings[caller].iter().find_map(|binding| {
                            let (name, target) = match binding {
                                ImportBinding::Module {
                                    binding: name,
                                    target,
                                    ..
                                } => (name.as_str(), *target),
                                ImportBinding::Function { local, target, .. } => {
                                    (local.as_str(), *target)
                                }
                                ImportBinding::Star { .. } => return None,
                            };
                            (name == class.as_str()
                                && modules[target].language == FlowLanguage::JavaScript)
                                .then_some(target)
                        });
                        let Some(target) = target else {
                            continue;
                        };
                        for (position, function) in functions[target].iter().enumerate() {
                            if !function.method {
                                continue;
                            }
                            let reached = deep_map[target][position].clone();
                            if reached.iter().all(|lines| lines.is_empty()) {
                                continue;
                            }
                            let receiver = if line.trim_start().starts_with("this.") {
                                format!("this.{}", variable.as_str())
                            } else {
                                variable.as_str().to_string()
                            };
                            imports.push(ImportedCallee {
                                receiver: Some(receiver),
                                name: function.name.clone(),
                                target,
                                params: function.params.len(),
                                summaries: reached,
                            });
                        }
                    }
                }
            }
            // Python instance variables: `self.repo = Store(...)` where
            // `Store` comes from `from .store import Store`, or
            // `self.repo = store.Store(...)` with `import store`, lets
            // `self.repo.m(...)` resolve to a method of the imported
            // file. Methods match by name within that file, whichever of
            // its classes defines them.
            if module.language == FlowLanguage::Python {
                let (Ok(instance_plain), Ok(instance_attr)) =
                    (instance_plain.as_ref(), instance_attr.as_ref())
                else {
                    return imports;
                };
                for line in &lines[caller] {
                    let code = line.split('#').next().unwrap_or("");
                    let (variable, target) = if let Some(captures) = instance_attr.captures(code) {
                        let (Some(variable), Some(module_name)) =
                            (captures.get(1), captures.get(2))
                        else {
                            continue;
                        };
                        let target = bindings[caller].iter().find_map(|binding| {
                            if let ImportBinding::Module {
                                binding: name,
                                target,
                                ..
                            } = binding
                            {
                                (name.as_str() == module_name.as_str()
                                    && modules[*target].language == FlowLanguage::Python)
                                    .then_some(*target)
                            } else {
                                None
                            }
                        });
                        (variable, target)
                    } else if let Some(captures) = instance_plain.captures(code) {
                        let (Some(variable), Some(class)) = (captures.get(1), captures.get(2))
                        else {
                            continue;
                        };
                        let target = bindings[caller].iter().find_map(|binding| {
                            if let ImportBinding::Function { local, target, .. } = binding {
                                (local.as_str() == class.as_str()
                                    && modules[*target].language == FlowLanguage::Python)
                                    .then_some(*target)
                            } else {
                                None
                            }
                        });
                        (variable, target)
                    } else {
                        continue;
                    };
                    let Some(target) = target else {
                        continue;
                    };
                    for (position, function) in functions[target].iter().enumerate() {
                        if !function.method {
                            continue;
                        }
                        let reached = deep_map[target][position].clone();
                        if reached.iter().all(|lines| lines.is_empty()) {
                            continue;
                        }
                        imports.push(ImportedCallee {
                            receiver: Some(format!("self.{}", variable.as_str())),
                            name: function.name.clone(),
                            target,
                            params: function.params.len(),
                            summaries: reached,
                        });
                    }
                }
            }
            // A call resolves only when one file provides the (receiver,
            // name) pair: two files offering the same callable are ambiguous
            // and neither resolves. Duplicate bindings for the same target
            // collapse instead.
            let mut groups: std::collections::HashMap<(Option<String>, String), Vec<usize>> =
                std::collections::HashMap::new();
            for (position, callee) in imports.iter().enumerate() {
                groups
                    .entry((callee.receiver.clone(), callee.name.clone()))
                    .or_default()
                    .push(position);
            }
            let mut keep = vec![true; imports.len()];
            for positions in groups.values() {
                let target = imports[positions[0]].target;
                if positions[1..]
                    .iter()
                    .any(|&position| imports[position].target != target)
                {
                    for &position in positions {
                        keep[position] = false;
                    }
                } else {
                    for &position in &positions[1..] {
                        keep[position] = false;
                    }
                }
            }
            let mut deduped = Vec::new();
            for (position, callee) in imports.into_iter().enumerate() {
                if keep[position] {
                    deduped.push(callee);
                }
            }
            deduped
        };
        for _ in 0..modules.len().max(3) {
            let mut next = deep.clone();
            let mut changed = false;
            for (caller, module) in modules.iter().enumerate() {
                let imports = build_imports(caller, &deep);
                if imports.is_empty() {
                    continue;
                }
                let sinks = build_sinks(module.language);
                let calls = FlowCalls {
                    functions: &functions[caller],
                    summaries: &summaries[caller],
                    imports: &imports,
                };
                for (function_index, function) in functions[caller].iter().enumerate() {
                    for (position, param) in function.params.iter().enumerate() {
                        let (reached, via_calls, imported) = flow_pass(
                            &lines[caller],
                            function.body.clone(),
                            module.language,
                            &sinks,
                            sanitized,
                            family == 0,
                            std::slice::from_ref(param),
                            false,
                            Some(&calls),
                        );
                        let mut pairs: std::collections::HashSet<(usize, usize)> = reached
                            .iter()
                            .chain(via_calls.iter())
                            .map(|line| (caller, *line))
                            .collect();
                        pairs.extend(imported.iter().copied());
                        if pairs != next[caller][function_index][position] {
                            next[caller][function_index][position] = pairs;
                            changed = true;
                        }
                    }
                }
            }
            deep = next;
            if !changed {
                break;
            }
        }
        for (caller, module) in modules.iter().enumerate() {
            let imports = build_imports(caller, &deep);
            if imports.is_empty() {
                continue;
            }
            let sinks = build_sinks(module.language);
            let calls = FlowCalls {
                functions: &functions[caller],
                summaries: &summaries[caller],
                imports: &imports,
            };
            let (_, _, mut reached) = flow_pass(
                &lines[caller],
                0..lines[caller].len(),
                module.language,
                &sinks,
                sanitized,
                family == 0,
                &[],
                true,
                Some(&calls),
            );
            for (body, seeds) in
                spring_annotated_seeds(&lines[caller], module.language, &functions[caller])
                    .into_iter()
                    .chain(python_route_seeds(
                        &lines[caller],
                        module.language,
                        &functions[caller],
                    ))
            {
                let (_, _, seeded_reached) = flow_pass(
                    &lines[caller],
                    body,
                    module.language,
                    &sinks,
                    sanitized,
                    family == 0,
                    &seeds,
                    true,
                    Some(&calls),
                );
                reached.extend(seeded_reached);
            }
            for (target, line) in reached {
                let entry = result.entry(modules[target].path.clone()).or_default();
                match family {
                    0 => entry.sql.insert(line),
                    1 => entry.command.insert(line),
                    2 => entry.ssrf.insert(line),
                    _ => entry.code.insert(line),
                };
            }
        }
    }
    result
}

