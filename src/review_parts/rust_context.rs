// Rust source context for line-based rules. No repository exemptions.
use proc_macro2::{Span, TokenStream, TokenTree};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::Visit;

#[derive(Default)]
pub(crate) struct RustContext {
    tests: HashSet<usize>,
    literals: Vec<(usize, usize)>,
    offsets: Vec<usize>,
}

impl RustContext {
    pub(crate) fn parse(content: &str, ext: &str) -> Self {
        let mut context = Self::default();
        if ext != "rs" {
            return context;
        }
        // Malformed or unsupported Rust remains scanned, never silently excluded.
        let Ok(file) = syn::parse_file(content) else {
            return context;
        };
        context.offsets.push(0);
        for (i, byte) in content.bytes().enumerate() {
            if byte == b'\n' {
                context.offsets.push(i + 1);
            }
        }
        context.visit_file(&file);
        if let Ok(tokens) = content.parse::<TokenStream>() {
            context.tokens(tokens);
        }
        context
    }
    fn offset(&self, line: usize, column: usize) -> usize {
        self.offsets
            .get(line.saturating_sub(1))
            .copied()
            .unwrap_or(0)
            + column
    }
    fn tokens(&mut self, tokens: TokenStream) {
        for token in tokens {
            match token {
                TokenTree::Group(group) => self.tokens(group.stream()),
                TokenTree::Literal(literal) => {
                    let span = literal.span();
                    self.literals.push((
                        self.offset(span.start().line, span.start().column),
                        self.offset(span.end().line, span.end().column),
                    ));
                }
                _ => {}
            }
        }
    }
    fn exclude_test(&mut self, attrs: &[syn::Attribute], span: Span) {
        // Only exact #[cfg(test)], not cfg(any(test, feature = "production")).
        let is_test = attrs.iter().any(|attr| {
            attr.path().is_ident("cfg")
                && attr.parse_args::<syn::Ident>().is_ok_and(|id| id == "test")
        });
        if is_test {
            self.tests.extend(span.start().line..=span.end().line);
        }
    }
    pub(crate) fn is_test(&self, line: usize) -> bool {
        self.tests.contains(&line)
    }
    pub(crate) fn executable_match(&self, line: usize, column: usize) -> bool {
        let offset = self.offset(line, column);
        !self
            .literals
            .iter()
            .any(|&(start, end)| start <= offset && offset < end)
    }
}

impl<'ast> Visit<'ast> for RustContext {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs: &[syn::Attribute] = match item {
            syn::Item::Const(i) => &i.attrs,
            syn::Item::Enum(i) => &i.attrs,
            syn::Item::Fn(i) => &i.attrs,
            syn::Item::Impl(i) => &i.attrs,
            syn::Item::Macro(i) => &i.attrs,
            syn::Item::Mod(i) => &i.attrs,
            syn::Item::Static(i) => &i.attrs,
            syn::Item::Struct(i) => &i.attrs,
            syn::Item::Trait(i) => &i.attrs,
            syn::Item::Type(i) => &i.attrs,
            syn::Item::Use(i) => &i.attrs,
            _ => &[],
        };
        self.exclude_test(attrs, item.span());
        syn::visit::visit_item(self, item);
    }
    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.exclude_test(&item.attrs, item.span());
        syn::visit::visit_impl_item_fn(self, item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_items_do_not_hide_following_production() {
        let source = "#[cfg(test)]\nmod regression {\nfn example() { let password = \"bad\"; }\n}\nfn shipped() { let password = \"bad\"; }";
        let ctx = RustContext::parse(source, "rs");
        assert!(ctx.is_test(3));
        assert!(!ctx.is_test(5));
        assert!(ctx.executable_match(5, 19));
    }
    #[test]
    fn conditional_production_and_invalid_rust_remain_scanned() {
        let ctx = RustContext::parse(
            "#[cfg(any(test, feature = \"server\"))]\nfn shipped() {}",
            "rs",
        );
        assert!(!ctx.is_test(2));
        assert!(!RustContext::parse("#[cfg(test)]\ninvalid rust", "rs").is_test(2));
    }
    #[test]
    fn raw_multiline_literals_and_executable_suffix() {
        let ctx = RustContext::parse("fn f() { let rule = r###\"\n dangerous_accept_invalid_certs\n\"###; client.dangerous_accept_invalid_certs(true); }", "rs");
        assert!(!ctx.executable_match(2, 1));
        assert!(ctx.executable_match(3, 13));
    }
}

/// Resolve literal include! edges in Rust syntax. A file is test-only only
/// when every reachable inclusion is beneath an exact cfg(test) item.
/// Mixed production/test use, cycles without roots, dynamic paths and parse
/// failures stay scanned. No path-name exemptions are used.
pub(crate) fn test_only_includes(files: &[std::path::PathBuf]) -> HashSet<std::path::PathBuf> {
    use std::collections::{HashMap, VecDeque};
    use std::path::{Path, PathBuf};
    struct Edges<'a> {
        file: &'a Path,
        test: bool,
        edges: Vec<(PathBuf, bool)>,
        unresolved: bool,
        modules: Vec<String>,
    }
    impl<'ast> Visit<'ast> for Edges<'_> {
        fn visit_item(&mut self, item: &'ast syn::Item) {
            let attrs: &[syn::Attribute] = match item {
                syn::Item::Fn(i) => &i.attrs,
                syn::Item::Mod(i) => &i.attrs,
                syn::Item::Macro(i) => &i.attrs,
                syn::Item::Impl(i) => &i.attrs,
                syn::Item::Const(i) => &i.attrs,
                syn::Item::Static(i) => &i.attrs,
                _ => &[],
            };
            let previous = self.test;
            self.test |= attrs.iter().any(|a| {
                a.path().is_ident("cfg")
                    && a.parse_args::<syn::Ident>().is_ok_and(|id| id == "test")
            });
            syn::visit::visit_item(self, item);
            self.test = previous;
        }
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if item.content.is_none() {
                self.modules.push(item.ident.to_string());
            }
            syn::visit::visit_item_mod(self, item);
        }
        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            if mac.path.is_ident("include") {
                if let Ok(literal) = syn::parse2::<syn::LitStr>(mac.tokens.clone()) {
                    if let Some(parent) = self.file.parent() {
                        if let Ok(target) = parent.join(literal.value()).canonicalize() {
                            self.edges.push((target, self.test));
                        } else {
                            self.unresolved = true;
                        }
                    }
                } else {
                    self.unresolved = true;
                }
            }
            syn::visit::visit_macro(self, mac);
        }
    }
    let known: HashSet<PathBuf> = files.iter().filter_map(|p| p.canonicalize().ok()).collect();
    let mut graph: HashMap<PathBuf, Vec<(PathBuf, bool)>> = HashMap::new();
    let mut included = HashSet::new();
    let mut module_names = HashSet::new();
    for path in &known {
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        let Ok(parsed) = syn::parse_file(&content) else {
            continue;
        };
        let mut visitor = Edges {
            file: path,
            test: false,
            edges: vec![],
            unresolved: false,
            modules: vec![],
        };
        visitor.visit_file(&parsed);
        if visitor.unresolved {
            return HashSet::new();
        }
        module_names.extend(visitor.modules);
        visitor.edges.retain(|(target, _)| known.contains(target));
        included.extend(visitor.edges.iter().map(|(p, _)| p.clone()));
        graph.insert(path.clone(), visitor.edges);
    }
    let mut queue: VecDeque<(PathBuf, bool)> = known
        .iter()
        .filter(|p| {
            !included.contains(*p)
                || p.file_stem()
                    .is_some_and(|s| module_names.contains(&s.to_string_lossy().to_string()))
        })
        .map(|p| (p.clone(), false))
        .collect();
    let mut seen = HashSet::new();
    while let Some((path, test)) = queue.pop_front() {
        if !seen.insert((path.clone(), test)) {
            continue;
        }
        if let Some(edges) = graph.get(&path) {
            for (next, local_test) in edges {
                queue.push_back((next.clone(), test || *local_test));
            }
        }
    }
    known
        .into_iter()
        .filter(|p| seen.contains(&(p.clone(), true)) && !seen.contains(&(p.clone(), false)))
        .collect()
}

#[cfg(test)]
mod include_tests {
    use super::*;
    #[test]
    fn include_ancestry_test_only_mixed_and_cycles() {
        let root = std::env::temp_dir().join(format!("cipher-includes-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        for (name, body) in [
            ("main.rs", "#[cfg(test)] mod t { include!(\"test.rs\"); include!(\"mixed.rs\"); } include!(\"mixed.rs\"); include!(\"prod.rs\");"),
            ("test.rs", "include!(\"nested.rs\");"), ("nested.rs", "fn x() {}"),
            ("mixed.rs", "fn x() {}"), ("prod.rs", "fn x() {}"),
            ("cycle_a.rs", "include!(\"cycle_b.rs\");"), ("cycle_b.rs", "include!(\"cycle_a.rs\");"),
        ] { std::fs::write(root.join(name), body).unwrap(); }
        let files: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        let result = test_only_includes(&files);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&root.join("test.rs").canonicalize().unwrap()));
        assert!(result.contains(&root.join("nested.rs").canonicalize().unwrap()));
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod conservative_include_tests {
    use super::*;
    #[test]
    fn dynamic_include_and_production_mod_are_not_hidden() {
        let root =
            std::env::temp_dir().join(format!("cipher-dynamic-includes-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let main = root.join("main.rs");
        let target = root.join("helper.rs");
        std::fs::write(&target, "fn production() {}").unwrap();
        std::fs::write(
            &main,
            "mod helper; #[cfg(test)] mod t { include!(\"helper.rs\"); }",
        )
        .unwrap();
        assert!(test_only_includes(&[main.clone(), target.clone()]).is_empty());
        std::fs::write(&main, "include!(concat!(\"helper\", \".rs\")); #[cfg(test)] mod t { include!(\"helper.rs\"); }").unwrap();
        assert!(test_only_includes(&[main, target]).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
}
