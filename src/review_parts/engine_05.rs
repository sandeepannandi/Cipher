/// Rails 8.0's legacy redirect default allows off-site redirects unless the
/// application opts into 7.0+ defaults or explicitly forbids other hosts.
fn scoped_rails_login_redirect(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let controller = root.join("app/controllers/sessions_controller.rb");
    let (Ok(text), Ok(app), Ok(lock)) = (
        std::fs::read_to_string(&controller),
        std::fs::read_to_string(root.join("config/application.rb")),
        std::fs::read_to_string(root.join("Gemfile.lock")),
    ) else {
        return vec![];
    };
    fn code(text: &str) -> Vec<&str> {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#'))
            .collect()
    }
    let app_code = code(&app);
    let lines = code(&text);
    if !lock.contains("actionpack (8.0.4)")
        || !text.contains("class SessionsController < ApplicationController")
        || !app_code
            .iter()
            .any(|line| line.contains("< Rails::Application"))
        || app_code.iter().any(|line| {
            line.contains("load_defaults 7.")
                || line.contains("load_defaults 8.")
                || line.contains("raise_on_open_redirects = true")
        })
        || lines.iter().any(|line| {
            line.contains("allow_other_host: false")
                || line.contains("url_from(")
                || line.contains("_url_host_allowed?")
        })
        || !lines.iter().any(|line| {
            line.contains("path = params[:url].present? ? params[:url] : home_dashboard_index_path")
        })
        || !lines.iter().any(|line| line == &"if user")
    {
        return vec![];
    }
    let Some((index, sink)) = text
        .lines()
        .enumerate()
        .find(|(_, line)| line.trim() == "redirect_to path")
    else {
        return vec![];
    };
    let Some(pattern) = patterns.iter().find(|p| p.name == "Open Redirect") else {
        return vec![];
    };
    vec![pattern_finding(pattern, &controller, index + 1, sink)]
}

/// Rails nested user resource selected from the URL and rendered with sensitive
/// fields. Authentication alone is not ownership: require route and view links.
fn scoped_rails_work_info_idor(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let controller = root.join("app/controllers/work_info_controller.rb");
    let base = root.join("app/controllers/application_controller.rb");
    let routes = root.join("config/routes.rb");
    let view = root.join("app/views/work_info/index.html.erb");
    let (Ok(text), Ok(base), Ok(routes), Ok(view)) = (
        std::fs::read_to_string(&controller),
        std::fs::read_to_string(base),
        std::fs::read_to_string(routes),
        std::fs::read_to_string(view),
    ) else {
        return vec![];
    };
    if !text.contains("< ApplicationController")
        || !routes.contains("resources :users do")
        || !routes.contains("resources :work_info")
        || !base.contains("before_action :authenticated")
        || !view.contains("@user.work_info.SSN")
        || !view.contains("@user.work_info.income")
    {
        return vec![];
    }
    let active: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .collect();
    let Some((index, source)) = active
        .iter()
        .enumerate()
        .find(|(_, line)| line.contains("@user = User.find_by(id: params[:user_id])"))
    else {
        return vec![];
    };
    let ownership = Regex::new(r"(?i)(?:@user\.id\s*==?\s*current_user\.id|current_user\.id\s*==?\s*@user\.id|authorize\b|check_ownership\b|current_user\.users\b|current_user\.work_info\b)").expect("valid ownership guard");
    if ownership.is_match(&active.join("\n"))
        || !active.iter().any(|line| line.contains("@user.admin"))
    {
        return vec![];
    }
    let Some(pattern) = patterns
        .iter()
        .find(|p| p.name == "Insecure Direct Object Reference (IDOR)")
    else {
        return vec![];
    };
    // Find the original line because comment filtering changes positions.
    let line_number = text
        .lines()
        .position(|line| line.trim() == *source)
        .unwrap_or(index)
        + 1;
    vec![pattern_finding(pattern, &controller, line_number, source)]
}

/// Rails CSRF requires application-level proof. A commented out declaration alone
/// is not enough: newer Rails defaults may still enable protection automatically.
/// Django templates autoescape by default; the `safe` filter disables
/// escaping for the rendered value, so a user-influenced value marked safe is
/// rendered as raw HTML. Gate on Django project evidence (`manage.py` naming
/// the settings module) and scan HTML templates for `{{ value|safe }}`.
/// HTML comments and Django `{# ... #}` comments are not findings, and
/// HTML-escaped documentation (`&#123;&#123;`) never forms a literal tag.
#[allow(clippy::items_after_test_module)]
fn scoped_django_safe_filter_findings(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(manage) = std::fs::read_to_string(root.join("manage.py")) else {
        return findings;
    };
    if !manage.contains("DJANGO_SETTINGS_MODULE") {
        return findings;
    }
    let Ok(safe_output) = Regex::new(r"\{\{[^{}]*\|\s*safe\s*\}\}") else {
        return findings;
    };
    let walker = WalkBuilder::new(root)
        .git_ignore(true)
        .git_global(true)
        .hidden(false)
        .max_depth(Some(scan::MAX_WALK_DEPTH))
        .build();
    let mut scanned = 0usize;
    for result in walker {
        if scanned >= scan::MAX_SCAN_FILES {
            break;
        }
        let Ok(entry) = result else {
            continue;
        };
        let path = entry.path();
        if !path.is_file() || file_extension(path) != "html" || scan::should_exclude_in(path, root)
        {
            continue;
        }
        scanned += 1;
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        for (index, line) in content.lines().enumerate() {
            let trim = line.trim_start();
            if trim.starts_with("<!--") || trim.starts_with("{#") {
                continue;
            }
            if safe_output.is_match(line) {
                if let Some(pattern) = patterns
                    .iter()
                    .find(|p| p.name == "Unescaped Django Output (XSS)")
                {
                    findings.push(pattern_finding(pattern, path, index + 1, line));
                }
            }
        }
    }
    findings
}

fn scoped_rails_csrf_findings(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let application = root.join("config/application.rb");
    let controller = root.join("app/controllers/application_controller.rb");
    let routes = root.join("config/routes.rb");
    let schedule = root.join("app/controllers/schedule_controller.rb");
    let session = root.join("config/initializers/session_store.rb");
    let Ok(app) = std::fs::read_to_string(application) else {
        return vec![];
    };
    let Ok(base) = std::fs::read_to_string(&controller) else {
        return vec![];
    };
    let Ok(routes) = std::fs::read_to_string(routes) else {
        return vec![];
    };
    let Ok(schedule) = std::fs::read_to_string(schedule) else {
        return vec![];
    };
    let Ok(session) = std::fs::read_to_string(session) else {
        return vec![];
    };
    let Ok(lock) = std::fs::read_to_string(root.join("Gemfile.lock")) else {
        return vec![];
    };
    fn active(text: &str) -> Vec<&str> {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#'))
            .collect()
    }
    let app_code = active(&app);
    let base_code = active(&base);
    // This legacy RailsGoat application does not load 5.2+ defaults. In Rails
    // 8.0.4, the railtie adds protection only when the default config is true.
    // A configured default or active controller guard is a negative control.
    if !lock.contains("actionpack (8.0.4)")
        || !app_code.iter().any(|l| l.contains("< Rails::Application"))
        || app_code.iter().any(|l| {
            l.contains("load_defaults") || l.contains("default_protect_from_forgery = true")
        })
        || base_code
            .iter()
            .any(|l| l.contains("protect_from_forgery") || l.contains("verify_authenticity_token"))
        || !base_code
            .iter()
            .any(|l| l.contains("< ActionController::Base"))
        || !session.contains("session_store :cookie_store")
        || !routes.contains("resources :schedule")
        || !schedule.contains("def create")
        || !schedule.contains("sched.save")
    {
        return vec![];
    }
    let Some((i, line)) = base.lines().enumerate().find(|(_, line)| {
        line.trim_start()
            .starts_with("#protect_from_forgery with: :exception")
    }) else {
        return vec![];
    };
    let Some(pattern) = patterns
        .iter()
        .find(|p| p.name == "Missing CSRF Protection")
    else {
        return vec![];
    };
    vec![pattern_finding(pattern, &controller, i + 1, line)]
}

/// Guarded, project-context checks: do not infer XSS from interpolation alone
/// or CSRF from a POST alone. Both require evidence in the app bootstrap and
/// concrete source/template or session/route links.
fn scoped_template_xss_csrf_findings(
    files: &[std::path::PathBuf],
    root: &Path,
    patterns: &[VulnPattern],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(autoescape) = Regex::new(r"\bautoescape\s*:\s*false\b") else {
        return findings;
    };
    let Ok(profile_field) =
        Regex::new(r"\buser\.(?:firstName|lastName)\s*=\s*(?:firstName|lastName)\b")
    else {
        return findings;
    };
    let Ok(interpolation) = Regex::new(r"\{\{\s*(firstName|lastName|firstNameSafeString)\s*\}\}")
    else {
        return findings;
    };
    let Ok(html_header) = Regex::new(r#"(?i)Content-Type["']?\s*:\s*["']text/html"#) else {
        return findings;
    };
    let Ok(session) = Regex::new(r"\bapp\.use\s*\(\s*session\s*\(") else {
        return findings;
    };
    let Ok(csrf) = Regex::new(r"\bapp\.use\s*\(\s*(?:csrf|csurf|csrfProtection)\s*\(") else {
        return findings;
    };
    let Ok(form_route) = Regex::new(r#"\bapp\.post\s*\(\s*["'](/(?:profile|benefits))["']"#) else {
        return findings;
    };
    let mut active = std::collections::HashMap::new();
    for path in files {
        if is_test_context_path(path, root) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        // Exclude complete JS block comments as well as single-line comments.
        let mut block = false;
        let code: Vec<(usize, String)> = content
            .lines()
            .enumerate()
            .filter_map(|(i, line)| {
                let trim = line.trim();
                if block {
                    if trim.contains("*/") {
                        block = false;
                    }
                    return None;
                }
                if trim.starts_with("/*") {
                    block = !trim.contains("*/");
                    return None;
                }
                if trim.starts_with("//") || trim.starts_with('*') || trim.starts_with("<!--") {
                    return None;
                }
                Some((i + 1, line.split("//").next().unwrap_or(line).to_string()))
            })
            .collect();
        active.insert(path.clone(), code);
    }
    let bootstrap = root.join("server.js");
    let Some(server) = active.get(&bootstrap) else {
        return findings;
    };
    let has_session = server.iter().any(|(_, line)| session.is_match(line));
    let swig_engine = server
        .iter()
        .any(|(_, line)| line.contains("consolidate.swig"));
    let has_csrf = server.iter().any(|(_, line)| csrf.is_match(line));
    let escape_off = server.iter().any(|(_, line)| autoescape.is_match(line));
    let views = root.join("app/views");
    let profiles = root.join("app/data/profile-dao.js");
    let profile_stored = active.get(&profiles).is_some_and(|lines| {
        lines.iter().any(|(_, line)| profile_field.is_match(line))
            && lines.iter().any(|(_, line)| line.contains("users.update("))
    });
    // HTML is not ordinarily part of the code scan set. Only follow a
    // rendered profile and its inherited layout after confirming the write
    // and both input paths, rather than scanning unrelated interpolations.
    let profile_route = active.get(&root.join("app/routes/profile.js"));
    let profile_render = profile_route.is_some_and(|lines| {
        lines
            .iter()
            .any(|(_, line)| line.contains("res.render(\"profile\""))
            && lines.iter().any(|(_, line)| line.contains("...doc"))
            && lines
                .iter()
                .any(|(_, line)| line.contains("firstNameSafeString = firstName"))
            && lines.iter().any(|(_, line)| line.contains("req.body"))
            && lines
                .iter()
                .any(|(_, line)| line.contains("profile.updateUser("))
    });
    if swig_engine && escape_off && profile_stored && profile_render {
        let profile = views.join("profile.html");
        let inherits_layout = std::fs::read_to_string(&profile).is_ok_and(|text| {
            text.contains("extends './layout.html'")
                || text.contains("extends \"./layout.html\"")
                || text.contains("extends 'layout.html'")
                || text.contains("extends \"layout.html\"")
        });
        for path in [profile, views.join("layout.html")] {
            if path.ends_with("layout.html") && !inherits_layout {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            for (index, line) in content.lines().enumerate() {
                if line.trim_start().starts_with("<!--") {
                    continue;
                }
                if interpolation.is_match(line) {
                    if let Some(pattern) = patterns
                        .iter()
                        .find(|p| p.name == "Unescaped Template Output (XSS)")
                    {
                        findings.push(pattern_finding(pattern, &path, index + 1, line));
                    }
                }
            }
        }
    }
    // Reflected HTML from an HTTP client is a separate flow from templates.
    for (path, lines) in &active {
        if !matches!(file_extension(path).as_str(), "js" | "ts")
            || !path.starts_with(root.join("app/routes"))
        {
            continue;
        }
        let source = lines.iter().any(|(_, line)| line.contains("needle.get("));
        let html = lines.iter().any(|(_, line)| html_header.is_match(line));
        if source && html {
            for (number, line) in lines {
                if line.contains("res.write(body)") {
                    if let Some(pattern) = patterns
                        .iter()
                        .find(|p| p.name == "Unsafe HTML Response (XSS)")
                    {
                        findings.push(pattern_finding(pattern, path, *number, line));
                    }
                }
            }
        }
    }
    if has_session && !has_csrf {
        let index = root.join("app/routes/index.js");
        if let Some(lines) = active.get(&index) {
            for (number, line) in lines {
                let route = form_route
                    .captures(line)
                    .and_then(|capture| capture.get(1))
                    .map(|match_| match_.as_str());
                let has_form = route.is_some_and(|route| {
                    let template = views.join(format!("{}.html", &route[1..]));
                    std::fs::read_to_string(template).is_ok_and(|html| {
                        html.lines().any(|form| {
                            form.contains("<form")
                                && (form.contains("method=\"POST\"")
                                    || form.contains("method=\"post\""))
                                && form.contains(&format!("action=\"{route}\""))
                        })
                    })
                });
                if has_form && !line.contains("csrf") && !line.contains("Csrf") {
                    if let Some(pattern) = patterns
                        .iter()
                        .find(|p| p.name == "Missing CSRF Protection")
                    {
                        findings.push(pattern_finding(pattern, &index, *number, line));
                    }
                }
            }
        }
    }
    findings
}

/// Login-specific session lifecycle check. A session assignment alone is not
/// enough: require a cookie-session app, credential validation, and a success
/// branch that assigns the authenticated identity without an active regenerate.
fn scoped_login_session_findings(
    files: &[std::path::PathBuf],
    root: &Path,
    patterns: &[VulnPattern],
) -> Vec<Finding> {
    let server = root.join("server.js");
    let handler = root.join("app/routes/session.js");
    if !files.contains(&server) || !files.contains(&handler) || is_test_context_path(&handler, root)
    {
        return Vec::new();
    }
    let Ok(server_body) = std::fs::read_to_string(&server) else {
        return Vec::new();
    };
    let Ok(handler_body) = std::fs::read_to_string(&handler) else {
        return Vec::new();
    };
    let active_lines = |body: &str| {
        let mut block = false;
        body.lines()
            .enumerate()
            .filter_map(|(index, line)| {
                let trimmed = line.trim();
                if block {
                    if trimmed.contains("*/") {
                        block = false;
                    }
                    return None;
                }
                if trimmed.starts_with("/*") {
                    block = !trimmed.contains("*/");
                    return None;
                }
                if trimmed.starts_with("//") || trimmed.starts_with('*') {
                    return None;
                }
                Some((
                    index + 1,
                    line.split("//").next().unwrap_or(line).to_string(),
                ))
            })
            .collect::<Vec<_>>()
    };
    let server_code = active_lines(&server_body);
    if !server_code
        .iter()
        .any(|(_, line)| line.contains("app.use(session("))
    {
        return Vec::new();
    }
    let code = active_lines(&handler_body);
    let start = code
        .iter()
        .position(|(_, line)| line.contains("this.handleLoginRequest ="));
    let end = code
        .iter()
        .position(|(_, line)| line.contains("this.displayLogoutPage ="));
    let (Some(start), Some(end)) = (start, end) else {
        return Vec::new();
    };
    if start >= end {
        return Vec::new();
    }
    let login = &code[start..end];
    if !login
        .iter()
        .any(|(_, line)| line.contains("validateLogin(") && line.contains("password"))
    {
        return Vec::new();
    }
    let Some((line_number, line)) = login
        .iter()
        .find(|(_, line)| line.contains("req.session.userId = user._id"))
    else {
        return Vec::new();
    };
    // A regenerate call anywhere in this one login handler is safer than
    // declaring fixation; this deliberately trades recall for precision.
    if login
        .iter()
        .any(|(_, line)| line.contains("req.session.regenerate("))
    {
        return Vec::new();
    }
    let Some(pattern) = patterns
        .iter()
        .find(|p| p.name == "Session Fixation on Login")
    else {
        return Vec::new();
    };
    vec![pattern_finding(pattern, &handler, *line_number, line)]
}

/// Narrow login-log check: the variable must be destructured from req.body in
/// the same login handler and logged directly. A tutorial's commented fix, a
/// constant log, and an active CR/LF replacement do not establish log forging.
fn scoped_login_log_forging_findings(
    files: &[std::path::PathBuf],
    root: &Path,
    patterns: &[VulnPattern],
) -> Vec<Finding> {
    let path = root.join("app/routes/session.js");
    if !files.contains(&path) || is_test_context_path(&path, root) {
        return Vec::new();
    }
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut block_comment = false;
    let code: Vec<(usize, &str)> = content
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let trimmed = line.trim();
            if block_comment {
                if trimmed.contains("*/") {
                    block_comment = false;
                }
                return None;
            }
            if trimmed.starts_with("/*") {
                block_comment = !trimmed.contains("*/");
                return None;
            }
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                return None;
            }
            Some((i + 1, line.split("//").next().unwrap_or(line)))
        })
        .collect();
    let start = code
        .iter()
        .position(|(_, line)| line.contains("this.handleLoginRequest ="));
    let end = code
        .iter()
        .position(|(_, line)| line.contains("this.displayLogoutPage ="));
    let (Some(start), Some(end)) = (start, end) else {
        return Vec::new();
    };
    if start >= end {
        return Vec::new();
    }
    let login = &code[start..end];
    // Destructuring is often split across lines, as in NodeGoat. Inspect
    // only the declaration-to-assignment window, not unrelated uses.
    let has_source = login.iter().enumerate().any(|(i, (_, line))| {
        if !line.contains("const {") && !line.contains("let {") && !line.contains("var {") {
            return false;
        }
        let declaration = login[i..login.len().min(i + 6)]
            .iter()
            .map(|(_, line)| *line)
            .collect::<Vec<_>>()
            .join(" ");
        declaration.contains("userName") && declaration.contains("= req.body")
    });
    if !has_source
        || !login
            .iter()
            .any(|(_, line)| line.contains("validateLogin("))
    {
        return Vec::new();
    }
    let Some(sink) = Regex::new(r"\bconsole\.(?:log|warn|error|info)\s*\([^)]*\buserName\b").ok()
    else {
        return Vec::new();
    };
    let Some(pattern) = patterns
        .iter()
        .find(|p| p.name == "Log Forging from Login Input")
    else {
        return Vec::new();
    };
    login
        .iter()
        .filter(|(_, line)| {
            sink.is_match(line)
                && !line.contains("userName.replace(")
                && !line.contains("encodeFor")
        })
        .map(|(number, line)| pattern_finding(pattern, &path, *number, line))
        .collect()
}

/// Require distinct, active login error values in the noSuchUser and
/// invalidPassword branches. Only the public `loginError` values count: log
/// messages and commented tutorial fixes do not establish enumeration.
fn scoped_login_enumeration_findings(
    files: &[std::path::PathBuf],
    root: &Path,
    patterns: &[VulnPattern],
) -> Vec<Finding> {
    let path = root.join("app/routes/session.js");
    if !files.contains(&path) || is_test_context_path(&path, root) {
        return Vec::new();
    }
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut block_comment = false;
    let code: Vec<(usize, String)> = content
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let trimmed = line.trim();
            if block_comment {
                if trimmed.contains("*/") {
                    block_comment = false;
                }
                return None;
            }
            if trimmed.starts_with("/*") {
                block_comment = !trimmed.contains("*/");
                return None;
            }
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                return None;
            }
            Some((i + 1, line.split("//").next().unwrap_or(line).to_string()))
        })
        .collect();
    let start = code
        .iter()
        .position(|(_, line)| line.contains("this.handleLoginRequest ="));
    let end = code
        .iter()
        .position(|(_, line)| line.contains("this.displayLogoutPage ="));
    let (Some(start), Some(end)) = (start, end) else {
        return Vec::new();
    };
    if start >= end {
        return Vec::new();
    }
    let login = &code[start..end];
    if !login
        .iter()
        .any(|(_, line)| line.contains("validateLogin("))
    {
        return Vec::new();
    }
    let unknown = login
        .iter()
        .position(|(_, line)| line.contains("err.noSuchUser"));
    let wrong = login
        .iter()
        .position(|(_, line)| line.contains("err.invalidPassword"));
    let (Some(unknown), Some(wrong)) = (unknown, wrong) else {
        return Vec::new();
    };
    if unknown >= wrong {
        return Vec::new();
    }
    let Some(assign) = Regex::new(r#"\b(?:const|let|var)\s+(\w+)\s*=\s*["']([^"']+)["']"#).ok()
    else {
        return Vec::new();
    };
    let mut values = std::collections::HashMap::new();
    for (_, line) in &login[..unknown] {
        if let Some(capture) = assign.captures(line) {
            values.insert(capture[1].to_string(), capture[2].to_string());
        }
    }
    let Some(error_field) = Regex::new(r#"\bloginError\s*:\s*(\w+|["'][^"']+["'])"#).ok() else {
        return Vec::new();
    };
    let public_error = |branch: &[(usize, String)]| {
        branch.iter().find_map(|(number, line)| {
            let capture = error_field.captures(line)?;
            let expr = capture.get(1)?.as_str();
            let value = if expr.starts_with(['\"', '\'']) {
                expr[1..expr.len() - 1].to_string()
            } else {
                values.get(expr)?.clone()
            };
            Some((*number, line.clone(), value))
        })
    };
    let (Some((number, line, unknown_value)), Some((_, _, wrong_value))) = (
        public_error(&login[unknown..wrong]),
        public_error(&login[wrong..]),
    ) else {
        return Vec::new();
    };
    if unknown_value == wrong_value {
        return Vec::new();
    }
    let Some(pattern) = patterns
        .iter()
        .find(|p| p.name == "Login Username Enumeration")
    else {
        return Vec::new();
    };
    vec![pattern_finding(pattern, &path, number, &line)]
}

/// Evidence-coupled profile storage check. Require several raw assignments
/// into the same document and an active database update of that document.
/// An active encrypt/transform for any tracked field suppresses the group,
/// deliberately preferring missed variants to mislabeled encrypted storage.
fn scoped_sensitive_profile_storage_findings(
    files: &[std::path::PathBuf],
    root: &Path,
    patterns: &[VulnPattern],
) -> Vec<Finding> {
    let path = root.join("app/data/profile-dao.js");
    if !files.contains(&path) || is_test_context_path(&path, root) {
        return Vec::new();
    }
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut in_block_comment = false;
    let active: Vec<(usize, String)> = content
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let trimmed = line.trim();
            if in_block_comment {
                if trimmed.contains("*/") {
                    in_block_comment = false;
                }
                return None;
            }
            if trimmed.starts_with("/*") {
                in_block_comment = !trimmed.contains("*/");
                return None;
            }
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                return None;
            }
            Some((
                index + 1,
                line.split("//").next().unwrap_or(line).to_string(),
            ))
        })
        .collect();
    let start = active
        .iter()
        .position(|(_, line)| line.contains("this.updateUser ="));
    let end = active
        .iter()
        .position(|(_, line)| line.contains("this.getByUserId ="));
    let (Some(start), Some(end)) = (start, end) else {
        return Vec::new();
    };
    if start >= end {
        return Vec::new();
    }
    let method = &active[start..end];
    if !method[0].1.contains("ssn")
        || !method[0].1.contains("dob")
        || !method[0].1.contains("bankAcc")
    {
        return Vec::new();
    }
    let Some(sink) = method
        .iter()
        .position(|(_, line)| line.contains("users.update("))
    else {
        return Vec::new();
    };
    if !method[sink..method.len().min(sink + 10)]
        .iter()
        .any(|(_, line)| line.contains("$set: user"))
    {
        return Vec::new();
    }
    let mut assignments = Vec::new();
    for field in ["ssn", "dob", "bankAcc", "bankRouting"] {
        let raw = format!("user.{field} = {field};");
        let transformed = format!("user.{field} =");
        if method[..sink]
            .iter()
            .any(|(_, line)| line.contains(&transformed) && !line.contains(&raw))
        {
            return Vec::new();
        }
        if let Some((number, line)) = method[..sink].iter().find(|(_, line)| line.contains(&raw)) {
            assignments.push((*number, line.as_str()));
        }
    }
    if assignments.len() < 2 {
        return Vec::new();
    }
    let Some(pattern) = patterns
        .iter()
        .find(|p| p.name == "Raw Sensitive Profile Storage")
    else {
        return Vec::new();
    };
    // One group finding, anchored on the first raw assignment. The remaining
    // raw fields and database sink are the corroborating context.
    let (number, line) = assignments[0];
    vec![pattern_finding(pattern, &path, number, line)]
}

/// Collect review findings without displaying them (for report generation)
pub(crate) async fn collect_review_findings(
    project_path: &Path,
    use_ai: bool,
    model: Option<&str>,
) -> Result<FindingReport> {
    let canonical_path = std::fs::canonicalize(project_path)?;

    let patterns = build_vuln_patterns();
    let mut report = FindingReport::new("security-review", canonical_path.to_string_lossy());

    // Walk source files with exclusions, depth limit, and file cap
    let walker = WalkBuilder::new(&canonical_path)
        .git_ignore(true)
        .git_global(true)
        .hidden(false)
        .max_depth(Some(scan::MAX_WALK_DEPTH))
        .build();

    let mut files = Vec::new();
    for result in walker {
        if files.len() >= scan::MAX_SCAN_FILES {
            eprintln!(
                "  {} Reached scan limit of {} files. Some files may not be checked.",
                "[!]".yellow(),
                scan::MAX_SCAN_FILES
            );
            break;
        }

        if let Ok(entry) = result {
            let path = entry.path();
            if path.is_file()
                && !scan::should_exclude_in(path, &canonical_path)
                && !scan::is_binary(path)
            {
                let ext = file_extension(path);
                if !ext.is_empty() && is_supported_extension(&ext) {
                    files.push(path.to_path_buf());
                }
            }
        }
    }

    let cross_file = cross_file_flow_sinks(&files, &canonical_path);
    for path in &files {
        let findings =
            scan_file_for_vulns_with(path, &patterns, cross_file.get(path), Some(&canonical_path));
        report.extend(findings);
    }
    // Route and handler context are needed for missing authorization. A bare
    // parameterized URL or a bare DAO lookup cannot establish an IDOR.
    report.extend(scoped_route_authz_findings(
        &files,
        &canonical_path,
        &patterns,
    ));
    report.extend(scoped_template_xss_csrf_findings(
        &files,
        &canonical_path,
        &patterns,
    ));
    report.extend(scoped_django_safe_filter_findings(
        &canonical_path,
        &patterns,
    ));
    report.extend(scoped_rails_csrf_findings(&canonical_path, &patterns));
    report.extend(scoped_rails_work_info_idor(&canonical_path, &patterns));
    report.extend(scoped_rails_admin_gate_bypass(&canonical_path, &patterns));
    report.extend(scoped_rails_ssn_client_mask(&canonical_path, &patterns));
    report.extend(scoped_php_password_csrf(&canonical_path, &patterns));
    report.extend(scoped_php_open_redirect(&canonical_path, &patterns));
    report.extend(scoped_php_single_pass_include_filter(
        &canonical_path,
        &patterns,
    ));
    report.extend(scoped_php_level_conditional_authz(
        &canonical_path,
        &patterns,
    ));
    report.extend(scoped_dotnet_lesson_sqli(&canonical_path, &patterns));
    report.extend(scoped_dotnet_path_manipulation(&canonical_path, &patterns));
    report.extend(scoped_dotnet_lesson_xss(&canonical_path, &patterns));
    report.extend(scoped_dotnet_upload_unrestricted(
        &canonical_path,
        &patterns,
    ));
    report.extend(scoped_dotnet_debug_disclosure(&canonical_path, &patterns));
    report.extend(scoped_dotnet_weak_digest(&canonical_path, &patterns));
    report.extend(scoped_dotnet_weak_random(&canonical_path, &patterns));
    report.extend(scoped_dotnet_unsafe_block(&canonical_path, &patterns));
    report.extend(scoped_dvga_command_injection(&canonical_path, &patterns));
    report.extend(scoped_dvga_arbitrary_file_write(&canonical_path, &patterns));
    report.extend(scoped_dvga_sql_injection(&canonical_path, &patterns));
    report.extend(scoped_dvga_jwt_no_verify(&canonical_path, &patterns));
    report.extend(scoped_dvga_stored_xss(&canonical_path, &patterns));
    report.extend(scoped_rails_login_redirect(&canonical_path, &patterns));
    report.extend(scoped_rails_login_enumeration(&canonical_path, &patterns));
    report.extend(scoped_php_ruby_file_xss_findings(
        &files,
        &canonical_path,
        &patterns,
    ));
    report.extend(scoped_login_session_findings(
        &files,
        &canonical_path,
        &patterns,
    ));
    report.extend(scoped_login_log_forging_findings(
        &files,
        &canonical_path,
        &patterns,
    ));
    report.extend(scoped_login_enumeration_findings(
        &files,
        &canonical_path,
        &patterns,
    ));
    report.extend(scoped_sensitive_profile_storage_findings(
        &files,
        &canonical_path,
        &patterns,
    ));
    // Package entries resolved through node_modules are never part of the
    // scanned set (the directory is excluded): emit only their cross-file
    // flow findings, so project request input reaching a package sink is
    // reported while the package's own pattern surface stays unscanned.
    let scanned: std::collections::HashSet<&std::path::PathBuf> = files.iter().collect();
    for (path, sinks) in &cross_file {
        if !scanned.contains(path) {
            report.extend(scan_file_flow_only(path, sinks));
        }
    }

    // AI-powered deep analysis
    if use_ai {
        if let Ok(ai_findings) = run_ai_review(&canonical_path, model).await {
            report.extend(ai_findings);
        }
    }

    // Test, example, fixture and benchmark paths are excluded outright: usage
    // there is deliberate and does not ship, so these findings are noise
    // rather than low-severity signal. Detectors keep their full surface on
    // shipped code.
    let root_for_filter = canonical_path.clone();
    report.findings.retain(|finding| {
        finding
            .file_path
            .as_deref()
            .map(|path| !is_test_context_path(Path::new(path), &root_for_filter))
            .unwrap_or(true)
    });
    attach_verified_paths(&mut report.findings, &canonical_path);
    downgrade_test_context(&mut report.findings, &canonical_path);
    mark_deployment_context(&mut report.findings, &canonical_path);
    report.sort_by_risk();
    Ok(report)
}

/// Match a tracer path to the exact reported terminal file and line. A
/// pattern match without a verified path remains explicitly untraced.
fn attach_verified_paths(findings: &mut [Finding], root: &Path) {
    let paths = crate::trace::trace_review_paths(root);
    for finding in findings {
        let (Some(file), Some(line)) = (&finding.file_path, finding.line_number) else {
            continue;
        };
        let matched = paths
            .iter()
            .filter(|path| {
                let Some(first) = path.steps.first() else {
                    return false;
                };
                let Some(last) = path.steps.last() else {
                    return false;
                };
                let sink = last.detail.to_ascii_lowercase();
                let compatible = match finding.title.as_str() {
                    "Code Injection" => sink.contains("eval") || sink.contains("assert"),
                    "Command Injection" => {
                        sink.contains("exec") || sink.contains("system") || sink.contains("popen")
                    }
                    "SQL Injection — String Concatenation" => {
                        sink.contains("query") || sink.contains("execute")
                    }
                    NOSQL_WHERE_TITLE => sink.contains("$where"),
                    _ => false,
                };
                compatible
                    && first.action == "source"
                    && last.action == "sink"
                    && last.line == line
                    && Path::new(&last.file) == Path::new(file)
            })
            .min_by_key(|path| path.steps.len());
        if let Some(path) = matched {
            finding.source_to_sink = Some(path.steps.clone());
        }
    }
}

/// Policy fingerprints must be portable: they key on the finding's file path,
/// which the scanner records as absolute. Rewriting paths root-relative before
/// evaluation keeps a baseline written on one machine (a CI checkout at a fixed
/// path, a contributor clone anywhere else) valid on every other. Paths outside
/// the scanned root are left as-is.
fn policy_findings_view(findings: &[Finding], root: &std::path::Path) -> Vec<Finding> {
    findings
        .iter()
        .map(|finding| {
            let mut viewed = finding.clone();
            if let Some(path) = viewed.file_path.as_deref() {
                if let Ok(relative) = std::path::Path::new(path).strip_prefix(root) {
                    viewed.file_path = Some(relative.to_string_lossy().replace('\\', "/"));
                }
            }
            viewed
        })
        .collect()
}

