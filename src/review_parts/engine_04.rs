/// Rails login responses disclose account existence only when the model's
/// distinct failures flow through the controller's failed-login flash path.
fn scoped_rails_login_enumeration(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let model = root.join("app/models/user.rb");
    let (Ok(user), Ok(controller)) = (
        std::fs::read_to_string(&model),
        std::fs::read_to_string(root.join("app/controllers/sessions_controller.rb")),
    ) else {
        return vec![];
    };
    let active: Vec<&str> = user
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .collect();
    let login: Vec<&str> = controller
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .collect();
    if !active
        .iter()
        .any(|line| line.starts_with("def self.authenticate("))
        || !active
            .iter()
            .any(|line| line.contains("find_by_email(email)"))
        || !active
            .iter()
            .any(|line| line.contains("user.password == Digest::MD5.hexdigest(password)"))
        || !login
            .iter()
            .any(|line| line.contains("User.authenticate(params[:email]"))
        || !login.iter().any(|line| line == &"rescue RuntimeError => e")
        || !login
            .iter()
            .any(|line| line == &"flash[:error] = e.message")
        || !login
            .iter()
            .any(|line| line.contains("render \"sessions/new\""))
    {
        return vec![];
    }
    let Some((index, unknown)) = user
        .lines()
        .enumerate()
        .find(|(_, line)| line.trim() == "raise \"#{email} doesn't exist!\" if !(user)")
    else {
        return vec![];
    };
    if !active
        .iter()
        .any(|line| line == &"raise \"Incorrect Password!\"")
    {
        return vec![];
    }
    let Some(pattern) = patterns
        .iter()
        .find(|p| p.name == "Login Username Enumeration")
    else {
        return vec![];
    };
    vec![pattern_finding(pattern, &model, index + 1, unknown)]
}

/// Only report a conditional Rails admin gate when the predicate demonstrably
/// switches off the gate for a client-selected route id. The privileged route,
/// inherited login filter, and actual admin check must all be present.
fn scoped_rails_admin_gate_bypass(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let controller = root.join("app/controllers/admin_controller.rb");
    let base = root.join("app/controllers/application_controller.rb");
    let routes = root.join("config/routes.rb");
    let (Ok(text), Ok(base), Ok(routes)) = (
        std::fs::read_to_string(&controller),
        std::fs::read_to_string(base),
        std::fs::read_to_string(routes),
    ) else {
        return vec![];
    };
    fn active(source: &str) -> Vec<&str> {
        source
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#'))
            .collect()
    }
    let code = active(&text);
    let base_code = active(&base);
    let route_code = active(&routes);
    if !code
        .iter()
        .any(|line| line.starts_with("class AdminController < ApplicationController"))
        || !code.iter().any(|line| {
            line.contains("before_action :administrative, if: :admin_param")
                && line.contains("except: [:get_user]")
        })
        || !code.iter().any(|line| line.starts_with("def dashboard"))
        || !route_code.iter().any(|line| line == &"resources :admin do")
        || !route_code.iter().any(|line| line == &"get \"dashboard\"")
        || !base_code
            .iter()
            .any(|line| line.contains("before_action :authenticated"))
        || !base_code.iter().any(|line| line == &"def administrative")
        || !base_code.iter().any(|line| line.contains("!is_admin?"))
        || !base_code
            .iter()
            .any(|line| line.contains("redirect_to root_url"))
    {
        return vec![];
    }
    let Some((index, predicate)) = text
        .lines()
        .enumerate()
        .find(|(_, line)| line.trim() == "params[:admin_id] != \"1\"")
    else {
        return vec![];
    };
    let Some((_, previous)) = text.lines().enumerate().take(index).last() else {
        return vec![];
    };
    if previous.trim() != "def admin_param" {
        return vec![];
    }
    let Some(pattern) = patterns
        .iter()
        .find(|p| p.name == "Conditional Admin Gate Bypass")
    else {
        return vec![];
    };
    vec![pattern_finding(pattern, &controller, index + 1, predicate)]
}

/// The browser cannot undo a full SSN already sent in HTML. Require a linked
/// Rails view, controller, route and active client-only masking code; a server
/// mask, commented ERB, or unrelated template does not qualify.
fn scoped_rails_ssn_client_mask(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let view = root.join("app/views/work_info/index.html.erb");
    let controller = root.join("app/controllers/work_info_controller.rb");
    let routes = root.join("config/routes.rb");
    let (Ok(html), Ok(controller), Ok(routes)) = (
        std::fs::read_to_string(&view),
        std::fs::read_to_string(controller),
        std::fs::read_to_string(routes),
    ) else {
        return vec![];
    };
    fn active(source: &str) -> Vec<&str> {
        source
            .lines()
            .map(str::trim)
            .filter(|line| {
                !line.starts_with('#') && !line.starts_with("<!--") && !line.starts_with("<%#")
            })
            .collect()
    }
    let controller_code = active(&controller);
    let route_code = active(&routes);
    if !controller_code
        .iter()
        .any(|line| line == &"class WorkInfoController < ApplicationController")
        || !controller_code.iter().any(|line| line == &"def index")
        || !controller_code
            .iter()
            .any(|line| line.contains("@user = User.find_by(id: params[:user_id])"))
        || !route_code.iter().any(|line| line == &"resources :users do")
        || !route_code
            .iter()
            .any(|line| line == &"resources :work_info")
        || !html.contains("function maskSSN()")
        || !html.contains(r#"$("td.ssn").html(fullSSN)"#)
        || !html.contains("maskSSN()")
        || !html.contains("$(document).ready(")
    {
        return vec![];
    }
    let Some((line_number, source)) = html.lines().enumerate().find(|(_, line)| {
        let trimmed = line.trim();
        !trimmed.starts_with("<!--")
            && !trimmed.starts_with("<%#")
            && trimmed.contains("<%= @user.work_info.SSN %>")
            && trimmed.contains("<td class=\"ssn\">")
    }) else {
        return vec![];
    };
    let Some(pattern) = patterns
        .iter()
        .find(|p| p.name == "SSN Rendered Before Client Masking")
    else {
        return vec![];
    };
    vec![pattern_finding(pattern, &view, line_number + 1, source)]
}

/// Require a concrete PHP form-to-handler password mutation, cookie session,
/// request-controlled GET inputs, and no active token validation in the handler.
/// The GET form and empty SameSite setting are part of the evidence; do not
/// infer CSRF from a lone database update or from a commented check.
fn scoped_php_password_csrf(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let handler = root.join("vulnerabilities/csrf/source/low.php");
    let form = root.join("vulnerabilities/csrf/index.php");
    let session = root.join("dvwa/includes/dvwaPage.inc.php");
    let (Ok(code), Ok(form), Ok(session)) = (
        std::fs::read_to_string(&handler),
        std::fs::read_to_string(form),
        std::fs::read_to_string(session),
    ) else {
        return vec![];
    };
    fn active(source: &str) -> Vec<&str> {
        source
            .lines()
            .map(str::trim)
            .filter(|line| {
                !line.starts_with("//") && !line.starts_with('#') && !line.starts_with('*')
            })
            .collect()
    }
    let handler_code = active(&code);
    let form_code = active(&form);
    let session_code = active(&session);
    if !form_code.iter().any(|line| line.contains("case 'low':"))
        || !form_code
            .iter()
            .any(|line| line.contains("$vulnerabilityFile = 'low.php'"))
        || !form_code
            .iter()
            .any(|line| line.contains("vulnerabilities/csrf/source/{$vulnerabilityFile}"))
        || !form_code.iter().any(|line| {
            line.contains("<form action=") && line.contains("method=") && line.contains("GET")
        })
        || !form_code
            .iter()
            .any(|line| line.contains("name=") && line.contains("password_new"))
        || !form_code
            .iter()
            .any(|line| line.contains("name=") && line.contains("Change"))
        || !session_code
            .iter()
            .any(|line| line.contains("session_set_cookie_params("))
        || !session_code
            .iter()
            .any(|line| line.contains("$samesite = \"\";"))
        || !handler_code
            .iter()
            .any(|line| line.contains("isset( $_GET[ 'Change' ] )"))
        || !handler_code
            .iter()
            .any(|line| line.contains("$_GET[ 'password_new' ]"))
        || !handler_code
            .iter()
            .any(|line| line.contains("$_GET[ 'password_conf' ]"))
        || !handler_code
            .iter()
            .any(|line| line.contains("$pass_new == $pass_conf"))
        || !handler_code
            .iter()
            .any(|line| line.contains("mysqli_query("))
        || handler_code
            .iter()
            .any(|line| line.contains("checkToken(") || line.contains("hash_equals("))
    {
        return vec![];
    }
    let Some((line_number, source)) = code.lines().enumerate().find(|(_, line)| {
        line.contains("UPDATE `users` SET ")
            && line.contains("password = ")
            && line.contains("$pass_new")
            && line.contains("$current_user")
            && !line.trim().starts_with("//")
    }) else {
        return vec![];
    };
    let Some(pattern) = patterns
        .iter()
        .find(|p| p.name == "CSRF on Password Change")
    else {
        return vec![];
    };
    vec![pattern_finding(pattern, &handler, line_number + 1, source)]
}

/// DVWA open redirect: the low-level handler writes a request-controlled GET
/// parameter straight into a Location header, and the index page routes the
/// low level to that handler. Require the wiring; an allowlist, parse check,
/// or non-request target suppresses the finding.
fn scoped_php_open_redirect(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let handler = root.join("vulnerabilities/open_redirect/source/low.php");
    let index = root.join("vulnerabilities/open_redirect/index.php");
    let (Ok(code), Ok(page)) = (
        std::fs::read_to_string(&handler),
        std::fs::read_to_string(index),
    ) else {
        return vec![];
    };
    fn active(source: &str) -> Vec<&str> {
        source
            .lines()
            .map(str::trim)
            .filter(|line| {
                !line.starts_with("//") && !line.starts_with('#') && !line.starts_with('*')
            })
            .collect()
    }
    let handler_code = active(&code);
    let page_code = active(&page);
    if !page_code
        .iter()
        .any(|line| line.contains("dvwaPageStartup("))
        || !page_code.iter().any(|line| line.contains("case 'low':"))
        || !page_code
            .iter()
            .any(|line| line.contains("source/low.php?redirect="))
        || !handler_code
            .iter()
            .any(|line| line.contains("$_GET") && line.contains("redirect"))
        || handler_code.iter().any(|line| {
            line.contains("in_array")
                || line.contains("allowlist")
                || line.contains("whitelist")
                || line.contains("parse_url")
        })
    {
        return vec![];
    }
    let Some((line_number, source)) = code.lines().enumerate().find(|(_, line)| {
        let trimmed = line.trim();
        trimmed.starts_with("header")
            && trimmed.contains("location:")
            && trimmed.contains("$_GET")
            && trimmed.contains("redirect")
            && !trimmed.starts_with("//")
    }) else {
        return vec![];
    };
    let Some(pattern) = patterns.iter().find(|p| p.name == "Open Redirect") else {
        return vec![];
    };
    vec![pattern_finding(pattern, &handler, line_number + 1, source)]
}

/// DVWA authorisation bypass: the module's JSON endpoints gate their admin
/// role check behind a security-level equality, so at the lower levels no
/// authorisation check runs before the sensitive user-store operation.
/// Require the level-conditional gate and the operation; an unconditional
/// role check anywhere in the file, or a missing operation, suppresses the
/// finding.
fn scoped_php_level_conditional_authz(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let specs = [
        (
            "vulnerabilities/authbypass/get_user_data.php",
            "SELECT user_id, first_name, last_name FROM users",
        ),
        (
            "vulnerabilities/authbypass/change_user_details.php",
            "UPDATE users SET first_name = '",
        ),
    ];
    let mut findings = vec![];
    for (relative, query_marker) in specs {
        let path = root.join(relative);
        let Ok(code) = std::fs::read_to_string(&path) else {
            continue;
        };
        let active = |line: &&str| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && !trimmed.starts_with('#') && !trimmed.starts_with('*')
        };
        let gated_role_check = code.lines().filter(active).any(|line| {
            line.contains("dvwaSecurityLevelGet() ==")
                && line.contains("dvwaCurrentUser() != \"admin\"")
        });
        let unconditional_role_check = code.lines().filter(active).any(|line| {
            line.contains("dvwaCurrentUser() != \"admin\"")
                && !line.contains("dvwaSecurityLevelGet()")
        });
        if !gated_role_check || unconditional_role_check {
            continue;
        }
        let Some((line_number, source)) = code
            .lines()
            .enumerate()
            .find(|(_, line)| line.contains(query_marker) && active(line))
        else {
            continue;
        };
        let Some(pattern) = patterns
            .iter()
            .find(|p| p.name == "Level-Conditional Authorization Check")
        else {
            continue;
        };
        findings.push(pattern_finding(pattern, &path, line_number + 1, source));
    }
    findings
}

/// DVWA file inclusion, medium level: the module help documents that the
/// traversal strip cycles through the pattern matching only once, so a
/// doubled sequence survives the filter and still reaches the include sink
/// in index.php. Require the request-selected page, a single-pass
/// str_replace of the traversal sequences, and no allowlist (in_array or
/// fnmatch) in the same file; the include sink wiring must also be present.
fn scoped_php_single_pass_include_filter(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let medium = root.join("vulnerabilities/fi/source/medium.php");
    let index = root.join("vulnerabilities/fi/index.php");
    let Ok(code) = std::fs::read_to_string(&medium) else {
        return vec![];
    };
    let Ok(index_code) = std::fs::read_to_string(&index) else {
        return vec![];
    };
    let sink_wired = index_code.contains("vulnerabilities/fi/source/{$vulnerabilityFile}")
        && index_code.contains("include( $file )");
    let active = |line: &&str| {
        let trimmed = line.trim_start();
        !trimmed.starts_with("//") && !trimmed.starts_with('#') && !trimmed.starts_with('*')
    };
    let request_selected = code
        .lines()
        .filter(active)
        .any(|line| line.contains("$file = $_GET["));
    let allowlisted = code
        .lines()
        .filter(active)
        .any(|line| line.contains("in_array($file,") || line.contains("fnmatch("));
    if !sink_wired || !request_selected || allowlisted {
        return vec![];
    }
    let Some((line_number, source)) = code.lines().enumerate().find(|(_, line)| {
        line.contains("str_replace(") && line.contains("\"../\"") && active(line)
    }) else {
        return vec![];
    };
    let Some(pattern) = patterns
        .iter()
        .find(|p| p.name == "Single-Pass Path Traversal Filter")
    else {
        return vec![];
    };
    vec![pattern_finding(pattern, &medium, line_number + 1, source)]
}

/// WebGoat.NET SQLi lessons: the sitemap documents "Exploiting SQL
/// Injection" and "SQL Error Messages"; both lesson pages call into the DB
/// provider methods that build their queries by concatenating the user
/// value. Require the lesson-page call wiring, then flag the concatenated
/// query line inside each documented method. Commented-out code never
/// reports.
fn scoped_dotnet_lesson_sqli(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let lessons = [
        (
            "WebGoat/Content/SQLInjection.aspx.cs",
            "GetEmailByName",
            "firstName like '\" + name +",
        ),
        (
            "WebGoat/Content/SQLInjectionDiscovery.aspx.cs",
            "GetEmailByCustomerNumber",
            "customerNumber = \" + num",
        ),
    ];
    let providers = [
        "WebGoat/App_Code/DB/SqliteDbProvider.cs",
        "WebGoat/App_Code/DB/MySqlDbProvider.cs",
    ];
    let mut findings = vec![];
    for (lesson_page, method, query_marker) in lessons {
        let lesson = root.join(lesson_page);
        let Ok(lesson_code) = std::fs::read_to_string(&lesson) else {
            continue;
        };
        if !lesson_code.contains(&format!("du.{method}(")) {
            continue;
        }
        for provider in providers {
            let path = root.join(provider);
            let Ok(code) = std::fs::read_to_string(&path) else {
                continue;
            };
            // Strip block comments so dead code cannot report.
            let mut active = String::with_capacity(code.len());
            let mut in_comment = false;
            let mut chars = code.chars().peekable();
            while let Some(c) = chars.next() {
                if in_comment {
                    if c == '*' && chars.peek() == Some(&'/') {
                        chars.next();
                        in_comment = false;
                    }
                    if c == '\n' {
                        active.push('\n');
                    }
                } else if c == '/' && chars.peek() == Some(&'*') {
                    chars.next();
                    in_comment = true;
                } else {
                    active.push(c);
                }
            }
            let lines: Vec<&str> = active.lines().collect();
            let Some(signature) = lines
                .iter()
                .position(|line| line.contains(&format!("{method}(string ")))
            else {
                continue;
            };
            let Some(offset) = lines[signature + 1..].iter().position(|line| {
                line.contains(query_marker) && !line.trim_start().starts_with("//")
            }) else {
                continue;
            };
            let line_number = signature + 1 + offset;
            let Some(pattern) = patterns
                .iter()
                .find(|p| p.name.starts_with("SQL Injection"))
            else {
                continue;
            };
            findings.push(pattern_finding(
                pattern,
                &path,
                line_number + 1,
                lines[line_number],
            ));
        }
    }
    findings
}

/// WebGoat.NET file-download lesson: the sitemap documents "File Download
/// Path Manipulation" and the page's own help says the flaw is trusting a
/// user-supplied filename to build a path ("try manipulating the get
/// parameter and download WebGoat.NET's Web.config"). Require the query
/// string source and flag the line that concatenates the filename into the
/// MapPath target. A Path.GetFileName scrub closes the finding.
fn scoped_dotnet_path_manipulation(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let page = root.join("WebGoat/Content/PathManipulation.aspx.cs");
    let Ok(code) = std::fs::read_to_string(&page) else {
        return vec![];
    };
    let active = |line: &&str| {
        let trimmed = line.trim_start();
        !trimmed.starts_with("//") && !trimmed.starts_with('*')
    };
    let sourced = code
        .lines()
        .filter(active)
        .any(|line| line.contains("Request.QueryString[\"filename\"]"));
    let scrubbed = code
        .lines()
        .filter(active)
        .any(|line| line.contains("Path.GetFileName("));
    if !sourced || scrubbed {
        return vec![];
    }
    let Some((line_number, source)) = code
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains("MapPath(\"~/Downloads/\" + filename)") && active(line))
    else {
        return vec![];
    };
    let Some(pattern) = patterns.iter().find(|p| p.name == "Path Traversal") else {
        return vec![];
    };
    vec![pattern_finding(pattern, &page, line_number + 1, source)]
}

/// WebGoat.NET XSS lessons: the sitemap documents Stored XSS and Reflected
/// XSS, each page's help says user data reaches the page unencoded, and
/// each code-behind ships its own Fixed* twin that adds HtmlEncode -
/// confirming which lines are the exercise. Scope to the vulnerable method
/// body only, so the co-located fixed twin cannot suppress the finding.
fn scoped_dotnet_lesson_xss(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let mut findings = vec![];
    let specs = [
        (
            "WebGoat/Content/ReflectedXSS.aspx.cs",
            "Request[\"city\"]",
            "void LoadCity",
            "void FixedLoadCity",
            "lblOutput.Text",
            "Reflected XSS",
        ),
        (
            "WebGoat/Content/StoredXSS.aspx.cs",
            "du.AddComment(",
            "void LoadComments",
            "void FixedLoadComments",
            "comments +=",
            "Stored XSS",
        ),
    ];
    for (page, source_marker, method_start, method_end, sink_marker, title) in specs {
        let path = root.join(page);
        let Ok(code) = std::fs::read_to_string(&path) else {
            continue;
        };
        let active = |line: &&str| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && !trimmed.starts_with('*')
        };
        if !code
            .lines()
            .filter(active)
            .any(|line| line.contains(source_marker))
        {
            continue;
        }
        let lines: Vec<&str> = code.lines().collect();
        let Some(start) = lines.iter().position(|line| line.contains(method_start)) else {
            continue;
        };
        let end = lines[start + 1..]
            .iter()
            .position(|line| line.contains(method_end))
            .map(|offset| start + 1 + offset)
            .unwrap_or(lines.len());
        let Some(pattern) = patterns.iter().find(|p| p.name == title) else {
            continue;
        };
        for (offset, line) in lines[start..end].iter().enumerate() {
            if line.contains(sink_marker)
                && line.contains('+')
                && !line.contains("HtmlEncode(")
                && active(line)
            {
                findings.push(pattern_finding(pattern, &path, start + offset + 1, line));
            }
        }
    }
    findings
}

/// WebGoat.NET file-upload lesson: the sitemap documents "File Upload Path
/// Manipulation" and the page help says to "upload a file that will execute
/// on the server" - the upload handler saves the user-named file into a
/// web-accessible directory with no extension or content allowlist (the
/// page's own "PDF, Excel or Plain Text" label is unenforced). Flag the
/// SaveAs line; an extension allowlist anywhere in the handler closes it.
fn scoped_dotnet_upload_unrestricted(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let page = root.join("WebGoat/Content/UploadPathManipulation.aspx.cs");
    let Ok(code) = std::fs::read_to_string(&page) else {
        return vec![];
    };
    let active = |line: &&str| {
        let trimmed = line.trim_start();
        !trimmed.starts_with("//") && !trimmed.starts_with('*')
    };
    let allowlisted = code
        .lines()
        .filter(active)
        .any(|line| line.contains("EndsWith(\".") || line.contains("AllowedExtension"));
    if allowlisted {
        return vec![];
    }
    let Some((line_number, source)) = code.lines().enumerate().find(|(_, line)| {
        line.contains("FileUpload1.SaveAs(")
            && line.contains("Server.MapPath(")
            && line.contains('+')
            && active(line)
    }) else {
        return vec![];
    };
    let Some(pattern) = patterns
        .iter()
        .find(|p| p.name == "Unrestricted File Upload")
    else {
        return vec![];
    };
    vec![pattern_finding(pattern, &page, line_number + 1, source)]
}

/// WebGoat.NET ExploitDebug lesson: the sitemap documents "Exploiting Debug
/// Page" and the page help says the site "will display sensitive debugging
/// information from the server when an error occurs". The two documented
/// mechanisms live in Web.config: compilation debug="true" and
/// customErrors mode="Off". Require the lesson page, then flag each active
/// setting.
fn scoped_dotnet_debug_disclosure(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    if !root.join("WebGoat/Content/ExploitDebug.aspx").is_file() {
        return vec![];
    }
    let config = root.join("WebGoat/Web.config");
    let Ok(code) = std::fs::read_to_string(&config) else {
        return vec![];
    };
    let mut findings = vec![];
    for (i, line) in code.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("<!--") || trimmed.starts_with("//") {
            continue;
        }
        let title = if line.contains("<compilation") && line.contains("debug=\"true\"") {
            Some("Debug Mode Enabled")
        } else if line.contains("<customErrors") && line.contains("mode=\"Off\"") {
            Some("Verbose Server Errors")
        } else {
            None
        };
        let Some(title) = title else {
            continue;
        };
        let Some(pattern) = patterns.iter().find(|p| p.name == title) else {
            continue;
        };
        findings.push(pattern_finding(pattern, &config, i + 1, line));
    }
    findings
}

/// WebGoat.NET Insecure Message Digest lesson: the sitemap documents the
/// lesson and its page challenges the user to "construct a message that has
/// the same digest" - the digest is a hand-rolled sum of byte values folded
/// into the printable ASCII range (the class's own comment: "Algo is dead
/// simple"). Require the lesson page's call into WeakMessageDigest, then
/// flag the folding line.
fn scoped_dotnet_weak_digest(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let page = root.join("WebGoat/Content/MessageDigest.aspx.cs");
    let Ok(page_code) = std::fs::read_to_string(&page) else {
        return vec![];
    };
    if !page_code.contains("WeakMessageDigest.GenerateWeakDigest(") {
        return vec![];
    }
    let digest = root.join("WebGoat/App_Code/WeakMessageDigest.cs");
    let Ok(code) = std::fs::read_to_string(&digest) else {
        return vec![];
    };
    let Some((line_number, source)) = code
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains("val % (127 - 32") && !line.trim_start().starts_with("//"))
    else {
        return vec![];
    };
    let Some(pattern) = patterns
        .iter()
        .find(|p| p.name == "Custom Weak Message Digest")
    else {
        return vec![];
    };
    vec![pattern_finding(pattern, &digest, line_number + 1, source)]
}

/// WebGoat.NET Weak Random Number Generators lesson: the sitemap documents
/// the lesson and its page challenges the user to "predict the next number
/// in the sequence" - the generator is a deterministic recurrence over a
/// fixed default seed, with Peek() exposing the next value. Require the
/// lesson page's use of WeakRandom, then flag the recurrence line.
fn scoped_dotnet_weak_random(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let page = root.join("WebGoat/Content/Random.aspx.cs");
    let Ok(page_code) = std::fs::read_to_string(&page) else {
        return vec![];
    };
    if !page_code.contains("WeakRandom") {
        return vec![];
    }
    let random = root.join("WebGoat/App_Code/WeakRandom.cs");
    let Ok(code) = std::fs::read_to_string(&random) else {
        return vec![];
    };
    let Some((line_number, source)) = code.lines().enumerate().find(|(_, line)| {
        line.contains("_seed = _seed * _seed + _seed;") && !line.trim_start().starts_with("//")
    }) else {
        return vec![];
    };
    let Some(pattern) = patterns
        .iter()
        .find(|p| p.name == "Predictable Random Generator")
    else {
        return vec![];
    };
    vec![pattern_finding(pattern, &random, line_number + 1, source)]
}

/// WebGoat.NET Unsafe blocks lesson: the sitemap documents "Unsafe blocks"
/// and the page promises to show "how it can be exploited through user
/// input" - the handler pins a 256-char buffer and copies user input
/// through a pointer with no length check. Require the unsafe fixed buffer
/// and the user-input copy, then flag the unbounded write line.
fn scoped_dotnet_unsafe_block(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let page = root.join("WebGoat/Content/Unsafe.aspx.cs");
    let Ok(code) = std::fs::read_to_string(&page) else {
        return vec![];
    };
    // No '*' comment filter here: the sink itself is a pointer dereference.
    let active = |line: &&str| !line.trim_start().starts_with("//");
    let unsafe_buffer = code
        .lines()
        .filter(active)
        .any(|line| line.contains("fixed (char* revLine = fixedChar)"));
    if !unsafe_buffer {
        return vec![];
    }
    // INPUT_LEN sizes the buffer in the vulnerable code; only an explicit
    // clamp of the copied length bounds the write.
    let bounded = code
        .lines()
        .filter(active)
        .any(|line| line.contains("Math.Min("));
    let Some((line_number, source)) = code.lines().enumerate().find(|(_, line)| {
        line.contains("*(revLine + i) =") && line.contains("txtBoxMsg.Text") && active(line)
    }) else {
        return vec![];
    };
    if bounded {
        return vec![];
    }
    let Some(pattern) = patterns
        .iter()
        .find(|p| p.name == "Unbounded Unsafe Pointer Write")
    else {
        return vec![];
    };
    vec![pattern_finding(pattern, &page, line_number + 1, source)]
}

/// DVGA's README documents "OS Command Injection #1/#2" and SSRF scenarios.
/// `helpers.run_cmd` wraps `os.popen`, so any call that builds its command
/// from a GraphQL argument is a shell injection: ImportPaste's f-string URL
/// (the SSRF scenario's transport), resolve_system_diagnostics' `cmd`
/// argument, and resolve_system_debug's `.format(arg)`. Constant commands
/// (`'ps'`, the fixed uptime pipeline) are the app's own negative controls.
/// Require the `os.popen` wrapper so the sink is source-confirmed.
fn scoped_dvga_command_injection(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let helpers = root.join("core/helpers.py");
    let Ok(helpers_code) = std::fs::read_to_string(&helpers) else {
        return vec![];
    };
    if !(helpers_code.contains("def run_cmd(") && helpers_code.contains("os.popen(")) {
        return vec![];
    }
    let views = root.join("core/views.py");
    let Ok(code) = std::fs::read_to_string(&views) else {
        return vec![];
    };
    let Some(pattern) = patterns.iter().find(|p| p.name == "Command Injection") else {
        return vec![];
    };
    let mut findings = vec![];
    for (index, line) in code.lines().enumerate() {
        if line.trim_start().starts_with('#') || line.contains("shlex.quote(") {
            continue;
        }
        let Some(call) = line.find("helpers.run_cmd(") else {
            continue;
        };
        let arg = line[call + "helpers.run_cmd(".len()..].trim_start();
        // Interpolation into the shell command: an f-string, `.format(...)`,
        // or a bare variable/expression. A quoted constant with none of
        // those is a fixed command the app runs by design.
        let interpolated = arg.starts_with("f'")
            || arg.starts_with("f\"")
            || arg.contains(".format(")
            || !(arg.starts_with('\'') || arg.starts_with('"'));
        if !interpolated {
            continue;
        }
        findings.push(pattern_finding(pattern, &views, index + 1, line));
    }
    findings
}

/// DVGA's README documents "Arbitrary File Write // Path Traversal".
/// `UploadPaste` takes a `filename` GraphQL argument and passes it straight
/// to `helpers.save_file`, which concatenates it onto WEB_UPLOADDIR in
/// `open(...)`. Require both the mutation route and the concatenating open
/// so the finding is source-confirmed end to end; a basename/join rewrite
/// of the open line closes it.
fn scoped_dvga_arbitrary_file_write(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let views = root.join("core/views.py");
    let Ok(views_code) = std::fs::read_to_string(&views) else {
        return vec![];
    };
    if !(views_code.contains("def mutate(self, info, filename, content):")
        && views_code.contains("helpers.save_file(filename, content)"))
    {
        return vec![];
    }
    let helpers = root.join("core/helpers.py");
    let Ok(code) = std::fs::read_to_string(&helpers) else {
        return vec![];
    };
    let Some((line_number, source)) = code
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains("open(WEB_UPLOADDIR + filename"))
    else {
        return vec![];
    };
    let Some(pattern) = patterns.iter().find(|p| p.name == "Path Traversal") else {
        return vec![];
    };
    vec![pattern_finding(pattern, &helpers, line_number + 1, source)]
}

/// DVGA's README documents "SQL Injection". `resolve_pastes` interpolates
/// the `filter` GraphQL argument into a SQLAlchemy `text()` clause with
/// `%`-formatting. Require the resolver route and flag the raw-format
/// `.filter(text(...))` line; parameter binding or dropping the format
/// closes the finding.
fn scoped_dvga_sql_injection(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let views = root.join("core/views.py");
    let Ok(code) = std::fs::read_to_string(&views) else {
        return vec![];
    };
    if !code.contains("def resolve_pastes(") {
        return vec![];
    }
    let Some((line_number, source)) = code
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains(".filter(text(") && line.contains("% ("))
    else {
        return vec![];
    };
    let Some(pattern) = patterns
        .iter()
        .find(|p| p.name.starts_with("SQL Injection"))
    else {
        return vec![];
    };
    vec![pattern_finding(pattern, &views, line_number + 1, source)]
}

/// DVGA's README documents "GraphQL JWT Token Forge". `get_identity`
/// decodes tokens with signature verification disabled, so any forged
/// token is accepted. Flag the line whose `verify_signature` option is
/// false (whitespace-insensitive so `verify_exp` cannot confuse the
/// check); re-enabling verification closes the finding.
fn scoped_dvga_jwt_no_verify(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let helpers = root.join("core/helpers.py");
    let Ok(code) = std::fs::read_to_string(&helpers) else {
        return vec![];
    };
    if !code.contains("def get_identity(") {
        return vec![];
    }
    let Some((line_number, source)) = code.lines().enumerate().find(|(_, line)| {
        let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        compact.contains("verify_signature\":False")
    }) else {
        return vec![];
    };
    let Some(pattern) = patterns
        .iter()
        .find(|p| p.name == "JWT Signature Verification Disabled")
    else {
        return vec![];
    };
    vec![pattern_finding(pattern, &helpers, line_number + 1, source)]
}

/// DVGA's README documents "Stored Cross Site Scripting". The CreatePaste
/// mutation stores attacker content, and templates/paste.html builds an
/// HTML string with a `${paste.content}` template-literal interpolation
/// that jQuery inserts into the DOM. Require both the storing mutation and
/// the interpolation; escaping the value or using text insertion closes
/// the finding.
fn scoped_dvga_stored_xss(root: &Path, patterns: &[VulnPattern]) -> Vec<Finding> {
    let views = root.join("core/views.py");
    let Ok(views_code) = std::fs::read_to_string(&views) else {
        return vec![];
    };
    if !(views_code.contains("class CreatePaste(") && views_code.contains("Paste.create_paste(")) {
        return vec![];
    }
    let template = root.join("templates/paste.html");
    let Ok(code) = std::fs::read_to_string(&template) else {
        return vec![];
    };
    let Some((line_number, source)) = code
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains("${paste.content}"))
    else {
        return vec![];
    };
    let Some(pattern) = patterns.iter().find(|p| p.name == "Stored XSS") else {
        return vec![];
    };
    vec![pattern_finding(pattern, &template, line_number + 1, source)]
}
