#[tokio::test]
    async fn ruby_php_pilot_paths_and_controls_at_exact_lines() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-ruby-php-{nonce}"));
        for relative in [
            "app/controllers",
            "app/models",
            "vulnerabilities/sqli/source",
            "vulnerabilities/exec/source",
            "vulnerabilities/exec/test",
        ] {
            fs::create_dir_all(root.join(relative)).expect("mkdir");
        }
        let rails = root.join("app/controllers/users_controller.rb");
        fs::write(
            &rails,
            [
                "# header",
                "# no query",
                "user = User.where(\"id = '#{params[:user][:id]}'\")[0]",
            ]
            .join("\n"),
        )
        .expect("ruby");
        let benefit = root.join("app/models/benefits.rb");
        fs::write(
            &benefit,
            "system(\"cp #{full_file_name} #{file.original_filename}\")",
        )
        .expect("benefit");
        let sqli = root.join("vulnerabilities/sqli/source/low.php");
        fs::write(
            &sqli,
            [
                "<?php",
                "$id = $_GET['id'];",
                "$query = \"SELECT * FROM users WHERE id = '$id'\";",
                "mysqli_query($db, $query);",
            ]
            .join("\n"),
        )
        .expect("php");
        let exec = root.join("vulnerabilities/exec/source/low.php");
        fs::write(
            &exec,
            [
                "<?php",
                "$target = $_REQUEST['ip'];",
                "$cmd = shell_exec('ping ' . $target);",
            ]
            .join("\n"),
        )
        .expect("exec");
        let impossible = root.join("vulnerabilities/exec/source/impossible.php");
        fs::write(&impossible, ["<?php", "$target = $_REQUEST['ip'];", "$octet = explode('.', $target);", "if (is_numeric( $octet[0] ) && is_numeric( $octet[1] ) && is_numeric( $octet[2] ) && is_numeric( $octet[3] ) && sizeof( $octet ) == 4) {", "$target = $octet[0] . $octet[1] . $octet[2] . $octet[3];", "$cmd = shell_exec('ping ' . $target);", "}"].join("\n")).expect("impossible");
        let fixture = root.join("vulnerabilities/exec/test/demo.php");
        fs::write(
            &fixture,
            [
                "$target = $_REQUEST['ip'];",
                "$cmd = shell_exec('ping ' . $target);",
            ]
            .join("\n"),
        )
        .expect("fixture");
        let report = collect_review_findings(&root, false, None)
            .await
            .expect("scan");
        let keys: std::collections::HashSet<(String, String, usize)> = report
            .findings
            .iter()
            .filter_map(|f| Some((f.title.clone(), f.file_path.clone()?, f.line_number?)))
            .collect();
        for (title, path, line) in [
            ("SQL Injection — String Concatenation", &rails, 3),
            ("Command Injection", &benefit, 1),
            ("SQL Injection — String Concatenation", &sqli, 3),
            ("Command Injection", &exec, 3),
        ] {
            assert!(
                keys.contains(&(title.to_string(), path.to_string_lossy().into_owned(), line)),
                "missing {title} at {}:{line}",
                path.display()
            );
        }
        assert!(!keys.iter().any(|(title, path, _)| (title
            == "SQL Injection — String Concatenation"
            || title == "Command Injection")
            && (path == &impossible.to_string_lossy() || path == &fixture.to_string_lossy())));
        fs::remove_dir_all(root).expect("cleanup");
    }

    const IDOR: &str = "Insecure Direct Object Reference (IDOR)";

    const MISSING_ADMIN: &str = "Missing Privileged Route Authorization";

    #[test]
    fn login_session_fixation_requires_active_cookie_session_and_no_regeneration() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-login-session-{nonce}"));
        fs::create_dir_all(root.join("app/routes")).unwrap();
        let server = root.join("server.js");
        let handler = root.join("app/routes/session.js");
        fs::write(&server, "app.use(session({ cookie: { httpOnly: true } }));").unwrap();
        let vulnerable = "this.handleLoginRequest = (req, res) => {\n  userDAO.validateLogin(userName, password, (err, user) => {\n    // req.session.regenerate(() => {});\n    req.session.userId = user._id;\n    return res.redirect('/dashboard');\n  });\n};\nthis.displayLogoutPage = () => {};";
        fs::write(&handler, vulnerable).unwrap();
        let files = vec![server.clone(), handler.clone()];
        let patterns = build_vuln_patterns();
        let check = || scoped_login_session_findings(&files, &root, &patterns);
        let found = check();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line_number, Some(4));
        assert_eq!(found[0].title, "Session Fixation on Login");
        fs::write(
            &handler,
            vulnerable.replace(
                "    req.session.userId = user._id;",
                "    req.session.regenerate(() => {\n      req.session.userId = user._id;\n    });",
            ),
        )
        .unwrap();
        assert!(check().is_empty(), "active regenerate must guard login");
        fs::write(&handler, vulnerable).unwrap();
        fs::write(
            &server,
            "// app.use(session({}));\napp.use(statelessAuth());",
        )
        .unwrap();
        assert!(
            check().is_empty(),
            "stateless app has no cookie-session finding"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn login_log_forging_requires_request_source_and_unsanitized_sink() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-login-log-{nonce}"));
        fs::create_dir_all(root.join("app/routes")).unwrap();
        let handler = root.join("app/routes/session.js");
        let raw = "this.handleLoginRequest = (req, res) => {\n  const { userName, password } = req.body;\n  userDAO.validateLogin(userName, password, () => {\n    // console.log('safe', userName.replace(/(\\r\\n|\\r|\\n)/g, '_'));\n    console.log('invalid login', userName);\n  });\n};\nthis.displayLogoutPage = () => {};";
        fs::write(&handler, raw).unwrap();
        let patterns = build_vuln_patterns();
        let check =
            || scoped_login_log_forging_findings(std::slice::from_ref(&handler), &root, &patterns);
        let found = check();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].title, "Log Forging from Login Input");
        assert_eq!(found[0].line_number, Some(5));
        fs::write(
            &handler,
            raw.replace(
                "console.log('invalid login', userName);",
                "console.log('invalid login', userName.replace(/(\\r\\n|\\r|\\n)/g, '_')); ",
            ),
        )
        .unwrap();
        assert!(check().is_empty(), "sanitized value is not reported");
        fs::write(
            &handler,
            raw.replace(
                "console.log('invalid login', userName);",
                "console.log('invalid login');",
            ),
        )
        .unwrap();
        assert!(check().is_empty(), "constant log is not reported");
        fs::write(&handler, raw.replace("= req.body", "= fixture")).unwrap();
        assert!(check().is_empty(), "non-request input is not reported");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn login_enumeration_requires_distinct_public_errors() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-login-enumeration-{nonce}"));
        fs::create_dir_all(root.join("app/routes")).unwrap();
        let handler = root.join("app/routes/session.js");
        let vulnerable = "this.handleLoginRequest = (req, res) => {\n  userDAO.validateLogin(userName, password, (err, user) => {\n    const missingError = 'Invalid username';\n    const wrongError = 'Invalid password';\n    const genericError = 'Invalid username or password';\n    if (err.noSuchUser) {\n      // loginError: genericError,\n      return res.render('login', { loginError: missingError });\n    } else if (err.invalidPassword) {\n      return res.render('login', { loginError: wrongError });\n    }\n  });\n};\nthis.displayLogoutPage = () => {};";
        fs::write(&handler, vulnerable).unwrap();
        let patterns = build_vuln_patterns();
        let check =
            || scoped_login_enumeration_findings(std::slice::from_ref(&handler), &root, &patterns);
        let found = check();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].title, "Login Username Enumeration");
        assert_eq!(found[0].line_number, Some(8));
        fs::write(
            &handler,
            vulnerable
                .replace("loginError: missingError", "loginError: genericError")
                .replace("loginError: wrongError", "loginError: genericError"),
        )
        .unwrap();
        assert!(check().is_empty(), "same public error stops enumeration");
        fs::write(
            &handler,
            vulnerable
                .replace("loginError: wrongError", "loginError: genericError")
                .replace("loginError: missingError", "loginError: genericError"),
        )
        .unwrap();
        assert!(check().is_empty());
        fs::write(
            &handler,
            vulnerable.replace("err.noSuchUser", "err.otherIssue"),
        )
        .unwrap();
        assert!(
            check().is_empty(),
            "only login identity branches are relevant"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sensitive_profile_storage_requires_raw_fields_and_persistent_sink() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-profile-storage-{nonce}"));
        fs::create_dir_all(root.join("app/data")).unwrap();
        let path = root.join("app/data/profile-dao.js");
        let raw = "this.updateUser = (userId, firstName, lastName, ssn, dob, address, bankAcc, bankRouting, callback) => {\n  const user = {};\n  user.bankAcc = bankAcc;\n  user.ssn = ssn;\n  user.dob = dob;\n  // user.ssn = encrypt(ssn);\n  users.update({_id: userId}, {$set: user}, callback);\n};\nthis.getByUserId = () => {};";
        fs::write(&path, raw).unwrap();
        let patterns = build_vuln_patterns();
        let check = || {
            scoped_sensitive_profile_storage_findings(std::slice::from_ref(&path), &root, &patterns)
        };
        let found = check();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line_number, Some(4));
        fs::write(
            &path,
            raw.replace(
                "  // user.ssn = encrypt(ssn);",
                "  user.ssn = encrypt(ssn);",
            ),
        )
        .unwrap();
        assert!(
            check().is_empty(),
            "active encryption must suppress the group"
        );
        fs::write(&path, raw.replace("$set: user", "$set: anotherDocument")).unwrap();
        assert!(check().is_empty(), "no persistence of this document");
        fs::write(
            &path,
            raw.replace("user.bankAcc = bankAcc;", "user.bankAcc = mask(bankAcc);")
                .replace("user.dob = dob;", "user.dob = format(dob);"),
        )
        .unwrap();
        assert!(check().is_empty(), "one raw field is insufficient");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scoped_xss_csrf_requires_linked_sources_and_active_guards() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-web-context-{nonce}"));
        let fixture = [
            ("server.js", r#"app.use(session({ cookie: {} }));
/* app.use(csrf()); */
app.engine('.html', consolidate.swig);
swig.setDefaults({ autoescape: false });"#),
            ("app/data/profile-dao.js", "user.firstName = firstName;\nuser.lastName = lastName;\nusers.update({ id }, user);"),
            ("app/routes/profile.js", r#"const { firstName } = req.body;
const firstNameSafeString = firstName;
profile.updateUser(id, firstName);
return res.render("profile", { ...doc, firstNameSafeString });"#),
            ("app/routes/index.js", r#"app.post("/profile", isLoggedIn, profileHandler.handleProfileUpdate);
app.post("/benefits", isLoggedIn, benefitsHandler.updateBenefits);"#),
            ("app/routes/research.js", r#"needle.get(url, (err, reply, body) => {
res.writeHead(200, { "Content-Type": "text/html" });
res.write(body);
});"#),
            ("app/views/profile.html", "{% extends './layout.html' %}\n<form method=\"post\" action=\"/profile\">\n<input value=\"{{firstNameSafeString}}\">\n<input value=\"{{lastName}}\">"),
            ("app/views/benefits.html", "<form method=\"POST\" action=\"/benefits\">"),
            ("app/views/layout.html", "<p>{{firstName}} {{lastName}}</p>"),
        ];
        for (relative, source) in fixture {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, source).unwrap();
        }
        let paths: Vec<_> = [
            "server.js",
            "app/data/profile-dao.js",
            "app/routes/profile.js",
            "app/routes/index.js",
            "app/routes/research.js",
        ]
        .into_iter()
        .map(|path| root.join(path))
        .collect();
        let patterns = build_vuln_patterns();
        let titles = || {
            scoped_template_xss_csrf_findings(&paths, &root, &patterns)
                .into_iter()
                .map(|f| (f.title, f.file_path.unwrap(), f.line_number.unwrap()))
                .collect::<Vec<_>>()
        };
        let positive = titles();
        assert_eq!(positive.len(), 6, "{positive:?}");
        assert_eq!(
            positive
                .iter()
                .filter(|(name, _, _)| name == "Unescaped Template Output (XSS)")
                .count(),
            3
        );
        assert_eq!(
            positive
                .iter()
                .filter(|(name, _, _)| name == "Missing CSRF Protection")
                .count(),
            2
        );
        assert_eq!(
            positive
                .iter()
                .filter(|(name, _, _)| name == "Unsafe HTML Response (XSS)")
                .count(),
            1
        );
        fs::write(
            root.join("server.js"),
            "app.use(session({}));\napp.use(csrf());\nswig.setDefaults({ autoescape: true });",
        )
        .unwrap();
        assert!(titles()
            .iter()
            .all(|(name, _, _)| name != "Missing CSRF Protection"
                && name != "Unescaped Template Output (XSS)"));
        fs::write(
            root.join("app/routes/research.js"),
            "needle.get(url, (e, r, body) => { res.type('text/plain'); res.write(body); });",
        )
        .unwrap();
        assert!(titles().is_empty(), "protected app should stay clean");
        fs::write(
            root.join("server.js"),
            "app.use(session({}));\nswig.setDefaults({ autoescape: false });",
        )
        .unwrap();
        fs::write(
            root.join("app/routes/profile.js"),
            "return res.render(\"profile\", { safeName: escapeHtml(req.body.firstName) });",
        )
        .unwrap();
        fs::write(
            root.join("app/data/profile-dao.js"),
            "user.firstName = escapeHtml(firstName);\nusers.update({}, user);",
        )
        .unwrap();
        assert!(titles()
            .iter()
            .all(|(name, _, _)| name != "Unescaped Template Output (XSS)"));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn linked_privileged_routes_and_private_object_without_guards_are_reported() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-authz-{nonce}"));
        fs::create_dir_all(root.join("app/routes")).expect("mkdir");
        fs::write(
            root.join("app/routes/index.js"),
            r#"const SessionHandler = require("./session");
const BenefitsHandler = require("./benefits");
const AllocationsHandler = require("./allocations");
const sessionHandler = new SessionHandler(db);
const benefitsHandler = new BenefitsHandler(db);
const allocationsHandler = new AllocationsHandler(db);
const isLoggedIn = sessionHandler.isLoggedInMiddleware;
const isAdmin = sessionHandler.isAdminUserMiddleware;
app.get("/benefits", isLoggedIn, benefitsHandler.displayBenefits);
app.post("/benefits", isLoggedIn, benefitsHandler.updateBenefits);
app.get("/allocations/:userId", isLoggedIn, allocationsHandler.displayAllocations);
app.get("/profile", isLoggedIn, profileHandler.displayProfile);
"#,
        )
        .expect("route fixture");
        fs::write(
            root.join("app/routes/benefits.js"),
            r#"this.displayBenefits = (req, res) => {
 benefitsDAO.getAllNonAdminUsers((err, users) => res.render("benefits", {users}));
};
this.updateBenefits = (req, res) => {
 const { userId } = req.body;
 benefitsDAO.updateBenefits(userId, req.body.date, () => res.render("benefits"));
};"#,
        )
        .expect("privileged fixture");
        fs::write(
            root.join("app/routes/allocations.js"),
            r#"this.displayAllocations = (req, res) => {
 const {
   userId
 } = req.params;
 allocationsDAO.getByUserIdAndThreshold(userId, req.query.threshold, (err, allocations) => {
   return res.render("allocations", { allocations });
 });
};"#,
        )
        .expect("idor fixture");
        let report = collect_review_findings(&root, false, None)
            .await
            .expect("review");
        let mut found: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.title == MISSING_ADMIN || f.title == IDOR)
            .map(|f| {
                (
                    f.title.as_str(),
                    f.file_path
                        .as_deref()
                        .unwrap_or("")
                        .strip_prefix(root.to_str().unwrap_or(""))
                        .unwrap_or(""),
                    f.line_number.unwrap_or(0),
                )
            })
            .collect();
        found.sort();
        assert_eq!(
            found,
            vec![
                (IDOR, "/app/routes/allocations.js", 3),
                (MISSING_ADMIN, "/app/routes/index.js", 9),
                (MISSING_ADMIN, "/app/routes/index.js", 10)
            ]
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[tokio::test]
    async fn admin_gate_and_owner_check_prevent_cross_file_findings() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-authz-guard-{nonce}"));
        fs::create_dir_all(root.join("routes")).expect("mkdir");
        fs::write(
            root.join("routes/index.js"),
            r#"const SessionHandler = require("./session");
const BenefitsHandler = require("./benefits");
const AllocationsHandler = require("./allocations");
const sessionHandler = new SessionHandler(db);
const benefitsHandler = new BenefitsHandler(db);
const allocationsHandler = new AllocationsHandler(db);
const isLoggedIn = sessionHandler.isLoggedInMiddleware;
const isAdmin = sessionHandler.isAdminUserMiddleware;
app.get("/benefits", isLoggedIn, isAdmin, benefitsHandler.displayBenefits);
app.post("/benefits", isLoggedIn, isAdmin, benefitsHandler.updateBenefits);
app.get("/allocations/:userId", isLoggedIn, allocationsHandler.displayAllocations);
"#,
        )
        .expect("route fixture");
        fs::write(root.join("routes/benefits.js"), "this.updateBenefits = () => benefitsDAO.updateBenefits();\nthis.displayBenefits = () => benefitsDAO.getAllNonAdminUsers();").expect("privileged fixture");
        fs::write(
            root.join("routes/allocations.js"),
            r#"this.displayAllocations = (req, res) => {
 const { userId } = req.params;
 if (userId !== req.session.userId) return res.sendStatus(403);
 allocationsDAO.getByUserIdAndThreshold(userId, threshold, () => res.render("allocations"));
};"#,
        )
        .expect("idor fixture");
        let report = collect_review_findings(&root, false, None)
            .await
            .expect("review");
        assert!(!report
            .findings
            .iter()
            .any(|f| f.title == MISSING_ADMIN || f.title == IDOR));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[tokio::test]
    async fn review_output_has_verified_source_to_sink_path_or_explicit_absence() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-path-output-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("app.js"),
            r#"const run = (req) => {
    const name = req.body.name;
    const command = name;
    exec(command);
};"#,
        )
        .unwrap();
        fs::write(
            root.join("config.js"),
            format!(
                "const jwt_secret = {:?};",
                ["insecure", "static", "secret"].join("-")
            ),
        )
        .unwrap();
        let report = collect_review_findings(&root, false, None).await.unwrap();
        let flow = report
            .findings
            .iter()
            .find(|f| {
                f.title == "Command Injection"
                    && f.file_path
                        .as_deref()
                        .is_some_and(|p| p.ends_with("app.js"))
            })
            .expect("command injection finding");
        let steps = flow.source_to_sink.as_ref().expect("verified trace");
        assert_eq!(steps.first().unwrap().action, "source");
        assert_eq!(steps.first().unwrap().line, 2);
        assert!(steps.iter().any(|s| s.action == "flow" && s.line == 3));
        assert_eq!(steps.last().unwrap().line, 4);
        let regex = report
            .findings
            .iter()
            .find(|f| f.title == "JWT Secret Hardcoded")
            .expect("regex finding");
        assert!(regex.source_to_sink.is_none());
        let json: serde_json::Value = serde_json::from_str(&generate_review_json(&report)).unwrap();
        let entries = json["findings"].as_array().unwrap();
        assert!(entries
            .iter()
            .any(|f| f["title"] == "Command Injection" && f["source_to_sink"].is_array()));
        assert!(entries
            .iter()
            .any(|f| f["title"] == "JWT Secret Hardcoded" && f["source_to_sink"].is_null()));
        let sarif: serde_json::Value =
            serde_json::from_str(&generate_sarif(&report, &root)).unwrap();
        assert!(sarif["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["message"]["text"]
                .as_str()
                .unwrap_or("")
                .contains("Source-to-sink path:")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bare_orm_lookup_and_guarded_spring_access_are_not_idor() {
        let helper = "def get_by_id(cls, record_id):\n    return cls.query.get(record_id)\n";
        assert!(!titles(&scan(helper, "py")).contains(&IDOR));
        let guarded = r#"@DeleteMapping("/{id}")
public ResponseEntity delete(@PathVariable("id") String id, User user) {
    var comment = commentRepository.findById(id);
    if (!AuthorizationService.canWriteComment(user, comment)) {
        throw new NoAuthorizationException();
    }
    commentRepository.remove(comment);
    return ResponseEntity.noContent().build();
}"#;
        assert!(!titles(&scan(guarded, "java")).contains(&IDOR));
    }

    #[test]
    fn idor_requires_http_route_and_object_exposure() {
        let helper = r#"public Record load(HttpServletRequest request) {
    String id = request.getParameter("id");
    return recordRepository.findById(id);
}"#;
        assert!(!titles(&scan(helper, "java")).contains(&IDOR));
        let guarded = r#"exports.read = (req, res) => {
    const id = req.params.id;
    const record = User.findById(id);
    if (!hasPermission(req.user, record)) return res.sendStatus(403);
    return res.json(record);
};"#;
        assert!(!titles(&scan(guarded, "js")).contains(&IDOR));
        let no_exposure = r#"exports.read = (req, res) => {
    const id = req.params.id;
    User.findById(id);
};"#;
        assert!(!titles(&scan(no_exposure, "js")).contains(&IDOR));
    }

    #[test]
    fn python_route_returning_request_selected_object_is_idor() {
        let route = r#"@app.route('/users/<id>')
def show(id):
    record = User.get_by_id(id)
    return record
"#;
        assert!(titles(&scan(route, "py")).contains(&IDOR));
    }

    #[test]
    fn unguarded_request_selected_orm_access_is_idor() {
        let java = r#"@GetMapping("/{id}")
public ResponseEntity read(@PathVariable("id") String id) {
    var record = recordRepository.findById(id);
    return ResponseEntity.ok(record);
}"#;
        assert!(titles(&scan(java, "java")).contains(&IDOR));
        let js = r#"exports.read = (req, res) => {
    const id = req.params.id;
    const record = User.findById(id);
    return res.json(record);
};"#;
        assert!(titles(&scan(js, "js")).contains(&IDOR));
    }

    const SSTI: &str = "Server-Side Template Injection (SSTI)";

    #[test]
    fn fixed_template_names_and_constant_list_are_not_ssti() {
        let source = r#"const pages = ["a1", "a2", "redos", "ssrf"];
for (const page of pages) {
    router.get(`${page}`, (req, res) => {
        return res.render(`tutorial/${page}`, { environmentalScripts });
    });
}
res.render("tutorial/a1", { page: req.query.page });
"#;
        assert!(!titles(&scan(source, "js")).contains(&SSTI));
        assert!(!titles(&scan(
            "render_template('article.html', name=request.args['name'])",
            "py"
        ))
        .contains(&SSTI));
    }

    #[test]
    fn request_controlled_template_sources_remain_ssti() {
        for source in [
            "res.render(req.params.page);",
            "const name = req.query.template;\nres.render(name);",
            "const name = req.params.page;\nconst selected = `tutorial/${name}`;\nres.render(selected);",
            "ejs.render(req.body.template, { user: 'a' });",
        ] {
            assert!(titles(&scan(source, "js")).contains(&SSTI), "{source}");
        }
        for source in [
            "render_template(request.args['page'])",
            "name = request.args['page']\nrender_template(name)",
            "render_template_string(request.form['template'])",
            "@app.route('/page/<name>')\ndef page(name):\n    return render_template(name)",
        ] {
            assert!(titles(&scan(source, "py")).contains(&SSTI), "{source}");
        }
    }

    #[test]
    fn test_context_paths_are_component_and_filename_based() {
        let root = Path::new("/work/tests/realworld-example-app");
        for path in [
            "src/tests/services/auth.service.test.ts",
            "tests/factories.py",
            "src/test/java/CommentsApiTest.java",
            "spec/models/user_spec.rb",
            "fixtures/user.json",
            "examples/demo.js",
            "src/services/auth.test.ts",
            "src/test_auth.py",
            "src/Example.java",
            "guava-tests/test/HashingTest.java",
            "benchmark/throughput.go",
            "features/step_definitions/login_steps.rb",
        ] {
            let expected = path != "src/Example.java";
            assert_eq!(
                is_test_context_path(&root.join(path), root),
                expected,
                "{path}"
            );
        }
        for path in [
            "src/contest/handler.ts",
            "src/specification.rs",
            "src/testimonials.js",
            "src/testing.ts",
            "src/production.java",
            "conduit/settings.py",
            "src/latest.rs",
            "src/contest-results.js",
            "src/attest.go",
        ] {
            assert!(!is_test_context_path(&root.join(path), root), "{path}");
        }
        assert!(!is_test_context_path(
            Path::new("/other/tests/auth.test.ts"),
            root
        ));
    }

    #[test]
    fn identifier_collision_patterns_match_real_sink_shapes_only() {
        let patterns = build_vuln_patterns();
        let by_name = |name: &str| {
            patterns
                .iter()
                .find(|p| p.name == name)
                .unwrap_or_else(|| panic!("pattern {name}"))
        };
        let hits = |name: &str, line: &str| {
            let p = by_name(name);
            p.pattern.is_match(line) && !p.negative.as_ref().is_some_and(|neg| neg.is_match(line))
        };

        // ORM raw queries: real call shapes survive.
        let orm = "SQL Injection — ORM Raw Queries";
        assert!(hits(
            orm,
            r#"users = User.objects.raw('SELECT * FROM users WHERE id = %s')"#,
        ));
        assert!(hits(orm, r#"DB::raw('select count(*) from logs')"#));
        assert!(hits(orm, r#"const rows = await client.rawQuery(sql)"#));
        assert!(hits(
            orm,
            r#"em.createNativeQuery("SELECT * FROM t WHERE x = " + x)"#
        ));
        assert!(hits(orm, r#"cursor.execute_sql("SELECT " + col)"#));
        // Identifier collisions and framework plumbing are gone.
        for line in [
            r#"def execute_sql(self, result_type):"#,
            r#"def self.sql(sql_string, *positional_binds)"#,
            r#"locking = Arel.sql("FOR UPDATE")"#,
            r#"Arel.sql(expr)"#,
            r#"return compiler.execute_sql(SINGLE) is not None"#,
            r#"connection.ops.execute_sql_flush(sql_list)"#,
            r#"from django.db.models.query import ModelIterable, RawQuerySet"#,
            r#"isinstance(queryset, RawQuerySet)"#,
            r#"__all__ = ["Query", "RawQuery"]"#,
            r#"raw (unescaped) character or not."#,
            r#""Prefetch querysets cannot use raw(), values(), and values_list().""#,
            r#"def raw(self, raw_query, params=(), translations=None, using=None):"#,
            r#"$this->config->raw()"#,
            r#"app.use(express.raw({ type: 'application/octet-stream' }))"#,
            r#"qparts = [sql.SQL("SELECT * FROM "), name, sql.SQL("(")]"#,
            r#"intent = QueryIntent.new(adapter: self, raw_sql: sql, name: name, binds: binds)"#,
            r#"u.RawQuery = r.URL.RawQuery"#,
        ] {
            assert!(
                !hits(orm, line),
                "orm-raw collision should not fire: {line}"
            );
        }

        // DES: crypto usages survive, lowercase identifiers do not.
        let des = "Weak Encryption — DES";
        assert!(hits(des, r#"block, err := des.NewCipher(key)"#));
        assert!(hits(des, r#"triple, err := des.NewTripleDESCipher(key24)"#));
        assert!(hits(des, r#"Cipher.getInstance("DES/CBC/PKCS5Padding")"#));
        assert!(hits(des, r#"cipher = OpenSSL::Cipher.new('DES-EDE3-CBC')"#));
        for line in [
            r#"des, err := f.File.(fs.ReadDirFile).ReadDir(n)"#,
            r#"for _, de := range des {"#,
            r#"dirs := make([]string, len(des))"#,
            r#"return des[:i], nil"#,
            r#"Des produits sont disponibles"#,
        ] {
            assert!(!hits(des, line), "des collision should not fire: {line}");
        }

        // OpenSSL exclusion-list tokens ('!DES') disable DES; they must not fire.
        for line in [
            r#"'!DES'"#,
            r#"'!3DES'"#,
            r#"'ssl' => '!DES:!3DES:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA',"#,
        ] {
            assert!(
                !hits(des, line),
                "DES exclusion token should not fire: {line}"
            );
        }

        // Mass assignment: standalone word survives, protection APIs do not.
        let ma = "Mass Assignment / Autobinding";
        assert!(hits(ma, r#"user.update_attributes(params[:user])"#));
        assert!(hits(ma, r#"mass_assignment = true"#));
        for line in [
            r#"def value_constructed_by_mass_assignment?(_value) # :nodoc:"#,
            r#"_assign_attributes(sanitize_for_mass_assignment(new_attributes))"#,
        ] {
            assert!(!hits(ma, line), "protection API should not fire: {line}");
        }
    }

    #[tokio::test]
    async fn review_excludes_test_credentials_but_not_production() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-context-{nonce}"));
        fs::create_dir_all(root.join("src/tests/services")).expect("mkdir");
        fs::create_dir_all(root.join("src/app")).expect("mkdir");
        let fixture = root.join("src/tests/services/auth.service.test.ts");
        let production = root.join("src/app/auth.service.ts");
        let code = format!("const user = {{ {}: '1234' }};", ["pass", "word"].concat());
        fs::write(&fixture, &code).expect("test fixture");
        fs::write(&production, &code).expect("production fixture");

        let report = collect_review_findings(&root, false, None)
            .await
            .expect("review");
        let credential = |path: &Path| {
            report
                .findings
                .iter()
                .find(|f| {
                    f.file_path.as_deref() == Some(path.to_string_lossy().as_ref())
                        && f.title == "Hardcoded Credentials"
                })
                .expect("credential finding")
        };
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.file_path.as_deref() != Some(fixture.to_string_lossy().as_ref())),
            "test-context finding is excluded, not downgraded"
        );
        let prod = credential(&production);
        assert_eq!(prod.severity, Severity::Critical);
        assert!(!prod.description.starts_with("Test/fixture context: "));
        let json = generate_review_json(&report);
        assert!(!json.contains("Test/fixture context:"));
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[tokio::test]
    async fn review_scans_repo_beneath_excluded_named_ancestors() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir()
            .join(format!("cipher-target-{nonce}"))
            .join("target")
            .join("vendor")
            .join("project");
        fs::create_dir_all(root.join("src")).expect("mkdir");
        fs::write(
            root.join("src/app.js"),
            format!(
                "const jwt_secret = {:?};",
                ["replace", "this", "secret"].join("-")
            ),
        )
        .expect("fixture");
        // Use a known pattern rule, not just a file-count assertion.
        let report = collect_review_findings(&root, false, None)
            .await
            .expect("review");
        fs::remove_dir_all(root.parent().unwrap().parent().unwrap().parent().unwrap())
            .expect("cleanup fixture");
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.title == "JWT Secret Hardcoded"),
            "review silently skipped the repository"
        );
    }

    #[test]
    fn seed_credentials_and_development_debug_keep_context_without_disappearing() {
        let root = Path::new("/repo");
        let mut findings = vec![
            Finding::new(
                FindingType::Vulnerability,
                "Hardcoded Credentials",
                "Fixed seed password",
                Severity::Critical,
                Confidence::High,
                "security-review",
            )
            .at("/repo/db/seeds.rb", 10),
            Finding::new(
                FindingType::Vulnerability,
                "Debug Mode Enabled",
                "Debug enabled",
                Severity::High,
                Confidence::High,
                "security-review",
            )
            .at("/repo/config/environments/development.rb", 30),
            Finding::new(
                FindingType::Vulnerability,
                "Debug Mode Enabled",
                "Debug enabled",
                Severity::High,
                Confidence::High,
                "security-review",
            )
            .at("/repo/config/environments/production.rb", 30),
            Finding::new(
                FindingType::Vulnerability,
                "Hardcoded Credentials",
                "Fixed password",
                Severity::Critical,
                Confidence::High,
                "security-review",
            )
            .at("/repo/app/user.rb", 10),
        ];
        mark_deployment_context(&mut findings, root);
        assert_eq!(
            findings.iter().map(|f| f.severity).collect::<Vec<_>>(),
            vec![
                Severity::Medium,
                Severity::Low,
                Severity::High,
                Severity::Critical
            ]
        );
        assert!(findings[0].description.starts_with("Seed data context: "));
        assert!(findings[1]
            .description
            .starts_with("Development-only setting: "));
    }

    #[test]
    fn python_file_based_pickle_load_is_deserialization() {
        let flagged = |src: &str| titles(&scan(src, "py")).contains(&"Insecure Deserialization");
        assert!(flagged(
            "f = request.files.get('file')\ndata = pickle.load(f)\n"
        ));
        assert!(flagged("data = pickle.loads(blob)\n"));
        // Writing and lookalike names are not deserialization.
        assert!(!flagged("pickle.dump(obj, fh)\n"));
        assert!(!flagged("pickle.dumps(obj)\n"));
        assert!(!flagged("x = pickle.loader_name\n"));
    }

    
