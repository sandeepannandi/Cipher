    #[test]
    fn sarif_paths_are_relative_escaped_and_do_not_require_existing_files() {
        assert_eq!(super::sarif_source_uri(Some("/repo/src/a b#c.rs"), std::path::Path::new("/repo")), "src/a%20b%23c.rs");
        assert_eq!(super::sarif_source_uri(Some("src/missing.rs"), std::path::Path::new("/repo")), "src/missing.rs");
        assert_eq!(super::sarif_source_uri(Some("C:\\repo\\src\\main.rs"), std::path::Path::new("C:\\repo")), "src/main.rs");
    }
    #[test]
    fn rust_fixture_strings_are_not_executed_but_real_sinks_remain() {
        let dir = std::env::temp_dir().join(format!("cipher-rust-context-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app.rs");
        std::fs::write(&path, r###"
const DESCRIPTION: &str = "DES 3DES dangerous_accept_invalid_certs";
#[cfg(test)]
mod fixtures {
 fn fake() { let password = "hunter2"; client.dangerous_accept_invalid_certs(true); }
}
fn production() {
 let password = "production-secret-not-fixture";
 client.dangerous_accept_invalid_certs(true);
}
"###).unwrap();
        let findings = super::scan_file_for_vulns(&path, &super::build_vuln_patterns());
        assert!(findings.iter().all(|f| f.line_number.unwrap() >= 8), "{findings:?}");
        assert!(findings.iter().any(|f| f.title.contains("Credentials")), "{findings:?}");
        assert!(findings.iter().any(|f| f.title.contains("Verification")), "{findings:?}");
        std::fs::remove_dir_all(dir).unwrap();
    }
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn rails_login_enumeration_requires_distinct_public_model_errors() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-rails-enumeration-{nonce}"));
        fs::create_dir_all(root.join("app/models")).unwrap();
        fs::create_dir_all(root.join("app/controllers")).unwrap();
        let model = root.join("app/models/user.rb");
        let controller = root.join("app/controllers/sessions_controller.rb");
        let vulnerable = "def self.authenticate(email, password)\n user = find_by_email(email)\n raise \"#{email} doesn't exist!\" if !(user)\n if user.password == Digest::MD5.hexdigest(password)\n  return user\n else\n  raise \"Incorrect Password!\"\n end\nend\n";
        let public = "User.authenticate(params[:email].to_s.strip.downcase, params[:password])\nrescue RuntimeError => e\nflash[:error] = e.message\nrender \"sessions/new\"\n";
        fs::write(&model, vulnerable).unwrap();
        fs::write(&controller, public).unwrap();
        let patterns = build_vuln_patterns();
        let detect = || scoped_rails_login_enumeration(&root, &patterns);
        assert_eq!(detect()[0].line_number, Some(3));
        fs::write(
            &controller,
            public.replace(
                "flash[:error] = e.message",
                "flash[:error] = \"Invalid login\"",
            ),
        )
        .unwrap();
        assert!(detect().is_empty(), "generic public error");
        fs::write(&controller, public).unwrap();
        fs::write(
            &model,
            vulnerable.replace(
                "raise \"Incorrect Password!\"",
                "raise \"#{email} doesn't exist!\"",
            ),
        )
        .unwrap();
        assert!(detect().is_empty(), "same error across branches");
        fs::write(
            &model,
            vulnerable.replace(
                "raise \"#{email} doesn't exist!\"",
                "raise \"Invalid login\"",
            ),
        )
        .unwrap();
        assert!(detect().is_empty(), "no email disclosure");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn php_password_csrf_requires_form_cookie_and_unguarded_get_write() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-php-password-csrf-{nonce}"));
        let handler = root.join("vulnerabilities/csrf/source/low.php");
        let form = root.join("vulnerabilities/csrf/index.php");
        let session = root.join("dvwa/includes/dvwaPage.inc.php");
        for path in [&handler, &form, &session] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
        }
        let code = concat!(
            "if( isset( $_GET[ 'Change' ] ) ) {\n $pass_new = $_GET[ 'password_new' ];\n $pass_conf = $_GET[ 'password_conf' ];\n if( $pass_new == $pass_conf ) {\n  $current_user = dvwaCurrentUser();\n",
            "  $insert = \"UPDATE `users` SET password = '",
            "$pass_new' WHERE user = '\" . $current_user . \"';\";\n  mysqli_query($db, $insert);\n }\n}\n"
        );
        let html = "case 'low':\n $vulnerabilityFile = 'low.php';\nrequire_once DVWA_WEB_PAGE_TO_ROOT . \"vulnerabilities/csrf/source/{$vulnerabilityFile}\";\n<form action=\"#\" method=\"GET\">\n<input name=\"password_new\">\n<input type=\"submit\" name=\"Change\">\n";
        fs::write(&handler, code).unwrap();
        fs::write(&form, html).unwrap();
        fs::write(
            &session,
            "session_set_cookie_params([\n$samesite = \"\";\n]);\n",
        )
        .unwrap();
        let patterns = build_vuln_patterns();
        let detect = || scoped_php_password_csrf(&root, &patterns);
        assert_eq!(detect()[0].line_number, Some(6));
        fs::write(
            &handler,
            code.replace(
                "mysqli_query($db, $insert);",
                "checkToken($token, $session, 'index.php');\n mysqli_query($db, $insert);",
            ),
        )
        .unwrap();
        assert!(detect().is_empty(), "validated token");
        fs::write(
            &handler,
            code.replace("$_GET[ 'password_new' ]", "$_POST[ 'password_new' ]"),
        )
        .unwrap();
        assert!(detect().is_empty(), "non-GET input");
        fs::write(&handler, code).unwrap();
        fs::write(&form, html.replace("method=\"GET\"", "method=\"POST\"")).unwrap();
        assert!(detect().is_empty(), "non-GET form");
        fs::write(&form, html).unwrap();
        fs::write(
            &session,
            "session_set_cookie_params(['samesite' => 'Strict']);",
        )
        .unwrap();
        assert!(detect().is_empty(), "strict cookie");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn php_level_conditional_authz_requires_gated_role_check_and_operation() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-php-level-authz-{nonce}"));
        let getter = root.join("vulnerabilities/authbypass/get_user_data.php");
        let changer = root.join("vulnerabilities/authbypass/change_user_details.php");
        for path in [&getter, &changer] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
        }
        let getter_code = concat!(
            "<?php\n\n\n\n\n\n/*\nOn high and impossible, only the admin is allowed to retrieve the data.\n*/\n",
            "if ((dvwaSecurityLevelGet() == \"high\" || dvwaSecurityLevelGet() == \"impossible\") && dvwaCurrentUser() != \"admin\") {\n",
            "\tprint json_encode (array (\"result\" => \"fail\", \"error\" => \"Access denied\"));\n\texit;\n}\n\n",
            "$query  = \"SELECT user_id, first_name, last_name FROM users\";\n",
            "$result = mysqli_query($GLOBALS[\"___mysqli_ston\"],  $query );\n"
        );
        let changer_code = concat!(
            "<?php\n\n\n\n\n\n/*\nOn impossible only the admin is allowed to retrieve the data.\n*/\n\n",
            "if (dvwaSecurityLevelGet() == \"impossible\" && dvwaCurrentUser() != \"admin\") {\n",
            "\tprint json_encode (array (\"result\" => \"fail\", \"error\" => \"Access denied\"));\n\texit;\n}\n\n",
            "$query = \"UPDATE users SET first_name = '\" . $data->first_name . \"' where user_id = \" . $data->id . \"\";\n"
        );
        fs::write(&getter, getter_code).unwrap();
        fs::write(&changer, changer_code).unwrap();
        let patterns = build_vuln_patterns();
        let detect = || scoped_php_level_conditional_authz(&root, &patterns);
        let found = detect();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].line_number, Some(15));
        assert_eq!(found[1].line_number, Some(16));
        // An unconditional admin gate covers every level: no finding.
        fs::write(
            &getter,
            getter_code.replace(
                "if ((dvwaSecurityLevelGet() == \"high\" || dvwaSecurityLevelGet() == \"impossible\") && dvwaCurrentUser() != \"admin\") {",
                "if (dvwaCurrentUser() != \"admin\") {",
            ),
        )
        .unwrap();
        let found = detect();
        assert_eq!(found.len(), 1, "unconditional gate on the getter");
        // No sensitive operation: the gated check alone is not reported.
        fs::write(&getter, getter_code).unwrap();
        fs::write(
            &changer,
            changer_code.replace(
                "$query = \"UPDATE users SET first_name = '\" . $data->first_name . \"' where user_id = \" . $data->id . \"\";",
                "$query = \"SELECT 1\";",
            ),
        )
        .unwrap();
        let found = detect();
        assert_eq!(found.len(), 1, "no user update on the changer");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn php_single_pass_include_filter_requires_single_pass_strip_and_sink() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-php-fi-filter-{nonce}"));
        let medium = root.join("vulnerabilities/fi/source/medium.php");
        let index = root.join("vulnerabilities/fi/index.php");
        fs::create_dir_all(medium.parent().unwrap()).unwrap();
        let medium_code = concat!(
            "<?php\n",
            "$file = $_GET[ 'page' ];\n",
            "$file = str_replace( array( \"http://\", \"https://\" ), \"\", $file );\n",
            "$file = str_replace( array( \"../\", \"..\\\\\" ), \"\", $file );\n",
            "?>\n"
        );
        let index_code = concat!(
            "<?php\n",
            "require_once DVWA_WEB_PAGE_TO_ROOT . \"vulnerabilities/fi/source/{$vulnerabilityFile}\";\n",
            "if( isset( $file ) )\n    include( $file );\n",
            "?>\n"
        );
        fs::write(&index, index_code).unwrap();
        let patterns = build_vuln_patterns();

        fs::write(&medium, medium_code).unwrap();
        let found = scoped_php_single_pass_include_filter(&root, &patterns);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line_number, Some(4));

        // An allowlist in place of the strip stays clean.
        fs::write(
            &medium,
            "<?php\n$file = $_GET[ 'page' ];\nif( !in_array($file, $configFileNames) ) { exit; }\n",
        )
        .unwrap();
        assert!(scoped_php_single_pass_include_filter(&root, &patterns).is_empty());

        // An fnmatch prefix gate (high level) stays clean.
        fs::write(
            &medium,
            "<?php\n$file = $_GET[ 'page' ];\nif( !fnmatch( \"file*\", $file ) && $file != \"include.php\" ) { exit; }\n",
        )
        .unwrap();
        assert!(scoped_php_single_pass_include_filter(&root, &patterns).is_empty());

        // Without the include sink wiring there is no reachable sink.
        fs::write(&medium, medium_code).unwrap();
        fs::write(&index, "<?php\nprint \"ok\";\n").unwrap();
        assert!(scoped_php_single_pass_include_filter(&root, &patterns).is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dotnet_lesson_sqli_requires_lesson_wiring_and_active_concat() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-dotnet-sqli-{nonce}"));
        let lesson = root.join("WebGoat/Content/SQLInjection.aspx.cs");
        let provider = root.join("WebGoat/App_Code/DB/SqliteDbProvider.cs");
        fs::create_dir_all(lesson.parent().unwrap()).unwrap();
        fs::create_dir_all(provider.parent().unwrap()).unwrap();
        let provider_code = concat!(
            "public DataSet GetEmailByName(string name)\n",
            "{\n",
            "    string sql = \"select firstName, lastName, email from Employees where firstName like '\" + name + \"%'\";\n",
            "/*\n",
            "    string sql2 = \"select firstName from Employees where firstName like '\" + name + \"%'\";\n",
            "*/\n",
            "}\n"
        );
        let patterns = build_vuln_patterns();

        // Wired lesson page: the active concatenated query reports, the
        // commented-out twin stays dead.
        fs::write(&lesson, "DataSet ds = du.GetEmailByName(name);\n").unwrap();
        fs::write(&provider, provider_code).unwrap();
        let found = scoped_dotnet_lesson_sqli(&root, &patterns);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line_number, Some(3));

        // Without the lesson-page call there is no documented route.
        fs::write(&lesson, "// nothing here\n").unwrap();
        assert!(scoped_dotnet_lesson_sqli(&root, &patterns).is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dotnet_path_manipulation_requires_source_and_unscrubbed_concat() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-dotnet-path-{nonce}"));
        let page = root.join("WebGoat/Content/PathManipulation.aspx.cs");
        fs::create_dir_all(page.parent().unwrap()).unwrap();
        let page_code = concat!(
            "protected void Page_Load(object sender, EventArgs e)\n",
            "{\n",
            "    string filename = Request.QueryString[\"filename\"];\n",
            "    if(filename != null)\n",
            "        ResponseFile(Request, Response, filename, MapPath(\"~/Downloads/\" + filename), 100);\n",
            "}\n"
        );
        let patterns = build_vuln_patterns();

        fs::write(&page, page_code).unwrap();
        let found = scoped_dotnet_path_manipulation(&root, &patterns);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line_number, Some(5));

        // A Path.GetFileName scrub closes the traversal.
        fs::write(
            &page,
            "string filename = Path.GetFileName(Request.QueryString[\"filename\"]);\nResponseFile(Request, Response, filename, MapPath(\"~/Downloads/\" + filename), 100);\n",
        )
        .unwrap();
        assert!(scoped_dotnet_path_manipulation(&root, &patterns).is_empty());

        // A fixed download target has no user-controlled component.
        fs::write(
            &page,
            "ResponseFile(Request, Response, \"report.pdf\", MapPath(\"~/Downloads/report.pdf\"), 100);\n",
        )
        .unwrap();
        assert!(scoped_dotnet_path_manipulation(&root, &patterns).is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dotnet_lesson_xss_is_scoped_to_the_vulnerable_method_body() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-dotnet-xss-{nonce}"));
        let reflected = root.join("WebGoat/Content/ReflectedXSS.aspx.cs");
        let stored = root.join("WebGoat/Content/StoredXSS.aspx.cs");
        fs::create_dir_all(reflected.parent().unwrap()).unwrap();
        let reflected_code = concat!(
            "if (Request[\"city\"] != null)\n",
            "    LoadCity(Request[\"city\"]);\n",
            "void LoadCity (String city)\n",
            "{\n",
            "    lblOutput.Text = \"Here are the details for our \" + city + \" Office\";\n",
            "}\n",
            "void FixedLoadCity (String city)\n",
            "{\n",
            "    lblOutput.Text = \"Here are the details for our \" + Server.HtmlEncode(city) + \" Office\";\n",
            "}\n"
        );
        let stored_code = concat!(
            "void LoadComments()\n",
            "{\n",
            "    DataSet ds = du.GetComments(\"user_cmt\");\n",
            "    comments += \"<strong>Email:</strong>\" + row[\"email\"] + \"<br/>\";\n",
            "    lblComments.Text = comments;\n",
            "}\n",
            "void FixedLoadComments()\n",
            "{\n",
            "    comments += \"<strong>Email:</strong>\" + Server.HtmlEncode(row[\"email\"].ToString()) + \"<br/>\";\n",
            "}\n",
            "void btnSave() { du.AddComment(\"user_cmt\", a, b); }\n"
        );
        let patterns = build_vuln_patterns();

        fs::write(&reflected, reflected_code).unwrap();
        fs::write(&stored, stored_code).unwrap();
        let found = scoped_dotnet_lesson_xss(&root, &patterns);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].line_number, Some(5));
        assert_eq!(found[1].line_number, Some(4));

        // When the load method itself encodes, both stay clean.
        fs::write(
            &reflected,
            "if (Request[\"city\"] != null)\nvoid LoadCity (String city)\n{\n    lblOutput.Text = \"x\" + Server.HtmlEncode(city) + \"y\";\n}\n",
        )
        .unwrap();
        fs::write(
            &stored,
            "void LoadComments() { comments += \"x\"; }\nvoid FixedLoadComments() {}\n",
        )
        .unwrap();
        assert!(scoped_dotnet_lesson_xss(&root, &patterns).is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dotnet_upload_unrestricted_requires_saveas_without_allowlist() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-dotnet-upload-{nonce}"));
        let page = root.join("WebGoat/Content/UploadPathManipulation.aspx.cs");
        fs::create_dir_all(page.parent().unwrap()).unwrap();
        let page_code = concat!(
            "if (FileUpload1.HasFile)\n",
            "{\n",
            "    string filename = Path.GetFileName(FileUpload1.FileName);\n",
            "    FileUpload1.SaveAs(Server.MapPath(\"~/WebGoatCoins/uploads/\") + filename);\n",
            "}\n"
        );
        let patterns = build_vuln_patterns();

        fs::write(&page, page_code).unwrap();
        let found = scoped_dotnet_upload_unrestricted(&root, &patterns);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line_number, Some(4));

        // An extension allowlist closes the finding.
        fs::write(
            &page,
            "if (!FileUpload1.FileName.EndsWith(\".pdf\")) { return; }\nFileUpload1.SaveAs(Server.MapPath(\"~/uploads/\") + filename);\n",
        )
        .unwrap();
        assert!(scoped_dotnet_upload_unrestricted(&root, &patterns).is_empty());

        // A fixed server-side name has no user-controlled path component.
        fs::write(
            &page,
            "FileUpload1.SaveAs(Server.MapPath(\"~/uploads/report.pdf\"));\n",
        )
        .unwrap();
        assert!(scoped_dotnet_upload_unrestricted(&root, &patterns).is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dotnet_debug_disclosure_flags_only_active_insecure_settings() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-dotnet-debug-{nonce}"));
        let config = root.join("WebGoat/Web.config");
        let lesson = root.join("WebGoat/Content/ExploitDebug.aspx");
        fs::create_dir_all(lesson.parent().unwrap()).unwrap();
        fs::write(&lesson, "<%@ Page %>\n").unwrap();
        let config_code = concat!(
            "<configuration>\n",
            "  <compilation defaultLanguage=\"C#\" debug=\"true\">\n",
            "  </compilation>\n",
            "  <customErrors mode=\"Off\" />\n",
            "</configuration>\n"
        );
        let patterns = build_vuln_patterns();

        fs::write(&config, config_code).unwrap();
        let found = scoped_dotnet_debug_disclosure(&root, &patterns);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].line_number, Some(2));
        assert_eq!(found[1].line_number, Some(4));

        // Hardened settings stay clean.
        fs::write(
            &config,
            "<configuration>\n  <compilation defaultLanguage=\"C#\" debug=\"false\">\n  </compilation>\n  <customErrors mode=\"RemoteOnly\" />\n</configuration>\n",
        )
        .unwrap();
        assert!(scoped_dotnet_debug_disclosure(&root, &patterns).is_empty());

        // Without the lesson page there is no documented exercise.
        fs::remove_file(&lesson).unwrap();
        fs::write(&config, config_code).unwrap();
        assert!(scoped_dotnet_debug_disclosure(&root, &patterns).is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dotnet_weak_digest_requires_lesson_wiring_and_fold_line() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-dotnet-digest-{nonce}"));
        let page = root.join("WebGoat/Content/MessageDigest.aspx.cs");
        let digest = root.join("WebGoat/App_Code/WeakMessageDigest.cs");
        fs::create_dir_all(page.parent().unwrap()).unwrap();
        fs::create_dir_all(digest.parent().unwrap()).unwrap();
        let digest_code = concat!(
            "public static byte GenByte(string word)\n",
            "{\n",
            "    int val = 0;\n",
            "    foreach(char c in word) val += (byte) c;\n",
            "    bVal = (byte) (val % (127 - 32 -1) + 33);\n",
            "    return bVal;\n",
            "}\n"
        );
        let patterns = build_vuln_patterns();

        fs::write(
            &page,
            "lblDigest.Text = WeakMessageDigest.GenerateWeakDigest(MSG);\n",
        )
        .unwrap();
        fs::write(&digest, digest_code).unwrap();
        let found = scoped_dotnet_weak_digest(&root, &patterns);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line_number, Some(5));

        // Without the lesson-page call there is no documented route.
        fs::write(&page, "// nothing\n").unwrap();
        assert!(scoped_dotnet_weak_digest(&root, &patterns).is_empty());

        // A vetted hash in place of the fold stays clean.
        fs::write(
            &page,
            "lblDigest.Text = WeakMessageDigest.GenerateWeakDigest(MSG);\n",
        )
        .unwrap();
        fs::write(&digest, "var bytes = SHA256.Create().ComputeHash(data);\n").unwrap();
        assert!(scoped_dotnet_weak_digest(&root, &patterns).is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dotnet_weak_random_requires_lesson_wiring_and_recurrence() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-dotnet-random-{nonce}"));
        let page = root.join("WebGoat/Content/Random.aspx.cs");
        let random = root.join("WebGoat/App_Code/WeakRandom.cs");
        fs::create_dir_all(page.parent().unwrap()).unwrap();
        fs::create_dir_all(random.parent().unwrap()).unwrap();
        let random_code = concat!(
            "public uint Next(uint min, uint max)\n",
            "{\n",
            "    unchecked\n",
            "    {\n",
            "        _seed = _seed * _seed + _seed;\n",
            "    }\n",
            "    return _seed % (max - min) + min;\n",
            "}\n"
        );
        let patterns = build_vuln_patterns();

        fs::write(
            &page,
            "WeakRandom rnd = (WeakRandom) Session[\"Random\"];\n",
        )
        .unwrap();
        fs::write(&random, random_code).unwrap();
        let found = scoped_dotnet_weak_random(&root, &patterns);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line_number, Some(5));

        // Without the lesson page there is no documented route.
        fs::write(&page, "// nothing\n").unwrap();
        assert!(scoped_dotnet_weak_random(&root, &patterns).is_empty());

        // A cryptographic generator in place of the recurrence stays clean.
        fs::write(
            &page,
            "WeakRandom rnd = (WeakRandom) Session[\"Random\"];\n",
        )
        .unwrap();
        fs::write(
            &random,
            "return RandomNumberGenerator.GetInt32((int)min, (int)max);\n",
        )
        .unwrap();
        assert!(scoped_dotnet_weak_random(&root, &patterns).is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dotnet_unsafe_block_requires_unbounded_user_write() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-dotnet-unsafe-{nonce}"));
        let page = root.join("WebGoat/Content/Unsafe.aspx.cs");
        fs::create_dir_all(page.parent().unwrap()).unwrap();
        let page_code = concat!(
            "public unsafe void btnReverse_Click(object sender, EventArgs args)\n",
            "{\n",
            "    char[] fixedChar = new char[256];\n",
            "    fixed (char* revLine = fixedChar)\n",
            "    {\n",
            "        int lineLen = txtBoxMsg.Text.Length;\n",
            "        for (int i = 0; i < lineLen; i++)\n",
            "            *(revLine + i) = txtBoxMsg.Text[lineLen - i - 1];\n",
            "    }\n",
            "}\n"
        );
        let patterns = build_vuln_patterns();

        fs::write(&page, page_code).unwrap();
        let found = scoped_dotnet_unsafe_block(&root, &patterns);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line_number, Some(8));

        // A bounded copy stays clean.
        fs::write(
            &page,
            "fixed (char* revLine = fixedChar)\n{\n    int lineLen = Math.Min(txtBoxMsg.Text.Length, INPUT_LEN);\n    for (int i = 0; i < lineLen; i++)\n        *(revLine + i) = txtBoxMsg.Text[lineLen - i - 1];\n}\n",
        )
        .unwrap();
        assert!(scoped_dotnet_unsafe_block(&root, &patterns).is_empty());

        // No unsafe fixed buffer, no finding.
        fs::write(&page, "lblReverse.Text = txtBoxMsg.Text;\n").unwrap();
        assert!(scoped_dotnet_unsafe_block(&root, &patterns).is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dvga_command_injection_flags_only_interpolated_run_cmd_calls() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-dvga-cmdi-{nonce}"));
        let helpers = root.join("core/helpers.py");
        let views = root.join("core/views.py");
        fs::create_dir_all(views.parent().unwrap()).unwrap();
        fs::write(
            &helpers,
            "import os\ndef run_cmd(cmd):\n  return os.popen(cmd).read()\n",
        )
        .unwrap();
        let views_code = concat!(
            "  def mutate(self, info, host, path):\n",
            "    url = f'{scheme}://{host}:{port}{path}'\n",
            "    cmd = helpers.run_cmd(f'curl --insecure {url}')\n",
            "  def resolve_system_diagnostics(self, info, cmd='whoami'):\n",
            "      output = helpers.run_cmd(cmd)\n",
            "  def resolve_system_debug(self, info, arg=None):\n",
            "      output = helpers.run_cmd('ps {}'.format(arg))\n",
            "      output = helpers.run_cmd('ps')\n",
            "      helpers.run_cmd(\"uptime | awk -F': ' '{print $2}'\")\n",
        );
        fs::write(&views, views_code).unwrap();
        let patterns = build_vuln_patterns();
        let found = scoped_dvga_command_injection(&root, &patterns);
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].line_number, Some(3));
        assert_eq!(found[1].line_number, Some(5));
        assert_eq!(found[2].line_number, Some(7));

        // shlex-quoted arguments close the finding.
        fs::write(
            &views,
            "      output = helpers.run_cmd('ps {}'.format(shlex.quote(arg)))\n",
        )
        .unwrap();
        assert!(scoped_dvga_command_injection(&root, &patterns).is_empty());

        // Without the os.popen wrapper, run_cmd is not source-confirmed.
        fs::write(&views, views_code).unwrap();
        fs::write(
            &helpers,
            "import subprocess\ndef run_cmd(cmd):\n  return subprocess.check_output(['run', cmd])\n",
        )
        .unwrap();
        assert!(scoped_dvga_command_injection(&root, &patterns).is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dvga_arbitrary_file_write_needs_route_and_concat_open() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-dvga-afw-{nonce}"));
        let helpers = root.join("core/helpers.py");
        let views = root.join("core/views.py");
        fs::create_dir_all(views.parent().unwrap()).unwrap();
        fs::write(
            &views,
            "  def mutate(self, info, filename, content):\n    result = helpers.save_file(filename, content)\n",
        )
        .unwrap();
        let helpers_code = concat!(
            "def save_file(filename, text):\n",
            "  try:\n",
            "    f = open(WEB_UPLOADDIR + filename, 'w')\n",
            "    f.write(text)\n",
        );
        fs::write(&helpers, helpers_code).unwrap();
        let patterns = build_vuln_patterns();
        let found = scoped_dvga_arbitrary_file_write(&root, &patterns);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line_number, Some(3));

        // A basename scrub closes the finding.
        fs::write(
            &helpers,
            "import os\ndef save_file(filename, text):\n  f = open(WEB_UPLOADDIR + os.path.basename(filename), 'w')\n",
        )
        .unwrap();
        assert!(scoped_dvga_arbitrary_file_write(&root, &patterns).is_empty());

        // Without the mutation route, the open is not user-reachable.
        fs::write(&helpers, helpers_code).unwrap();
        fs::write(&views, "  def mutate(self, info):\n    pass\n").unwrap();
        assert!(scoped_dvga_arbitrary_file_write(&root, &patterns).is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dvga_sql_injection_requires_resolver_and_raw_format() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-dvga-sqli-{nonce}"));
        let views = root.join("core/views.py");
        fs::create_dir_all(views.parent().unwrap()).unwrap();
        let views_code = concat!(
            "  def resolve_pastes(self, info, public=False, limit=1000, filter=None):\n",
            "    result = query.filter_by(public=public, burn=False)\n",
            "    if filter:\n",
            "      result = result.filter(text(\"title = '%s' or content = '%s'\" % (filter, filter)))\n",
        );
        fs::write(&views, views_code).unwrap();
        let patterns = build_vuln_patterns();
        let found = scoped_dvga_sql_injection(&root, &patterns);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line_number, Some(4));

        // Bound parameters close the finding.
        fs::write(
            &views,
            "  def resolve_pastes(self, info, filter=None):\n    result = result.filter(text(\"title = :t\").bindparams(t=filter))\n",
        )
        .unwrap();
        assert!(scoped_dvga_sql_injection(&root, &patterns).is_empty());

        // Without the resolver route there is no documented source.
        fs::write(
            &views,
            "result = result.filter(text(\"x = '%s'\" % (f,)))\n",
        )
        .unwrap();
        assert!(scoped_dvga_sql_injection(&root, &patterns).is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dvga_jwt_no_verify_flags_only_disabled_signature_check() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-dvga-jwt-{nonce}"));
        let helpers = root.join("core/helpers.py");
        fs::create_dir_all(helpers.parent().unwrap()).unwrap();
        let helpers_code = concat!(
            "from jwt import decode\n",
            "def get_identity(token):\n",
            "  return decode(token, options={\"verify_signature\":False, \"verify_exp\":False}).get('identity')\n",
        );
        fs::write(&helpers, helpers_code).unwrap();
        let patterns = build_vuln_patterns();
        let found = scoped_dvga_jwt_no_verify(&root, &patterns);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line_number, Some(3));

        // Verifying signatures closes the finding even with verify_exp off.
        fs::write(
            &helpers,
            "from jwt import decode\ndef get_identity(token):\n  return decode(token, options={\"verify_signature\": True, \"verify_exp\": False}).get('identity')\n",
        )
        .unwrap();
        assert!(scoped_dvga_jwt_no_verify(&root, &patterns).is_empty());

        // Without the identity route there is no documented source.
        fs::write(
            &helpers,
            "decode(token, options={\"verify_signature\":False})\n",
        )
        .unwrap();
        assert!(scoped_dvga_jwt_no_verify(&root, &patterns).is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dvga_stored_xss_requires_mutation_and_template_interpolation() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-dvga-xss-{nonce}"));
        let views = root.join("core/views.py");
        let template = root.join("templates/paste.html");
        fs::create_dir_all(views.parent().unwrap()).unwrap();
        fs::create_dir_all(template.parent().unwrap()).unwrap();
        fs::write(
            &views,
            "class CreatePaste(graphene.Mutation):\n    Paste.create_paste(title=title, content=content)\n",
        )
        .unwrap();
        let template_code = concat!(
            "<script>\n",
            "  var pasteHTML = `<div>${paste.title}</div>\n",
            "    <pre>${paste.content}</pre>`;\n",
            "  $(pasteHTML).hide().prependTo(\"#public_gallery\");\n",
            "</script>\n",
        );
        fs::write(&template, template_code).unwrap();
        let patterns = build_vuln_patterns();
        let found = scoped_dvga_stored_xss(&root, &patterns);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line_number, Some(3));

        // Escaping the value closes the finding.
        fs::write(&template, "<pre>{{ paste.content }}</pre>\n").unwrap();
        assert!(scoped_dvga_stored_xss(&root, &patterns).is_empty());

        // Without the storing mutation there is no documented source.
        fs::write(&template, template_code).unwrap();
        fs::write(&views, "class Other(graphene.Mutation):\n    pass\n").unwrap();
        assert!(scoped_dvga_stored_xss(&root, &patterns).is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn php_open_redirect_requires_get_location_write_and_low_route() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-php-open-redirect-{nonce}"));
        let handler = root.join("vulnerabilities/open_redirect/source/low.php");
        let index = root.join("vulnerabilities/open_redirect/index.php");
        for path in [&handler, &index] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
        }
        let code = concat!(
            "<?php\nif (array_key_exists (\"redirect\", $_GET) && $_GET['redirect'] != \"\") {\n",
            "\theader (\"location: \" . $_GET['redirect']);\n\texit;\n}\n"
        );
        let page = concat!(
            "dvwaPageStartup( array( 'authenticated' ) );\ncase 'low':\n",
            " $link1 = \"source/low.php?redirect=info.php?id=1\";\n"
        );
        fs::write(&handler, code).unwrap();
        fs::write(&index, page).unwrap();
        let patterns = build_vuln_patterns();
        let detect = || scoped_php_open_redirect(&root, &patterns);
        assert_eq!(detect()[0].line_number, Some(3));
        fs::write(&index, page.replace("case 'low':", "case 'medium':")).unwrap();
        assert!(detect().is_empty(), "low level not routed");
        fs::write(&index, page).unwrap();
        fs::write(
            &handler,
            code.replace(
                "header (\"location: \" . $_GET['redirect']);",
                "$allowed = [\"info.php?id=1\", \"info.php?id=2\"];\nif (in_array($_GET['redirect'], $allowed)) { header (\"location: \" . $_GET['redirect']); }",
            ),
        )
        .unwrap();
        assert!(detect().is_empty(), "allowlisted target");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn go_open_redirect_requires_request_controlled_target() {
        let data = r#"func Redirect(w http.ResponseWriter, r *http.Request) {
target := r.URL.Query().Get("to")
http.Redirect(w, r, target, http.StatusFound)
}"#;
        assert_eq!(open_redirect_sink_lines(data, "go"), [3].into());
        let constant = r#"func Home(w http.ResponseWriter, r *http.Request) {
http.Redirect(w, r, "/dashboard", http.StatusFound)
}"#;
        assert!(open_redirect_sink_lines(constant, "go").is_empty());
        let other_arg = r#"func Forward(w http.ResponseWriter, r *http.Request) {
http.Redirect(w, r, "/dashboard", http.StatusFound)
proxy(r.URL.Query().Get("to"))
}"#;
        assert!(open_redirect_sink_lines(other_arg, "go").is_empty());
    }

    #[test]
    fn go_jwt_parse_without_method_pinning_is_reported() {
        let unpinned = r#"func ValidateJWT(w http.ResponseWriter, r *http.Request) {
tokenStr := r.URL.Query().Get("token")
token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
return jwtSecret, nil
})
_ = token
_ = err
}"#;
        assert_eq!(go_jwt_unpinned_parse_lines(unpinned, "go"), [3].into());
        let pinned = r#"func ValidateJWT(w http.ResponseWriter, r *http.Request) {
tokenStr := r.URL.Query().Get("token")
token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
return nil, fmt.Errorf("unexpected signing method")
}
return jwtSecret, nil
})
_ = token
_ = err
}"#;
        assert!(go_jwt_unpinned_parse_lines(pinned, "go").is_empty());
        let valid_methods = r#"func ValidateJWT(w http.ResponseWriter, r *http.Request) {
token, err := jwt.Parse(tokenStr, keyFunc, jwt.WithValidMethods([]string{"HS256"}))
_ = token
_ = err
}"#;
        assert!(go_jwt_unpinned_parse_lines(valid_methods, "go").is_empty());
        assert!(go_jwt_unpinned_parse_lines(unpinned, "js").is_empty());
    }

    #[test]
    fn django_settings_md5_hasher_cookie_session_and_pickle_are_reported() {
        let settings = r#"DEBUG = False
PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']
SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"
SESSION_SERIALIZER = "django.contrib.sessions.serializers.PickleSerializer"
"#;
        let (password, cookie_session, pickle) = django_settings_sink_lines(settings, "py");
        assert_eq!(password, [2].into());
        assert_eq!(cookie_session, [3].into());
        assert_eq!(pickle, [4].into());
        let safe = r#"SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_SERIALIZER = "django.contrib.sessions.serializers.JSONSerializer"
"#;
        let (password, cookie_session, pickle) = django_settings_sink_lines(safe, "py");
        assert!(password.is_empty() && cookie_session.is_empty() && pickle.is_empty());
        let (password, _, _) = django_settings_sink_lines(settings, "rb");
        assert!(password.is_empty());
    }

    #[test]
    fn django_csrf_exempt_decorator_is_reported() {
        let views = r#"from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def reset_password(request):
    pass

@csrf_protect
def safe_view(request):
    pass

# @csrf_exempt
def commented_out(request):
    pass
"#;
        let sinks = django_csrf_exempt_lines(views, "py");
        assert_eq!(sinks, [3].into_iter().collect());
        assert!(django_csrf_exempt_lines(views, "js").is_empty());
    }

    
