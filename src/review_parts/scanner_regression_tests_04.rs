#[test]
    fn php_body_reads_and_json_decoding_are_not_object_deserialization() {
        let harmless = r#"$body = file_get_contents('php://input');
$input = json_decode(file_get_contents('php://input'), true);
$data = json_decode($body, true);"#;
        assert!(!titles(&scan(harmless, "php")).contains(&"Insecure Deserialization"));
        assert!(
            titles(&scan("$obj = unserialize($_POST['payload']);", "php"))
                .contains(&"Insecure Deserialization")
        );
        assert!(titles(&scan("user = Marshal.load(params[:user])", "rb"))
            .contains(&"Insecure Deserialization"));
        // Safe loader spellings and PHP class allowlists are the mitigation,
        // not the vulnerability.
        assert!(!titles(&scan(
            "objects = yaml.load(stream, Loader=SafeLoader)",
            "py"
        ))
        .contains(&"Insecure Deserialization"));
        assert!(
            !titles(&scan("data = SafeYAML.load(raw)", "rb")).contains(&"Insecure Deserialization")
        );
        assert!(!titles(&scan(
            "$callable = unserialize($action['uses'], ['allowed_classes' => [self::class]]);",
            "php"
        ))
        .contains(&"Insecure Deserialization"));
    }

    #[test]
    fn weak_hash_in_non_security_function_uses_the_enclosing_declaration() {
        let patterns = build_vuln_patterns();
        let negative = patterns
            .iter()
            .find(|p| p.name == "Weak Hash Algorithm — MD5")
            .and_then(|p| p.negative.as_ref())
            .expect("negative");
        let call = |f: &str, a: &str| format!("{f}({a})");
        let wrapper = format!(
            "def _db_md5(text):\n    if text is None:\n        return None\n    return {}.hexdigest()\n",
            call("md5", "text.encode()")
        );
        assert!(weak_hash_in_non_security_function(&wrapper, 4, negative));
        let mutex = format!(
            "    public function mutexName()\n    {{\n        return 'a'.\n            {};\n    }}\n",
            call("sha1", "$this->expression")
        );
        assert!(weak_hash_in_non_security_function(&mutex, 4, negative));
        // Negative controls: security names, neutral names, and no enclosing declaration.
        let password = format!(
            "def md5_password(password):\n    return {}.hexdigest()\n",
            call("md5", "password.encode()")
        );
        assert!(!weak_hash_in_non_security_function(&password, 2, negative));
        let neutral = format!(
            "def encode(self, password, salt):\n    return {}.hexdigest()\n",
            call("md5", "salt + password")
        );
        assert!(!weak_hash_in_non_security_function(&neutral, 2, negative));
        let toplevel = format!("pass = {}\n", call("md5", "pass"));
        assert!(!weak_hash_in_non_security_function(&toplevel, 1, negative));
        let token = format!(
            "function generateSessionToken() {{\n    return {};\n}}\n",
            call("md5", "uniqid()")
        );
        assert!(!weak_hash_in_non_security_function(&token, 2, negative));
    }

    #[test]
    fn weak_hash_protocol_contexts_do_not_fire() {
        let patterns = build_vuln_patterns();
        let hits = |name: &str, line: &str| {
            let p = patterns
                .iter()
                .find(|p| p.name == name)
                .unwrap_or_else(|| panic!("pattern {name}"));
            p.pattern.is_match(line) && !p.negative.as_ref().is_some_and(|neg| neg.is_match(line))
        };
        let md5 = "Weak Hash Algorithm — MD5";
        let sha1 = "Weak Hash Algorithm — SHA1";
        // Security usage still reports.
        assert!(hits(md5, r#"$pass = md5( $pass );"#));
        assert!(hits(
            md5,
            r#"digest = hashlib.md5(password.encode()).hexdigest()"#
        ));
        assert!(hits(
            sha1,
            r#"token = hashlib.sha1(secret.encode()).hexdigest()"#
        ));
        // Protocol-mandated and non-security contexts do not.
        for line in [
            r#"return hashlib.md5(x, usedforsecurity=False).hexdigest()"#,
            r#"md5(response.content, usedforsecurity=False).hexdigest()"#,
            r#"Metadata: map[string]string{metaMD5Hash: hex.EncodeToString(upload.Local.MD5())}"#,
            r#"func (lf *localFile) MD5() []byte {"#,
            r#"func (ns *Namespace) MD5(v any) (string, error) {"#,
            r#"public function sha1(string $file)"#,
            r#"class SHA1(OracleHashMixin, PostgreSQLSHAMixin, Transform):"#,
        ] {
            assert!(!hits(md5, line), "md5 protocol context: {line}");
        }
        for line in [
            r#"return hashlib.sha1(x, usedforsecurity=False).hexdigest()"#,
            r#"'key' => self::$shouldHashKeys ? md5($limiterName.$limit->key) : $limiterName.':'.$limit->key,"#,
            r#"return self::$shouldHashKeys ? sha1($value) : $value;"#,
            r#"if (isset($metadata['sha1']) && $this->cache->sha1((string) $include) === $metadata['sha1']) {"#,
            r#"if ($this->cache !== null && ($checksum === null || $checksum === '' || $checksum === $this->cache->sha1($file))) {"#,
            r#"if (! hash_equals(sha1($this->user()->getEmailForVerification()), (string) $this->route('hash'))) {"#,
            r#"'hash' => sha1($notifiable->getEmailForVerification()),"#,
            r#"return 'login_'.$this->name.'_'.sha1(static::class);"#,
            r#"$this->sendOutputTo(storage_path('logs/schedule-'.sha1($this->mutexName()).'.log'));"#,
            r#"if (is_file($path = storage_path('framework/cache/facade-'.sha1($alias).'.php'))) {"#,
            r#"func (ns *Namespace) SHA1(v any) (string, error) {"#,
            r#"static final HashFunction SHA_1 = new MessageDigestHashFunction("SHA-1", "Hashing.sha1()");"#,
            r#"$parts = array_slice(str_split($hash = sha1($key), 2), 0, 2);"#,
            r#"return sha1($this->tags->getNamespace()).':'.$key;"#,
            r#"return 'framework/schedule-'.sha1($this->description ?? '');"#,
            r#"return hashlib.sha1("|".join(values).encode()).hexdigest()"#,
            r#"return sha1(implode('|', array_merge("#,
            r#"$hash = strtoupper(sha1((string) $value));"#,
        ] {
            assert!(!hits(sha1, line), "sha1 non-security context: {line}");
        }
        assert!(!hits(
            md5,
            r#"} else if !bytes.Equal(lf.MD5(), remoteFile.MD5) {"#
        ));
        assert!(!hits(
            md5,
            r#"return 'dynamic_'.md5((new Collection($config))->map(function ($value, $key) {"#
        ));
        // Negative controls: hashes of credentials and signed material still report.
        // Built with format! so the repo's own scan does not see these as calls.
        let call = |f: &str, a: &str| format!("{f}({a})");
        let lines = [
            (
                md5,
                format!(
                    "hash = hashlib.{}.hexdigest()",
                    call("md5", "force_bytes(salt) + force_bytes(password)")
                ),
            ),
            (
                md5,
                format!("$stored = {};", call("md5", "$password . $salt")),
            ),
            (
                md5,
                format!(
                    "sig = hashlib.{}.hexdigest()",
                    call("md5", "secret + message")
                ),
            ),
            (
                sha1,
                format!(
                    "signature = hashlib.{}.hexdigest()",
                    call("sha1", "payload + api_secret")
                ),
            ),
            (
                sha1,
                format!("$token = {};", call("sha1", "$user->password . $salt")),
            ),
            (
                sha1,
                format!("digest = {}.hexdigest()", call("sha1", "password.encode()")),
            ),
        ];
        for (name, line) in &lines {
            assert!(hits(name, line), "security hash must report: {line}");
        }
    }

    #[test]
    fn deserialization_on_trusted_stores_is_documented_design() {
        // MAC-verified payload (laravel Encrypter shape).
        let mac = "function decrypt($payload) { return hash_equals($a, $b); }
$value = unserialize($decrypted);";
        assert!(deserialization_in_trusted_store(
            mac,
            "src/Encryption/Encrypter.php"
        ));
        // Bidirectional codec: the application writes what it reads.
        let codec = "def write(e)
 Marshal.dump(e)
 end
 def read
 Marshal.load(@raw)
 end";
        assert!(deserialization_in_trusted_store(
            codec,
            "lib/cache/entry.rb"
        ));
        let pycodec = "def set(self, v):
 return pickle.dumps(v)
def get(self):
 return pickle.loads(self.raw)";
        assert!(deserialization_in_trusted_store(
            pycodec,
            "django/core/cache/backends/locmem.py"
        ));
        // Trusted-store path alone (queue handler reading broker payloads).
        let handler = "public function handle($command) { return unserialize($command); }";
        assert!(deserialization_in_trusted_store(
            handler,
            "src/Illuminate/Queue/CallQueuedHandler.php"
        ));
        // Request-data deserialization with no trust signals still reports.
        let controller = "def reset_password
 user = Marshal.load(Base64.decode64(params[:user]))
 end";
        assert!(!deserialization_in_trusted_store(
            controller,
            "app/controllers/password_resets_controller.rb"
        ));

        // A codec-shaped file under an attacker-facing path is still a codec,
        // but an unserialize-only file outside trusted segments reports.
        let reader = "$value = unserialize(file_get_contents($path));";
        assert!(!deserialization_in_trusted_store(
            reader,
            "src/Service/Import.php"
        ));
    }

    #[test]
    fn small_fp_class_suppression_helpers() {
        // Debug Mode Enabled: configuration reads and prose messages are
        // suppressed; real flag assignments still fire.
        for line in [
            "if (config('app.debug')) {",
            "return $this->app['config']->get('app.debug', false);",
            "$this->app['config']->get('app.debug')",
        ] {
            assert!(debug_flag_is_config_read(line), "config read: {line}");
        }
        assert!(!debug_flag_is_config_read("DEBUG = True"));
        assert!(!debug_flag_is_config_read("debug: true"));
        assert!(debug_flag_in_prose(
            r#""more": _("More information is available with DEBUG=True."),"#
        ));
        assert!(!debug_flag_in_prose("DEBUG = True"));
        assert!(!debug_flag_in_prose("debug=True,"));
        assert!(!debug_flag_in_prose(r#"DEBUG = "DEBUG=True""#));

        // Hardcoded Credentials: an Algolia DocSearch client key is public
        // by design; the same key without the DocSearch config still fires.
        let docsearch = "docsearch({\n  app_id: 'D1BPLZHGYQ',\n  api_key: '6df94e1e5d55d258c56f60d974d10314',\n  index: 'hugodocs',\n});";
        assert!(is_algolia_docsearch_client_key(
            "api_key: '6df94e1e5d55d258c56f60d974d10314',",
            docsearch
        ));
        assert!(!is_algolia_docsearch_client_key(
            "api_key: '6df94e1e5d55d258c56f60d974d10314',",
            "const x = 1;"
        ));

        // SQL concat: fully quoted interpolation is suppressed; raw
        // interpolation and non-interpolated lines still fire.
        assert!(sql_interpolations_all_quoted(
            r#"execute("UPDATE #{quote_table_name(table_name)} SET #{quote_column_name(column_name)}=#{quote(value)}")"#
        ));
        assert!(!sql_interpolations_all_quoted(
            r#"execute("UPDATE users SET name=#{params[:name]}")"#
        ));
        assert!(!sql_interpolations_all_quoted(
            r#"$query = "SELECT * FROM users WHERE id = '$id'";"#
        ));
        assert!(!sql_interpolations_all_quoted(r#"execute("SELECT 1")"#));
    }

    #[test]
    fn php_sql_interpolation_is_not_a_literal_password() {
        for source in [
            concat!(
                "$query = \"SELECT * FROM users WHERE pass",
                "word='$pass';\";"
            ),
            concat!(
                "$query = \"UPDATE users SET pass",
                "word = '$pass_new' WHERE id = 1;\";"
            ),
        ] {
            assert!(
                !titles(&scan(source, "php")).contains(&"Hardcoded Credentials"),
                "{source}"
            );
        }
        assert!(titles(&scan(
            &["$pass", "word = 'actual-fixed-password';"].concat(),
            "php"
        ))
        .contains(&"Hardcoded Credentials"));
    }

    #[test]
    fn go_xml_sample_users_and_des_import_are_not_credential_or_cipher_use() {
        let source = ["xmlData := `<users>\n  <user name=\"admin\" password=\"secret\"/>\n</users>`\n\"crypto/", "d", "es\"\nblock, err := d", "es.NewCipher(key)"].concat();
        let findings = scan(&source, "go");
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.title == "Hardcoded Credentials")
                .count(),
            0
        );
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.title == ["Weak Encryption — ", "D", "ES"].concat())
                .count(),
            1
        );
        assert!(
            titles(&scan("adminPassword = \"real-fixed-password\"", "go"))
                .contains(&"Hardcoded Credentials")
        );
    }

    fn titles(findings: &[Finding]) -> Vec<&str> {
        findings
            .iter()
            .map(|finding| finding.title.as_str())
            .collect()
    }

    #[test]
    fn github_workflow_yaml_gets_workflow_checks() {
        let findings = scan(
            "on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n",
            "yml",
        );
        assert!(titles(&findings).contains(&crate::workflow::SCRIPT_INJECTION_TITLE));
        let plain = scan(
            "name: app\nrun: echo ${{ github.event.issue.title }}\n",
            "yml",
        );
        assert!(!titles(&plain).contains(&crate::workflow::SCRIPT_INJECTION_TITLE));
    }

    #[test]
    fn jwt_specific_binding_is_not_reported_as_generic_secret() {
        let findings = scan(r#"const jwt_secret = "replace-this-secret";"#, "js");
        assert_eq!(titles(&findings), vec!["JWT Secret Hardcoded"]);
    }

    #[test]
    fn contextual_jwt_secret_binding_is_promoted_to_specific_rule() {
        let findings = scan(
            "const secret = \"dev-secret\";\nconst token = `jwt.${secret}.payload`;",
            "js",
        );
        assert_eq!(titles(&findings), vec!["JWT Secret Hardcoded"]);
    }

    #[test]
    fn unrelated_generic_secret_keeps_generic_detection() {
        let findings = scan(
            r#"const secret = "dev-secret";
connect(secret);"#,
            "js",
        );
        assert_eq!(titles(&findings), vec!["Hardcoded Credentials"]);
    }

    #[test]
    fn signing_secret_fallbacks_and_properties_are_reported_once() {
        let js = scan("jwt.sign({ id }, process.env.JWT_SECRET || 'superSecret');\nsecret: process.env.JWT_SECRET || 'superSecret',\nsecret: process.env.JWT_SECRET || 'superSecret',", "ts");
        assert_eq!(
            js.iter()
                .filter(|f| f.title == "JWT Secret Hardcoded")
                .count(),
            3
        );
        assert_eq!(js.len(), 3);
        let py = scan(
            "SECRET_KEY = os.environ.get('CONDUIT_SECRET', 'secret-key')",
            "py",
        );
        assert_eq!(titles(&py), vec!["JWT Secret Hardcoded"]);
        let properties = scan(
            "jwt.secret=ThisFixedSigningSecretHasEnoughBytes123\n",
            "properties",
        );
        assert_eq!(titles(&properties), vec!["JWT Secret Hardcoded"]);
    }

    #[test]
    fn signing_secret_rule_rejects_environment_only_comments_and_non_signing_literals() {
        for (source, ext) in [
            ("const secret = process.env.JWT_SECRET;", "ts"),
            (
                "// secret: process.env.JWT_SECRET || 'example-secret'",
                "ts",
            ),
            ("SECRET_KEY = os.environ['CONDUIT_SECRET']", "py"),
            ("# jwt.secret=FakeSigningSecretValue", "properties"),
            ("jwt.secret=${JWT_SECRET}", "properties"),
            ("database.password=superSecret", "properties"),
        ] {
            assert!(
                scan(source, ext).is_empty(),
                "unexpected finding for {source}"
            );
        }
        let fixture = Path::new("/repo/src/test/resources/application.properties");
        assert!(signing_secret_sink_lines(
            fixture,
            "jwt.secret=AnyFixedSigningKey123",
            "properties"
        )
        .is_empty());
        let ts_fixture = Path::new("/repo/src/tests/auth.service.test.ts");
        assert!(signing_secret_sink_lines(
            ts_fixture,
            "secret: process.env.JWT_SECRET || 'known-secret',",
            "ts"
        )
        .is_empty());
        let py_fixture = Path::new("/repo/tests/test_settings.py");
        assert!(signing_secret_sink_lines(
            py_fixture,
            "SECRET_KEY = os.getenv('SECRET_KEY', 'known-secret')",
            "py"
        )
        .is_empty());
    }

    #[test]
    fn environment_jwt_secret_is_not_reported() {
        let findings = scan(
            "const secret = process.env.JWT_SECRET;\nconst token = `jwt.${secret}.payload`;",
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn rust_shell_c_with_untrusted_argument_is_reported() {
        let findings = scan(
            r#"Command::new("sh").arg("-c").arg(input).status()?;"#,
            "rs",
        );
        assert_eq!(titles(&findings), vec!["Command Injection"]);
    }

    #[test]
    fn rust_fixed_executable_with_argument_vector_is_clean() {
        let findings = scan(
            r#"let mut cmd = Command::new("/usr/bin/printf");
cmd.arg(input);"#,
            "rs",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn rust_annotated_parse_is_clean() {
        let findings = scan(
            r#"let id: i64 = params.get("id").parse().unwrap_or(0);
let q = format!("SELECT * FROM users WHERE id = {}", id);
conn.execute(q)?;"#,
            "rs",
        );
        assert!(findings.is_empty());
    }
    #[test]
    fn java_runtime_exec_with_composed_shell_command_is_reported() {
        let findings = scan(
            r#"Runtime.getRuntime().exec("sh -c '" + input + "'");"#,
            "java",
        );
        assert_eq!(titles(&findings), vec!["Command Injection"]);
    }

    #[test]
    fn java_process_builder_argument_vector_is_clean() {
        let findings = scan(
            r#"new ProcessBuilder("/usr/bin/printf", input).start();"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_message_digest_md5_is_reported() {
        let findings = scan(
            r#"MessageDigest md = MessageDigest.getInstance("MD5");"#,
            "java",
        );
        assert_eq!(titles(&findings), vec!["Weak Hash Algorithm — MD5"]);
    }

    #[test]
    fn java_message_digest_sha256_is_clean() {
        let findings = scan(
            r#"MessageDigest md = MessageDigest.getInstance("SHA-256");"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_request_path_reaching_open_is_reported() {
        let findings = scan(
            r#"from flask import request
import os
requested = request.args.get("file")
target = os.path.join("uploads", requested)
with open(target, "rb") as handle:
    return handle.read()"#,
            "py",
        );
        assert_eq!(titles(&findings), vec!["Path Traversal"]);
    }

    #[test]
    fn python_basename_sanitized_path_is_clean() {
        let findings = scan(
            r#"from flask import request
import os
requested = os.path.basename(request.args.get("file"))
target = os.path.join("uploads", requested)
with open(target, "rb") as handle:
    return handle.read()"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_pathlib_name_sanitized_path_is_clean() {
        let findings = scan(
            r#"requested = request.args.get("filename")
name = Path(requested).name
content = open(name).read()"#,
            "py",
        );
        assert!(findings.is_empty());
    }
    #[test]
    fn java_request_path_reaching_file_stream_is_reported() {
        let findings = scan(
            r#"String requested = request.getParameter("file");
File target = new File("uploads", requested);
FileInputStream in = new FileInputStream(target);"#,
            "java",
        );
        assert_eq!(titles(&findings), vec!["Path Traversal"]);
    }

    #[test]
    fn java_file_name_sanitized_path_is_clean() {
        let findings = scan(
            r#"String requested = Paths.get(request.getParameter("file")).getFileName().toString();
File target = new File("uploads", requested);
FileInputStream in = new FileInputStream(target);"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_request_path_reaching_read_file_is_reported() {
        let findings = scan(
            r#"requested := r.URL.Query().Get("file")
target := filepath.Join("uploads", requested)
data, err := os.ReadFile(target)"#,
            "go",
        );
        assert_eq!(titles(&findings), vec!["Path Traversal"]);
    }

    #[test]
    fn go_base_sanitized_path_is_clean() {
        let findings = scan(
            r#"requested := filepath.Base(r.URL.Query().Get("file"))
target := filepath.Join("uploads", requested)
data, err := os.ReadFile(target)"#,
            "go",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn md5_function_call_is_still_reported() {
        let findings = scan(
            r#"return hashlib.md5(value.encode("utf-8")).hexdigest();"#,
            "py",
        );
        assert_eq!(titles(&findings), vec!["Weak Hash Algorithm — MD5"]);
    }

    #[test]
    fn python_md5_callable_alias_is_reported() {
        let findings = scan(
            r#"import hashlib
algorithm = hashlib.md5
return algorithm(payload).hexdigest()"#,
            "py",
        );
        assert_eq!(titles(&findings), vec!["Weak Hash Algorithm — MD5"]);
    }

    #[test]
    fn python_sha256_callable_alias_is_clean() {
        let findings = scan(
            r#"import hashlib
algorithm = hashlib.sha256
return algorithm(payload).hexdigest()"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_eval_request_and_function_are_reported_static_is_clean() {
        let findings = scan(
            "eval(req.body.code);\neval(1+2);\nnew Function(req.query.code);",
            "js",
        );
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.title == "Code Injection")
                .count(),
            2
        );
    }

    const SQLI: &str = "SQL Injection — String Concatenation";
    const ORM_RAW: &str = "SQL Injection — ORM Raw Queries";

    #[test]
    fn orm_raw_query_word_boundary_keeps_vendored_draw_calls_clean() {
        let vendored = scan(
            "if (!(this.target = this.$el.simpledraw(this.width, this.height, this.options.get('composite'), interactive))) {\nthis.target = this.$el.simpledraw(width, height, options.get('composite'));\n",
            "js",
        );
        assert!(!titles(&vendored).contains(&ORM_RAW));
        let django = scan(
            "cursor = Model.objects.raw(\"SELECT * FROM app_model\")\n",
            "py",
        );
        assert!(titles(&django).contains(&ORM_RAW));
    }

    #[test]
    fn orm_raw_skips_wrapped_constant_and_empty_calls_but_not_sql_arguments() {
        // Built with format! so the repo's own scan does not see these as calls.
        let call = format!("{}(", "execute_sql");
        let wrapped = format!("x = self.{call}\n    MULTI, chunk=1\n)\n");
        assert!(!titles(&scan(&wrapped, "py")).contains(&ORM_RAW));
        let empty = format!("r = list(self.{call}))\n");
        assert!(!titles(&scan(&empty, "py")).contains(&ORM_RAW));
        // A wrapped call whose first argument is a variable still reports.
        let var = format!("x = self.{call}\n    query, params\n)\n");
        assert!(titles(&scan(&var, "py")).contains(&ORM_RAW));
        let sql = format!("x = self.{call}\"select * from t where a=\" + a)\n");
        assert!(titles(&scan(&sql, "py")).contains(&ORM_RAW));
    }

    #[test]
    fn debug_true_in_django_template_engine_is_not_debug_mode() {
        let debug = "Debug Mode Enabled";
        // Placeholders keep the repo's own scan from reading these fixtures as findings.
        let fx = |t: &str| {
            t.replace("@D", &["debug", "True"].join("="))
                .replace("@S", &["DEBUG", "True"].join(" = "))
        };
        let engine = fx("from django.template import Engine\nDEBUG_ENGINE = Engine(\n    @D,\n    libraries={},\n)\n");
        assert!(!titles(&scan(&engine, "py")).contains(&debug));
        let one = fx("from django.template import Engine\ne = Engine(@D)\n");
        assert!(!titles(&scan(&one, "py")).contains(&debug));
        // The real setting, and other constructors, still report.
        let setting = fx("from django.template import Engine\n@S\n");
        assert!(titles(&scan(&setting, "py")).contains(&debug));
        let app = fx("from django.template import Engine\napp = Flask(__name__)\napp.run(@D)\n");
        assert!(titles(&scan(&app, "py")).contains(&debug));
        let other = fx("from django.template import Engine\nserver = GameEngine(@D)\n");
        assert!(titles(&scan(&other, "py")).contains(&debug));
        let no_django = fx("e = Engine(@D)\n");
        assert!(titles(&scan(&no_django, "py")).contains(&debug));
    }

    #[test]
    fn orm_raw_ignores_docstring_prose_but_not_calls() {
        // Built with format! so the repo's own scan does not see these as calls.
        let call = format!("{}(", "execute_sql");
        let doc = format!(
            "def __iter__(self):\n    \"\"\"\n    1. sql.compiler.{call})\n       - returns rows\n    \"\"\"\n    return x\n"
        );
        assert!(!titles(&scan(&doc, "py")).contains(&ORM_RAW));
        let one_line = format!("def f():\n    \"\"\"Calls {call}) once.\"\"\"\n    return 1\n");
        assert!(!titles(&scan(&one_line, "py")).contains(&ORM_RAW));
        // A real raw-query call after the docstring still reports.
        let real = "def f(self):\n    \"\"\"Run it.\"\"\"\n    return Model.objects.raw(\"SELECT * FROM app_model\")\n";
        assert!(titles(&scan(real, "py")).contains(&ORM_RAW));
        // A triple-quoted string that is an assignment or call argument is not a docstring.
        let src = "q = \"\"\"\nselect 1\n\"\"\"\ndef f():\n    \"\"\"doc\n    more\n    \"\"\"\n    return run('''x''')\n";
        let lines = python_docstring_line_numbers(src, "py");
        let mut got: Vec<usize> = lines.into_iter().collect();
        got.sort();
        assert_eq!(got, vec![5, 6, 7]);
        assert!(python_docstring_line_numbers(src, "rb").is_empty());
    }

    #[test]
    fn python_request_value_built_into_executed_query_is_reported() {
        let findings = scan(
            r#"user_id = request.args.get("id")
query = f"SELECT * FROM users WHERE id = '{user_id}'"
cursor.execute(query)"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn python_request_header_value_built_into_executed_query_is_reported() {
        let findings = scan(
            r#"token = request.headers.get("X-Token")
query = f"SELECT * FROM sessions WHERE token = '{token}'"
cursor.execute(query)"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn python_request_cookie_value_built_into_executed_query_is_reported() {
        let findings = scan(
            r#"sid = request.cookies.get("session_id")
query = f"SELECT * FROM sessions WHERE id = '{sid}'"
cursor.execute(query)"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn python_request_json_value_built_into_executed_query_is_reported() {
        let findings = scan(
            r#"user_id = request.json.get("id")
query = f"SELECT * FROM users WHERE id = '{user_id}'"
cursor.execute(query)"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn python_str_wrapped_request_value_is_reported() {
        let findings = scan(
            r#"q = str(request.args.get("q"))
query = f"SELECT * FROM items WHERE name = '{q}'"
cursor.execute(query)"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn python_int_wrapped_request_value_is_clean() {
        let findings = scan(
            r#"n = int(request.args.get("n"))
query = "SELECT * FROM items WHERE id = " + str(n)
cursor.execute(query)"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_fstring_embedded_request_read_is_reported() {
        let findings = scan(
            r#"query = f"SELECT * FROM users WHERE id = '{request.args.get('id')}'"
cursor.execute(query)"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn python_inline_request_read_at_sink_is_reported() {
        let findings = scan(
            r#"cursor.execute(f"SELECT * FROM users WHERE id = '{request.args.get('id')}'")"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn python_inline_request_read_as_parameter_is_clean() {
        let findings = scan(
            r#"query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (request.args.get("id"),))"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_flask_route_param_reaching_query_is_reported() {
        let findings = scan(
            r#"@app.route("/user/<name>")
def show_user(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn python_flask_int_converter_param_is_clean() {
        let findings = scan(
            r#"@app.route("/user/<int:uid>")
def show_user(uid):
    query = "SELECT * FROM users WHERE id = " + str(uid)
    cursor.execute(query)"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_django_view_kwarg_reaching_query_is_reported() {
        let findings = scan(
            r#"def update_user(request, user_id):
    cursor.execute(f"UPDATE users SET admin = 1 WHERE id = '{user_id}'")"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn python_multiline_execute_percent_format_is_reported() {
        let findings = scan(
            r#"def upload(request, project_id):
    name = request.POST.get('name', False)
    curs = connection.cursor()
    curs.execute(
        "insert into taskManager_file ('name','path','project_id') values ('%s','%s',%s)" %
        (name, upload_path, project_id))"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(4));
    }

    #[test]
    fn python_multiline_fstring_argument_is_reported() {
        let findings = scan(
            r#"def show(request):
    name = request.GET.get('name')
    cursor.execute(
        f"SELECT * FROM users WHERE name = '{name}'"
    )"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn python_multiline_parameterized_execute_is_clean() {
        let findings = scan(
            r#"def upload(request):
    name = request.POST.get('name')
    curs = connection.cursor()
    curs.execute(
        "insert into files ('name') values (%s)",
        (name,),
    )"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_multiline_execute_without_request_input_is_clean() {
        let findings = scan(
            r#"def rebuild():
    curs = connection.cursor()
    curs.execute(
        "insert into t ('name') values ('%s')" %
        (constant_name,))"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_plain_helper_param_is_not_seeded() {
        let findings = scan(
            r#"def build_query(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)"#,
            "py",
        );
        assert!(findings.is_empty());
    }
    #[test]
    fn python_parameterized_query_with_request_value_is_clean() {
        let findings = scan(
            r#"user_id = request.args.get("id")
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_int_converted_request_value_is_clean() {
        let findings = scan(
            r#"user_id = request.args.get("id")
user_id = int(user_id)
query = "SELECT * FROM users WHERE id = " + str(user_id)
cursor.execute(query)"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_uuid_conversion_is_clean() {
        let findings = scan(
            r#"uid = uuid.UUID(request.args.get("id"))
query = f"SELECT * FROM users WHERE id = '{uid}'"
cursor.execute(query)"#,
            "py",
        );
        assert!(findings.is_empty());
    }
    #[test]
    fn python_identifier_only_inside_plain_string_is_clean() {
        let findings = scan(
            r#"name = request.args.get("name")
query = "SELECT name FROM users"
cursor.execute(query)"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_destructured_request_value_in_template_query_is_reported() {
        let findings = scan(
            r#"const { name } = req.query;
const sql = `SELECT * FROM products WHERE name = '${name}'`;
const rows = db.query(sql);"#,
            "js",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn js_destructured_header_value_in_template_query_is_reported() {
        let findings = scan(
            r#"const { host } = req.headers;
const sql = `SELECT * FROM hosts WHERE name = '${host}'`;
const rows = db.query(sql);"#,
            "js",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }
    #[test]
    fn js_request_header_value_in_template_query_is_reported() {
        let findings = scan(
            r#"const host = req.headers.host;
const sql = `SELECT * FROM hosts WHERE name = '${host}'`;
const rows = db.query(sql);"#,
            "js",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn js_request_cookie_value_in_template_query_is_reported() {
        let findings = scan(
            r#"const sid = req.cookies.sid;
const sql = `SELECT * FROM sessions WHERE id = '${sid}'`;
const rows = db.query(sql);"#,
            "js",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn js_string_wrapped_request_value_is_reported() {
        let findings = scan(
            r#"const q = String(req.query.q);
const sql = `SELECT * FROM items WHERE name = '${q}'`;
const rows = db.query(sql);"#,
            "js",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn js_number_wrapped_request_value_is_clean() {
        let findings = scan(
            r#"const n = Number(req.query.n);
const sql = "SELECT * FROM items WHERE id = " + n;
const rows = db.query(sql);"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_template_embedded_request_read_is_reported() {
        let findings = scan(
            r#"const sql = `SELECT * FROM users WHERE id = '${req.query.id}'`;
const rows = db.query(sql);"#,
            "js",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn js_inline_request_read_at_sink_is_reported() {
        let findings = scan(
            r#"const rows = db.query(`SELECT * FROM users WHERE id = '${req.query.id}'`);"#,
            "js",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn js_inline_request_read_as_parameter_is_clean() {
        let findings = scan(
            r#"const rows = db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);"#,
            "js",
        );
        assert!(findings.is_empty());
    }
    #[test]
    fn js_placeholder_query_with_request_value_is_clean() {
        let findings = scan(
            r#"const name = req.query.name;
const sql = "SELECT * FROM products WHERE name = ?";
const rows = db.query(sql, [name]);"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_request_value_concatenated_into_statement_is_reported() {
        let findings = scan(
            r#"String name = request.getParameter("name");
String sql = "SELECT * FROM users WHERE name = '" + name + "'";
ResultSet rs = stmt.executeQuery(sql);"#,
            "java",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn java_query_string_value_concatenated_into_statement_is_reported() {
        let findings = scan(
            r#"String qs = request.getQueryString();
String sql = "SELECT * FROM users WHERE name = '" + qs + "'";
ResultSet rs = stmt.executeQuery(sql);"#,
            "java",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn java_double_parse_is_clean() {
        let findings = scan(
            r#"String s = request.getParameter("score");
double d = Double.parseDouble(s);
String sql = "SELECT * FROM users WHERE score > " + d;
ResultSet rs = stmt.executeQuery(sql);"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_valueof_wrapped_request_value_is_reported() {
        let findings = scan(
            r#"String s = String.valueOf(request.getParameter("q"));
String sql = "SELECT * FROM items WHERE name = '" + s + "'";
ResultSet rs = stmt.executeQuery(sql);"#,
            "java",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn java_parseint_wrapped_request_value_is_clean() {
        let findings = scan(
            r#"int n = Integer.parseInt(request.getParameter("n"));
String sql = "SELECT * FROM items WHERE id = " + n;
ResultSet rs = stmt.executeQuery(sql);"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_concat_embedded_request_read_is_reported() {
        let findings = scan(
            r#"String sql = "SELECT * FROM users WHERE id = '" + request.getParameter("id") + "'";
ResultSet rs = stmt.executeQuery(sql);"#,
            "java",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }
    
