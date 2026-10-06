#[test]
    fn java_prepared_statement_bind_value_is_clean() {
        let findings = scan(
            r#"String name = request.getParameter("name");
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
ps.setString(1, name);
ResultSet rs = ps.executeQuery();"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_sprintf_request_value_in_query_is_reported() {
        let findings = scan(
            r#"name := r.URL.Query().Get("name")
query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
rows, err := db.QueryContext(ctx, query)"#,
            "go",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn go_placeholder_query_with_request_value_is_clean() {
        let findings = scan(
            r#"name := r.URL.Query().Get("name")
rows, err := db.QueryContext(ctx, "SELECT * FROM users WHERE name = $1", name)"#,
            "go",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_atoi_converted_request_value_is_clean() {
        let findings = scan(
            r#"raw := r.URL.Query().Get("id")
id, err := strconv.Atoi(raw)
query := fmt.Sprintf("SELECT * FROM users WHERE id = %d", id)
rows, err := db.Query(query)"#,
            "go",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_sprintf_embedded_request_read_is_reported() {
        let findings = scan(
            r#"query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", r.URL.Query().Get("name"))
rows, err := db.Query(query)"#,
            "go",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn go_inline_request_read_at_sink_is_reported() {
        let findings = scan(
            r#"rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", r.URL.Query().Get("name")))"#,
            "go",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn go_inline_request_read_as_parameter_is_clean() {
        let findings = scan(
            r#"rows, err := db.QueryContext(ctx, "SELECT * FROM users WHERE name = $1", r.URL.Query().Get("name"))"#,
            "go",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_concat_embedded_request_read_is_reported() {
        let findings = scan(
            r#"query := "SELECT * FROM users WHERE name = '" + r.FormValue("name") + "'"
rows, err := db.Query(query)"#,
            "go",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    const CMDI: &str = "Command Injection";

    #[test]
    fn python_request_value_reaching_popen_is_reported() {
        let findings = scan(
            r#"host = request.args.get("host")
cmd = "ping -c 1 " + host
return os.popen(cmd).read()"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![CMDI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn python_subprocess_shell_true_is_reported() {
        let findings = scan(
            r#"host = request.args.get("host")
cmd = f"ping -c 1 {host}"
subprocess.run(cmd, shell=True, check=True)"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![CMDI]);
    }

    #[test]
    fn python_argument_vector_without_shell_is_clean() {
        let findings = scan(
            r#"host = request.args.get("host")
subprocess.run(["ping", "-c", "1", host], check=True)"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_shlex_quoted_value_is_clean() {
        let findings = scan(
            r#"host = shlex.quote(request.args.get("host"))
cmd = "ping -c 1 " + host
os.system(cmd)"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_request_value_reaching_exec_is_reported() {
        let findings = scan(
            r#"const target = req.query.host;
const cmd = "ping -c 1 " + target;
exec(cmd, (err, out) => res.send(out));"#,
            "js",
        );
        assert_eq!(titles(&findings), vec![CMDI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn js_exec_file_argument_vector_is_clean() {
        let findings = scan(
            r#"const target = req.query.host;
execFile("ping", ["-c", "1", target], (err, out) => res.send(out));"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_regex_exec_method_is_not_a_command_sink() {
        let findings = scan(
            r#"const target = req.query.host;
const match = pattern.exec(target);"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_request_value_in_shell_process_builder_is_reported() {
        let findings = scan(
            r#"String host = request.getParameter("host");
String cmd = "ping -c 1 " + host;
Process p = new ProcessBuilder("sh", "-c", cmd).start();"#,
            "java",
        );
        assert_eq!(titles(&findings), vec![CMDI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn java_request_value_in_process_builder_argument_vector_is_clean() {
        let findings = scan(
            r#"String host = request.getParameter("host");
Process p = new ProcessBuilder("ping", "-c", "1", host).start();"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_request_value_in_shell_command_is_reported() {
        let findings = scan(
            r#"host := r.URL.Query().Get("host")
cmd := "ping -c 1 " + host
out, err := exec.Command("sh", "-c", cmd).Output()"#,
            "go",
        );
        assert_eq!(titles(&findings), vec![CMDI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn django_logout_redirect_from_query_is_reported() {
        let exposed = "def logout_view(request):\n    return redirect(request.GET.get('redirect', '/taskManager/'))\n";
        assert_eq!(open_redirect_sink_lines(exposed, "py"), [2].into());
        let safe = "def logout_view(request):\n    return redirect('/taskManager/')\n";
        assert!(open_redirect_sink_lines(safe, "py").is_empty());
        assert!(open_redirect_sink_lines(exposed, "js").is_empty());
    }

    #[test]
    fn go_archive_entry_names_joined_without_containment_check() {
        let hit = |src: &str| !go_archive_entry_join_lines(src, "go").is_empty();
        // cpio, tar and zip iterators joined straight onto the destination.
        assert!(hit(
            "func Extract(rs io.Reader, dest string) error {\n\tfor {\n\t\tentry, err := stream.ReadNextEntry()\n\t\ttarget := path.Join(dest, path.Clean(entry.Header.filename))\n\t}\n}\n"
        ));
        assert!(hit(
            "func untar(r io.Reader, dir string) error {\n\ttr := tar.NewReader(r)\n\tfor {\n\t\thdr, err := tr.Next()\n\t\tp := filepath.Join(dir, hdr.Name)\n\t}\n}\n"
        ));
        assert!(hit(
            "func unzip(z *zip.Reader, dir string) {\n\tfor _, f := range z.File {\n\t\tname := f.Name\n\t\tp := filepath.Join(dir, name)\n\t}\n}\n"
        ));
        // Negative controls: containment check, Base, IsLocal, ".." test.
        assert!(!hit(
            "func untar(r io.Reader, dir string) error {\n\tfor {\n\t\thdr, err := tr.Next()\n\t\tp := filepath.Join(dir, hdr.Name)\n\t\tif !strings.HasPrefix(p, filepath.Clean(dir)+string(os.PathSeparator)) {\n\t\t\treturn errBad\n\t\t}\n\t}\n}\n"
        ));
        assert!(!hit(
            "func untar(r io.Reader, dir string) error {\n\tfor {\n\t\thdr, err := tr.Next()\n\t\tp := filepath.Join(dir, filepath.Base(hdr.Name))\n\t}\n}\n"
        ));
        assert!(!hit(
            "func untar(r io.Reader, dir string) error {\n\tfor {\n\t\thdr, err := tr.Next()\n\t\tif !filepath.IsLocal(hdr.Name) {\n\t\t\tcontinue\n\t\t}\n\t\tp := filepath.Join(dir, hdr.Name)\n\t}\n}\n"
        ));
        assert!(!hit(
            "func untar(r io.Reader, dir string) error {\n\tfor {\n\t\thdr, err := tr.Next()\n\t\tif strings.Contains(hdr.Name, \"..\") {\n\t\t\tcontinue\n\t\t}\n\t\tp := filepath.Join(dir, hdr.Name)\n\t}\n}\n"
        ));
        // Join of unrelated values in a function without an archive iterator.
        assert!(!hit(
            "func cfg(dir, name string) string {\n\treturn filepath.Join(dir, name)\n}\n"
        ));
        // A fixed name from an iterator that is not joined.
        assert!(!hit(
            "func count(tr *tar.Reader) int {\n\tn := 0\n\tfor {\n\t\t_, err := tr.Next()\n\t\tif err != nil {\n\t\t\tbreak\n\t\t}\n\t\tn++\n\t}\n\treturn n\n}\n"
        ));
    }

    #[test]
    fn wrapped_same_file_call_carries_taint_to_the_callee_sink() {
        let lines = |src: &str| {
            let mut v: Vec<usize> = ssrf_sink_lines(src, "py").into_iter().collect();
            v.sort();
            v
        };
        let callee = "def fetch(ids, project, url):\n    with urlopen(url) as f:\n        return f.read()\n\n";
        // One-line call (existing behaviour) and the same call wrapped.
        let one = format!("{callee}def load(request, project):\n    url = request.data.get('url')\n    return fetch([], project, url)\n");
        assert_eq!(lines(&one), vec![2]);
        let wrapped = format!("{callee}def load(request, project):\n    url = request.data.get('url')\n    return fetch(\n        [], project, url\n    )\n");
        assert_eq!(lines(&wrapped), vec![2]);
        // Negative controls: constant argument, untainted position, sanitized argument.
        let constant = format!("{callee}def load(request, project):\n    url = request.data.get('url')\n    return fetch(\n        [], project, 'https://example.com/'\n    )\n");
        assert!(lines(&constant).is_empty());
        let other_position = format!("{callee}def load(request, project):\n    url = request.data.get('url')\n    return fetch(\n        [url], project, 'https://example.com/'\n    )\n");
        assert!(lines(&other_position).is_empty());
        // A wrapped call to a function the file does not define stays quiet.
        let unknown = "def load(request, project):\n    url = request.data.get('url')\n    return helper(\n        [], project, url\n    )\n";
        assert!(lines(unknown).is_empty());
    }

    #[test]
    fn python_connection_sink_moves_to_the_request_call() {
        let lines = |src: &str| {
            let mut v: Vec<usize> = ssrf_sink_lines(src, "py").into_iter().collect();
            v.sort();
            v
        };
        let moved = "def f(request):\n    url = request.GET['url']\n    proto, server, path, query, frag = urlsplit(url)\n    conn = HTTPConnection(server)\n    conn.request('GET', path)\n";
        assert_eq!(lines(moved), vec![5]);
        // No request call on the connection: the constructor line stays.
        let bare = "def f(request):\n    url = request.GET['url']\n    proto, server, path, query, frag = urlsplit(url)\n    conn = HTTPConnection(server)\n";
        assert_eq!(lines(bare), vec![4]);
        // A request on a different variable does not move it.
        let other = "def f(request):\n    url = request.GET['url']\n    proto, server, path, query, frag = urlsplit(url)\n    conn = HTTPConnection(server)\n    other.request('GET', path)\n";
        assert_eq!(lines(other), vec![4]);
        // A fixed host stays quiet.
        let fixed = "def f(request):\n    u = request.GET['u']\n    conn = HTTPConnection('internal.example')\n    conn.request('GET', u)\n";
        assert!(lines(fixed).is_empty());
    }

    #[test]
    fn python_tuple_unpack_of_a_call_carries_request_taint() {
        let hit = |src: &str| !ssrf_sink_lines(src, "py").is_empty();
        assert!(hit(
            "def f(request):\n    url = request.GET['url']\n    proto, server, path, query, frag = urlsplit(url)\n    conn = HTTPConnection(server)\n"
        ));
        assert!(hit(
            "def f(request):\n    u = request.GET['u']\n    (a, b) = parse(u)\n    requests.get(b)\n"
        ));
        // Negative controls.
        // Pairwise assignment is not an unpack: the second name is a constant.
        assert!(!hit(
            "def f(request):\n    u = request.GET['u']\n    a, b = u, 'https://example.com/'\n    requests.get(b)\n"
        ));
        // Unpacking a call that does not involve the request value.
        assert!(!hit(
            "def f(request):\n    u = request.GET['u']\n    host, port = get_config()\n    HTTPConnection(host)\n"
        ));
        // A later reassignment clears the unpacked name.
        assert!(!hit(
            "def f(request):\n    u = request.GET['u']\n    a, b = split(u)\n    b, c = get_config()\n    requests.get(b)\n"
        ));
        // Fixed host connection.
        assert!(!hit(
            "def f(request):\n    u = request.GET['u']\n    conn = HTTPConnection('internal.example')\n    conn.request('GET', u)\n"
        ));
    }

    #[test]
    fn ruby_public_method_parameter_into_kernel_open() {
        let hit = |src: &str| !ruby_parameter_open_lines(src, "rb").is_empty();
        // Positives: Kernel.open and bare open on a public method parameter.
        assert!(hit(
            "class Image\n  def self.open(path_or_url, ext = nil)\n    Kernel.open(path_or_url, 'rb') do |f|\n      read(f)\n    end\n  end\nend\n"
        ));
        assert!(hit(
            "class Jar\n  def save(output, *options)\n    return open(output, 'w') { |io| save(io) }\n  end\nend\n"
        ));
        // Negative controls.
        // Explicit non-Kernel receivers.
        assert!(!hit(
            "class A\n  def f(p)\n    File.open(p, 'rb') { |f| f.read }\n  end\nend\n"
        ));
        assert!(!hit("class A\n  def f(p)\n    URI.open(p)\n  end\nend\n"));
        assert!(!hit("class A\n  def f(p)\n    IO.popen(p)\n  end\nend\n"));
        // Literal path, or an argument that is not a parameter.
        assert!(!hit(
            "class A\n  def f(p)\n    open('data.txt')\n  end\nend\n"
        ));
        assert!(!hit(
            "class A\n  def f(p)\n    q = clean(p)\n    open(q)\n  end\nend\n"
        ));
        // Private, protected and underscore methods.
        assert!(!hit(
            "class A\n  private\n  def f(p)\n    open(p)\n  end\nend\n"
        ));
        assert!(!hit(
            "class A\n  protected\n  def f(p)\n    open(p)\n  end\nend\n"
        ));
        assert!(!hit("class A\n  def _f(p)\n    open(p)\n  end\nend\n"));
        assert!(!hit(
            "class A\n  private def f(p)\n    open(p)\n  end\nend\n"
        ));
        // Public again after `private`.
        assert!(hit("class A\n  private\n  def g(x)\n    x\n  end\n  public\n  def f(p)\n    open(p)\n  end\nend\n"));
        // A leading-pipe check clears it.
        assert!(!hit(
            "class A\n  def f(p)\n    raise 'no' if p.start_with?('|')\n    open(p)\n  end\nend\n"
        ));
        // A file that defines its own `open`: a bare open is that method.
        assert!(!hit(
            "class Bib\n  def self.open(path)\n    parse(open(path))\n  end\nend\n"
        ));
        assert!(hit(
            "class Bib\n  def self.open(path)\n    parse(Kernel.open(path, 'r'))\n  end\nend\n"
        ));
    }

    #[test]
    fn java_public_method_string_parameter_appended_into_sql_builder() {
        let hit = |src: &str| !java_sql_append_lines(src, "java").is_empty();
        let method = |vis: &str, ty: &str, body: &str| {
            format!(
                "class Dao {{\n    {vis} List<Row> find(long from, {ty} keyword) throws IOException {{\n        StringBuilder sql = new StringBuilder();\n        List<Object> parameters = new ArrayList<>();\n        sql.append(\"select * from t where 1=1 \");\n{body}\n        try (Connection c = client.getConnection()) {{\n            return client.executeQuery(c, sql.toString(), parameters.toArray());\n        }}\n    }}\n}}\n"
            )
        };
        let concat = "        sql.append(\" and name like '%\").append(keyword).append(\"%' \");";
        let plus = "        sql.append(\" and name like '%\" + keyword + \"%'\");";
        assert!(hit(&method("public", "String", concat)));
        assert!(hit(&method("public", "String", plus)));
        // Multi-line statement.
        assert!(hit(&method(
            "public",
            "String",
            "        sql.append(\" and name = '\")\n            .append(keyword).append(\"'\");"
        )));
        // Bound parameter (the SkyWalking fix): never appended.
        assert!(!hit(&method("public", "String", "        sql.append(\" and name like concat('%',?,'%') \");\n        parameters.add(keyword);")));
        // Private method, numeric parameter, escaped value.
        assert!(!hit(&method("private", "String", concat)));
        assert!(!hit(&method("public", "int", concat)));
        assert!(!hit(&method("public", "Long", concat)));
        assert!(!hit(&method(
            "public",
            "String",
            &format!("        keyword = escape(keyword);\n{concat}")
        )));
        // Appended text is not a parameter, or the builder is not SQL.
        assert!(!hit(&method(
            "public",
            "String",
            "        sql.append(\" and name = 'x' \");"
        )));
        assert!(!hit("class A {\n    public String join(String name) {\n        StringBuilder sb = new StringBuilder();\n        sb.append(\"hello \").append(name);\n        return sb.toString();\n    }\n}\n"));
        // No database call in the method.
        assert!(!hit("class A {\n    public String label(String name) {\n        StringBuilder sb = new StringBuilder();\n        sb.append(\"select from where \").append(name);\n        return sb.toString();\n    }\n}\n"));
    }

    #[test]
    fn python_git_argv_value_from_parameter_without_separator() {
        let hit = |src: &str| !python_git_option_injection_lines(src, "py").is_empty();
        let class = |call: &str| {
            format!(
                "import subprocess\n\nclass Puller:\n    def __init__(self, git_url, repo_dir):\n        self.git_url = git_url\n        self.repo_dir = repo_dir\n\n    def resolve(self):\n        return subprocess.run(\n            {call},\n            capture_output=True,\n        )\n"
            )
        };
        assert!(hit(&class(
            r#"["git", "ls-remote", "--symref", self.git_url, "HEAD"]"#
        )));
        assert!(hit(&class(
            r#"["git", "clone", self.git_url, self.repo_dir]"#
        )));
        // `--` ends option parsing.
        assert!(!hit(&class(r#"["git", "ls-remote", "--", self.git_url]"#)));
        // Field not taken from a parameter, or a fixed URL.
        assert!(!hit(&class(r#"["git", "ls-remote", self.other]"#)));
        assert!(!hit(&class(
            r#"["git", "ls-remote", "https://example.com/r.git"]"#
        )));
        assert!(!hit(&class(r#"["git", "status", self.git_url]"#)));
        // Private method and explicit leading-dash check stay quiet.
        assert!(!hit(
            &class(r#"["git", "ls-remote", self.git_url]"#).replace("def resolve", "def _resolve")
        ));
        assert!(!hit(&format!(
            "{}\n# if url.startswith('-'): raise\nx = url.startswith(\"-\")\n",
            class(r#"["git", "ls-remote", self.git_url]"#)
        )));
        // Direct parameter of a public function.
        assert!(hit("import subprocess\n\ndef remote_heads(url):\n    return subprocess.run([\"git\", \"ls-remote\", url])\n"));
        assert!(!hit("import subprocess\n\ndef remote_heads(url):\n    return subprocess.run([\"git\", \"ls-remote\", \"--\", url])\n"));
    }

    #[test]
    fn ruby_public_method_parameter_into_shell_string() {
        let hit = |src: &str| !ruby_parameter_shell_lines(src, "rb").is_empty();
        // Positives: backtick through a local, system with interpolation, %x.
        assert!(hit(
            "class Fs\n  def ls(ftp_path, option)\n    path = expand(ftp_path)\n    filename = File.basename(path)\n    command = [\n      'ls',\n      option,\n      filename,\n    ].compact.join(' ')\n    `#{command}`\n  end\nend\n"
        ));
        assert!(hit(
            "class A\n  def run(name)\n    system(\"convert #{name} out.png\")\n  end\nend\n"
        ));
        assert!(hit(
            "class A\n  def run(name)\n    %x(identify #{name})\n  end\nend\n"
        ));
        assert!(hit(
            "class A\n  def run(name)\n    cmd = 'ls ' + name\n    system(cmd)\n  end\nend\n"
        ));
        // Negative controls.
        // Fixed command, no parameter.
        assert!(!hit("class A\n  def run(name)\n    `uptime`\n  end\nend\n"));
        // Argument-vector system is not a shell string.
        assert!(!hit(
            "class A\n  def run(name)\n    system('convert', name, 'out.png')\n  end\nend\n"
        ));
        // Shell-escaped, numeric and Shellwords handling.
        assert!(!hit(
            "class A\n  def run(name)\n    `ls #{name.shellescape}`\n  end\nend\n"
        ));
        assert!(!hit(
            "class A\n  def run(name)\n    `ls #{Shellwords.escape(name)}`\n  end\nend\n"
        ));
        assert!(!hit(
            "class A\n  def run(count)\n    `head -n #{count.to_i} log`\n  end\nend\n"
        ));
        // Local reassigned to a constant before the sink.
        assert!(!hit("class A\n  def run(name)\n    arg = name\n    arg = 'safe'\n    `ls #{arg}`\n  end\nend\n"));
        // Private, protected and underscore methods.
        assert!(!hit(
            "class A\n  private\n  def run(name)\n    `ls #{name}`\n  end\nend\n"
        ));
        assert!(!hit(
            "class A\n  def _run(name)\n    `ls #{name}`\n  end\nend\n"
        ));
        // A splatted argument list is an argument vector (Jekyll's Exec.run).
        assert!(!hit(
            "module Exec\n  def run(*args)\n    stdin, stdout = Open3.popen3(*args)\n  end\nend\n"
        ));
        assert!(!hit(
            "class A\n  def run(*args)\n    system(*args)\n  end\nend\n"
        ));
        // Backticks and `system(` inside quoted messages or heredocs are text.
        assert!(!hit("class A\n  def f(name)\n    raise ArgumentError, \"model aliases `#{name}`, not an attribute\"\n  end\nend\n"));
        assert!(!hit("class A\n  def f(name)\n    @q[name] ||= \"`#{name.to_s.gsub('`', '``')}`\".freeze\n  end\nend\n"));
        assert!(!hit("class A\n  def f(name, type)\n    super <<~EOS\n      Column `#{name}` of type #{type} is bad\n    EOS\n  end\nend\n"));
        assert!(!hit(
            "class A\n  def f(name)\n    msg = \"call system(#{name}) later\"\n  end\nend\n"
        ));
        // A nested class does not reset an outer `private` (Rails AppBase shape).
        assert!(!hit("class AppBase\n  private\n    class Entry < Struct.new(:a)\n      def x\n      end\n    end\n\n    def capture_command(command, pattern = nil)\n      output = `#{command}`\n    end\nend\n"));
        assert!(hit("class AppBase\n  class Entry < Struct.new(:a)\n  end\n  def capture_command(command)\n    `#{command}`\n  end\nend\n"));
        // Interpolated value unrelated to any parameter.
        assert!(!hit(
            "class A\n  def run(name)\n    dir = Dir.pwd\n    `ls #{dir}`\n  end\nend\n"
        ));
    }

    #[test]
    fn go_argument_vector_command_is_clean() {
        let findings = scan(
            r#"host := r.URL.Query().Get("host")
out, err := exec.Command("ping", "-c", "1", host).Output()"#,
            "go",
        );
        assert!(findings.is_empty());
    }

    const SSRF: &str = "Server-Side Request Forgery (SSRF)";

    const OPEN_REDIRECT: &str = "Open Redirect";

    const REDOS: &str = "Regular Expression Denial of Service (ReDoS)";
    const PLAINTEXT_STORAGE: &str = "Plaintext Password Storage";
    const PLAINTEXT_COMPARE: &str = "Plaintext Password Comparison";

    #[test]
    fn nodegoat_nested_regex_on_destructured_body_is_reported_at_declaration() {
        let findings = scan(
            "const { bankRouting } = req.body;\nconst regexPattern = /([0-9]+)+\\#/;\nconst match = regexPattern.test(bankRouting);",
            "js",
        );
        let redos: Vec<_> = findings.iter().filter(|f| f.title == REDOS).collect();
        assert_eq!(redos.len(), 1);
        assert_eq!(redos[0].line_number, Some(2));
    }

    #[test]
    fn nodegoat_plaintext_password_store_and_compare_are_exact() {
        let findings = scan(
            "const usersCol = db.collection('users');\nthis.addUser = (password) => {\n  const user = {\n    userName,\n    password // from request\n    /* password: bcrypt.hashSync(password, salt) */\n  };\n  usersCol.insert(user);\n};\nthis.validateLogin = () => {\n  const comparePassword = (fromDB, fromUser) => {\n    return fromDB === fromUser;\n    /* return bcrypt.compareSync(fromDB, fromUser); */\n  };\n  if (comparePassword(password, user.password)) return user;\n};",
            "js",
        );
        let storage: Vec<_> = findings
            .iter()
            .filter(|f| f.title == PLAINTEXT_STORAGE)
            .collect();
        let compare: Vec<_> = findings
            .iter()
            .filter(|f| f.title == PLAINTEXT_COMPARE)
            .collect();
        assert_eq!(storage.len(), 1);
        assert_eq!(storage[0].line_number, Some(5));
        assert_eq!(compare.len(), 1);
        assert_eq!(compare[0].line_number, Some(12));
    }

    #[test]
    fn safe_regex_hashing_and_non_password_comparisons_are_clean() {
        for source in [
            "const { bankRouting } = req.body;\nconst regexPattern = /([0-9]+)\\#/;\nregexPattern.test(bankRouting);",
            "const regexPattern = /([0-9]+)+\\#/;\nregexPattern.test('123#');",
            "const regexPattern = /([0-9]+)+\\#/;\nconst bankRouting = '123#';\nregexPattern.test(bankRouting);",
            "// const regexPattern = /([0-9]+)+\\#/;\n// regexPattern.test(req.body.bankRouting);",
            "const user = { password: bcrypt.hashSync(password, salt) };\nusersCol.insert(user);",
            "const user = { password };\nreturn user;",
            "const comparePassword = (fromDB, fromUser) => bcrypt.compareSync(fromDB, fromUser);\nif (comparePassword(password, user.password)) return user;",
            "const comparePassword = (fromDB, fromUser) => fromDB === fromUser;\nif (user.password) return user;",
        ] {
            let findings = scan(source, "js");
            assert!(!findings.iter().any(|f| [REDOS, PLAINTEXT_STORAGE, PLAINTEXT_COMPARE].contains(&f.title.as_str())), "{source}");
        }
    }

    #[test]
    fn nodegoat_documented_needle_url_flow_is_ssrf_on_exact_sink_line() {
        let findings = scan(
            "const needle = require('needle');\nfunction research(req, res) {\n  if (req.query.symbol) {\n    const url = req.query.url + req.query.symbol;\n    return needle.get(url, (err, response) => response);\n  }\n}",
            "js",
        );
        let ssrf: Vec<_> = findings.iter().filter(|f| f.title == SSRF).collect();
        assert_eq!(ssrf.len(), 1);
        assert_eq!(ssrf[0].line_number, Some(5));
    }

    #[test]
    fn express_request_controlled_redirect_is_reported_at_sink() {
        let findings = scan(
            "app.get('/learn', (req, res) => {\n  return res.redirect(req.query.url);\n});",
            "js",
        );
        let redirect: Vec<_> = findings
            .iter()
            .filter(|f| f.title == OPEN_REDIRECT)
            .collect();
        assert_eq!(redirect.len(), 1);
        assert_eq!(redirect[0].line_number, Some(2));
    }

    #[test]
    fn redirect_alias_and_status_overload_are_traced_in_typescript() {
        let findings = scan(
            "const target = req.body.next;\nres.redirect(302, target);",
            "ts",
        );
        assert_eq!(titles(&findings), vec![OPEN_REDIRECT]);
        assert_eq!(findings[0].line_number, Some(2));
    }

    #[test]
    fn fixed_redirects_and_unrelated_request_parameters_are_clean() {
        for source in [
            "res.redirect('/login');",
            "const id = req.query.id; res.redirect('/dashboard');",
            "const url = req.query.url; res.redirect('/login');",
            "res.redirect(req.query.url, '/safe');",
            "const url = req.query.url; needle.get('https://example.com', { headers: { url } });",
        ] {
            let findings = scan(source, "js");
            assert!(
                !findings
                    .iter()
                    .any(|f| f.title == OPEN_REDIRECT || f.title == SSRF),
                "{source}"
            );
        }
    }

    #[test]
    fn python_request_url_reaching_requests_get_is_reported() {
        let findings = scan(
            r#"target = request.args.get("url")
endpoint = target + "/status"
resp = requests.get(endpoint, timeout=5)"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![SSRF]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn python_request_value_as_query_param_of_fixed_url_is_clean() {
        let findings = scan(
            r#"term = request.args.get("q")
resp = requests.get("https://api.example.com/search", params={"q": term})"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_request_url_reaching_fetch_is_reported() {
        let findings = scan(
            r#"const target = req.query.url;
const endpoint = `${target}/status`;
const resp = await fetch(endpoint);"#,
            "js",
        );
        assert_eq!(titles(&findings), vec![SSRF]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn js_request_value_in_body_of_fixed_url_is_clean() {
        let findings = scan(
            r#"const term = req.query.q;
const resp = await fetch("https://api.example.com/search", { method: "POST", body: term });"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_request_url_reaching_new_url_is_reported() {
        let findings = scan(
            r#"String target = request.getParameter("url");
URL endpoint = new URL(target);
HttpURLConnection conn = (HttpURLConnection) endpoint.openConnection();"#,
            "java",
        );
        assert_eq!(titles(&findings), vec![SSRF]);
        assert_eq!(findings[0].line_number, Some(2));
    }

    #[test]
    fn java_request_value_posted_to_fixed_url_is_clean() {
        let findings = scan(
            r#"String term = request.getParameter("q");
String body = restTemplate.postForObject("https://api.example.com/search", term, String.class);"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_request_url_reaching_new_request_is_reported() {
        let findings = scan(
            r#"target := r.URL.Query().Get("url")
req, err := http.NewRequestWithContext(ctx, "GET", target, nil)"#,
            "go",
        );
        assert_eq!(titles(&findings), vec![SSRF]);
    }

    #[test]
    fn go_request_value_in_body_of_fixed_url_is_clean() {
        let findings = scan(
            r#"term := r.URL.Query().Get("q")
req, err := http.NewRequest("POST", "https://api.example.com/search", strings.NewReader(term))"#,
            "go",
        );
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn review_attaches_nodegoat_paths_only_for_proven_sinks() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-nodegoat-path-{nonce}"));
        fs::create_dir_all(root.join("app/routes")).unwrap();
        fs::create_dir_all(root.join("app/data")).unwrap();
        fs::write(
            root.join("app/routes/contributions.js"),
            r#"function ContributionsHandler() {
  this.update = (req) => {
    const before = eval(req.body.before);
    const after = eval(req.body.after);
    const amount = eval(req.body.amount);
    const safe = eval('2 + 2');
  };
}"#,
        )
        .unwrap();
        fs::write(
            root.join("app/routes/allocations.js"),
            r#"const AllocationsDAO = require('../data/allocations-dao').AllocationsDAO;
function AllocationsHandler(db) {
  const allocationsDAO = new AllocationsDAO(db);
  this.display = (req) => {
    const {
      threshold
    } = req.query;
    allocationsDAO.getByUserIdAndThreshold(req.session.userId, threshold, callback);
  };
}"#,
        )
        .unwrap();
        fs::write(
            root.join("app/data/allocations-dao.js"),
            r#"const AllocationsDAO = function(db) {
  this.getByUserIdAndThreshold = (userId, threshold, callback) => {
    const parsedUserId = parseInt(userId);
    const searchCriteria = () => {
      return {
        $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
      };
    };
    return db.collection('allocations').find(searchCriteria());
  };
};
exports.AllocationsDAO = AllocationsDAO;"#,
        )
        .unwrap();
        let report = collect_review_findings(&root, false, None).await.unwrap();
        for line in [3, 4, 5] {
            let finding = report
                .findings
                .iter()
                .find(|f| {
                    f.title == "Code Injection"
                        && f.file_path
                            .as_deref()
                            .is_some_and(|p| p.ends_with("contributions.js"))
                        && f.line_number == Some(line)
                })
                .expect("direct eval finding");
            let steps = finding.source_to_sink.as_ref().expect("direct path");
            assert_eq!(steps.first().unwrap().line, line);
            assert_eq!(steps.last().unwrap().line, line);
        }
        let where_finding = report
            .findings
            .iter()
            .find(|f| {
                f.title == NOSQL_WHERE_TITLE
                    && f.cwe_id.as_deref() == Some("CWE-943")
                    && f.file_path
                        .as_deref()
                        .is_some_and(|p| p.ends_with("allocations-dao.js"))
                    && f.line_number == Some(6)
            })
            .expect("where finding");
        let steps = where_finding
            .source_to_sink
            .as_ref()
            .expect("cross-file path");
        assert!(steps.first().unwrap().file.ends_with("allocations.js"));
        assert_eq!(steps.first().unwrap().line, 7);
        assert_eq!(steps.last().unwrap().line, 6);
        assert!(steps
            .iter()
            .any(|s| s.action == "call" && s.file.ends_with("allocations.js")));
        assert!(report.findings.iter().all(|f| f
            .file_path
            .as_deref()
            .is_none_or(|p| !p.ends_with("contributions.js"))
            || f.line_number != Some(6)
            || f.source_to_sink.is_none()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nodegoat_constructor_arrow_where_sink_reached_across_files() {
        let route = r#"const AllocationsDAO = require('../data/allocations-dao').AllocationsDAO;
class AllocationsHandler {
  constructor(db) {
    const allocationsDAO = new AllocationsDAO(db);
    this.displayAllocations = (req, res, next) => {
      const {
        threshold
      } = req.query;
      allocationsDAO.getByUserIdAndThreshold(req.session.userId, threshold, callback);
    };
  }
}"#;
        let dao = r#"const AllocationsDAO = function(db) {
  this.getByUserIdAndThreshold = (userId, threshold, callback) => {
    const parsedUserId = parseInt(userId);
    const searchCriteria = () => {
      if (threshold) {
        return {
          $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
        };
      }
    };
    return db.collection('allocations').find(searchCriteria());
  };
}
exports.AllocationsDAO = AllocationsDAO;"#;
        let found = scan_project(&[
            ("app/routes/allocations.js", route),
            ("app/data/allocations-dao.js", dao),
        ]);
        assert!(
            found.contains(&(
                "app/data/allocations-dao.js".to_string(),
                NOSQL_WHERE_TITLE.to_string(),
                7
            )),
            "{found:?}"
        );
    }

    #[test]
    fn js_multiline_request_destructure_only_seeds_request_values() {
        let unsafe_findings = scan(
            "const {\n  term\n} = req.query;\ndb.query(`SELECT * FROM users WHERE name = '${term}'`);",
            "js",
        );
        assert_eq!(titles(&unsafe_findings), vec![SQLI_FLOW]);
        let safe_findings = scan(
            "const {\n  term\n} = trustedOptions;\ndb.query(`SELECT * FROM users WHERE name = '${term}'`);",
            "js",
        );
        assert!(safe_findings.is_empty(), "{safe_findings:?}");
    }

    #[test]
    fn js_property_require_instance_call_is_reported_in_service() {
        let route = r#"const Repo = require('../services/repo').Repo;
function Handler() {
    const repo = new Repo();
    this.search = (req, res) => {
        const { name } = req.query;
        return res.json(repo.findByName(name));
    };
}"#;
        let repo = r#"function Repo() {
    this.findByName = (name) => {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    };
}
exports.Repo = Repo;"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/repo.js", repo),
        ]);
        assert_eq!(
            found,
            vec![("src/services/repo.js".to_string(), SQLI_FLOW.to_string(), 4)]
        );
    }

    #[test]
    fn literal_only_log_and_cli_flag_credential_are_not_findings() {
        // Suppressed: fixed-string log, and an option-name map entry.
        let findings = scan(
            "if (GITHUB_TOKEN) {\n  console.log(`[GITHUB_TOKEN OK]`);\n}",
            "js",
        );
        assert!(findings.is_empty(), "{findings:?}");
        let findings = scan("cli_arg_map = {\n  password: \"--password\",\n}", "rb");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn logging_a_secret_value_and_real_credentials_still_fire() {
        // Negative controls: interpolation, concatenation and a second
        // argument all log the value; a real password literal still fires.
        for code in [
            "console.log(`token ${token}`);",
            "console.log('token ' + token);",
            "console.log('token', token);",
            "console.log(token);",
        ] {
            let findings = scan(code, "js");
            assert!(
                findings
                    .iter()
                    .any(|f| f.title == "Sensitive Data in Logging"),
                "{code}: {findings:?}"
            );
        }
        let findings = scan("config = {\n  password: \"hunter2hunter2\",\n}", "rb");
        assert!(
            findings.iter().any(|f| f.title == "Hardcoded Credentials"),
            "{findings:?}"
        );
        let findings = scan("config = {\n  password: \"--hunter2\",\n}", "rb");
        assert!(
            findings.iter().any(|f| f.title == "Hardcoded Credentials"),
            "{findings:?}"
        );
    }

    #[test]
    fn js_commented_where_is_not_a_sink() {
        let findings = scan(
            "const threshold = req.query.threshold;\n/*\nreturn {$where: `${threshold}`};\n*/",
            "js",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn js_where_is_reported_as_nosql_injection() {
        let findings = scan(
            "const threshold = req.query.threshold;\nreturn {$where: `${threshold}`};",
            "js",
        );
        assert_eq!(titles(&findings), vec![NOSQL_WHERE_TITLE]);
        assert_eq!(findings[0].cwe_id.as_deref(), Some("CWE-943"));
    }

    
