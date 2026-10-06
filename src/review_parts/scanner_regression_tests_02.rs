#[test]
    fn django_modelform_exclude_missing_privilege_flag_is_reported() {
        let forms = r#"class UserForm(forms.ModelForm):
    """ User registration form """
    class Meta:
        model = User
        exclude = ['groups', 'user_permissions', 'last_login', 'date_joined', 'is_active']


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password')


class CompleteForm(forms.ModelForm):
    class Meta:
        model = User
        exclude = ['is_superuser', 'is_staff', 'groups']


class OtherForm(forms.ModelForm):
    class Meta:
        model = Project
        exclude = ['owner']
"#;
        let sinks = django_modelform_exclude_lines(forms, "py");
        assert_eq!(sinks, [5].into_iter().collect());
        assert!(django_modelform_exclude_lines(forms, "rb").is_empty());
        assert!(django_modelform_exclude_lines("exclude = ['x']", "py").is_empty());
    }

    #[test]
    fn django_privilege_mutation_without_role_check_is_reported() {
        let views = r#"def manage_groups(request):
    user = request.user
    if user.is_authenticated():
        if request.method == 'POST':
            post_data = request.POST.dict()
            grp = Group.objects.get(name=post_data["accesslevel"])
            specified_user = User.objects.get(pk=post_data["userid"])
            specified_user.groups.add(grp)
            specified_user.save()


def admin_only(request):
    user = request.user
    if user.is_authenticated() and user.is_staff:
        target = User.objects.get(pk=1)
        target.groups.add(Group.objects.get(name='admin_g'))


def readonly(request):
    if request.user.is_authenticated():
        return Group.objects.all()


def get_checked_post_not(request):
    user = request.user
    if user.is_authenticated():
        if request.method == 'POST':
            target = User.objects.get(pk=1)
            target.groups.add(Group.objects.get(name='admin_g'))
        else:
            if user.has_perm('can_change_group'):
                return Group.objects.all()
"#;
        let sinks = django_missing_role_check_lines(views, "py");
        assert_eq!(sinks, [8, 29].into_iter().collect());
        assert!(django_missing_role_check_lines(views, "rb").is_empty());
    }

    #[test]
    fn django_orm_get_by_url_param_without_ownership_filter_is_reported() {
        let views = r#"def upload(request, project_id):
    proj = Project.objects.get(pk=project_id)
    return render(request, 'u.html')

def details(request, project_id):
    proj = Project.objects.filter(
        users_assigned=request.user.id,
        pk=project_id)
    if not proj:
        return redirect('/')
    proj = Project.objects.get(pk=project_id)
    return render(request, 'd.html')

def task_details(request, task_id):
    task = Task.objects.get(pk=task_id)
    ok = task.users_assigned.filter(username=request.user.username).exists()
    return render(request, 't.html', {'ok': ok})

def assign(request, project_id):
    userid = request.POST.get("userid")
    user = User.objects.get(pk=userid)
    # proj = Project.objects.get(pk=project_id)
    return redirect('/')
"#;
        let sinks = django_idor_sink_lines(views, "py");
        assert!(sinks.contains(&2));
        assert_eq!(sinks.len(), 1);
        assert!(django_idor_sink_lines(views, "js").is_empty());
    }

    /// Directories above the scan root are where the project was checked out,
    /// not part of the project: a checkout under `.../cache/` must report the
    /// same findings as one anywhere else, while a `cache` directory inside
    /// the project still marks a trusted store.
    #[test]
    fn library_parameter_shell_sinks_fire_only_when_composed_and_public() {
        let hit = |ext: &str, src: &str| !library_parameter_command_lines(src, ext).is_empty();
        // Positive: public JS function composes its parameter into exec.
        assert!(hit(
            "js",
            "module.exports = function (iface, callback) {\n  exec(\"ifconfig \" + iface, function (e, out) {});\n};\n"
        ));
        assert!(hit(
            "js",
            "export function ping(host) {\n  const cmd = `ping -c1 ${host}`;\n  execSync(cmd);\n}\n"
        ));
        // Positive: public Python function, os.system with a formatted string.
        assert!(hit(
            "py",
            "def run(path):\n    os.system('cat %s' % path)\n"
        ));
        // Positive: exported Go function, bash -c with Sprintf of the parameter.
        assert!(hit(
            "go",
            "func HasImage(path string) bool {\n\tcmd := \"pdffonts %s\"\n\tout, _ := exec.Command(\"bash\", \"-c\", fmt.Sprintf(cmd, path)).Output()\n\treturn len(out) > 0\n}\n"
        ));
        // Negative controls.
        // Build-tool task scripts are not a library boundary.
        assert!(!hit(
            "js",
            "module.exports = function (grunt) {\n  grunt.registerTask('x', function (arg) {\n    exec('node ' + arg);\n  });\n};\n"
        ));
        // Fixed command, no parameter.
        assert!(!hit(
            "js",
            "module.exports = function (cb) {\n  exec('uptime', cb);\n};\n"
        ));
        // Parameter is not part of the command text.
        assert!(!hit(
            "js",
            "module.exports = function (iface, cb) {\n  exec('uptime', function () { cb(iface); });\n};\n"
        ));
        // Shell-quoted parameter.
        assert!(!hit(
            "py",
            "def run(path):\n    os.system('cat ' + shlex.quote(path))\n"
        ));
        assert!(!hit(
            "js",
            "module.exports = function (p) {\n  exec('ls ' + shellQuote(p));\n};\n"
        ));
        // Not public: underscore Python helper, lower-case Go func, unexported JS function.
        assert!(!hit(
            "py",
            "def _run(path):\n    os.system('cat ' + path)\n"
        ));
        assert!(!hit(
            "go",
            "func run(path string) {\n\texec.Command(\"bash\", \"-c\", \"cat \"+path).Run()\n}\n"
        ));
        assert!(!hit("js", "function helper(p) {\n  exec('ls ' + p);\n}\n"));
        // Fixed argv call is safe even with a parameter.
        assert!(!hit(
            "py",
            "def run(path):\n    subprocess.run(['cat', path])\n"
        ));
        assert!(hit(
            "py",
            "def run(path):\n    subprocess.run('cat ' + path, shell=True)\n"
        ));
        assert!(!hit(
            "py",
            "def run(path):\n    subprocess.run('cat ' + path)\n"
        ));
    }

    #[test]
    fn path_context_rules_ignore_directories_above_the_scan_root() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("cipher-rootrel-{nonce}"));
        let source = "def reset_password
  user = Marshal.load(Base64.decode64(params[:user]))
end
";
        let patterns = build_vuln_patterns();
        let reports = |root: &Path, relative: &str| {
            let file = root.join(relative);
            fs::create_dir_all(file.parent().expect("parent")).expect("mkdir");
            fs::write(&file, source).expect("write");
            scan_file_for_vulns_with(&file, &patterns, None, Some(root))
                .iter()
                .any(|f| f.title == "Insecure Deserialization")
        };
        // Checkout lives under a directory named `cache`: still reported.
        let under_cache = base.join("cache").join("project");
        assert!(reports(
            &under_cache,
            "app/controllers/password_resets_controller.rb"
        ));
        // Same file in a checkout with a neutral parent: reported.
        let neutral = base.join("neutral").join("project");
        assert!(reports(
            &neutral,
            "app/controllers/password_resets_controller.rb"
        ));
        // Negative control: a cache directory INSIDE the project is a trusted
        // store and stays suppressed.
        assert!(!reports(&neutral, "lib/cache/entry_loader.rb"));
        // Checkout under `tests/`: test-directory exemptions do not apply to
        // the project, so a real finding is still produced.
        let under_tests = base.join("tests").join("project");
        assert!(reports(&under_tests, "app/controllers/other_controller.rb"));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn go_log_printf_with_password_arg_is_reported() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-go-cred-log-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        let file = root.join("auth.go");
        let patterns = build_vuln_patterns();
        fs::write(
            &file,
            r#"func Login(w http.ResponseWriter, r *http.Request) {
password := r.FormValue("password")
log.Printf("Login attempt: username=%s password=%s", username, password)
}"#,
        )
        .unwrap();
        let findings = scan_file_for_vulns(&file, &patterns);
        assert!(findings
            .iter()
            .any(|f| f.title == "Sensitive Data in Logging" && f.line_number == Some(3)));
        fs::write(
            &file,
            r#"func Login(w http.ResponseWriter, r *http.Request) {
log.Printf("login ok for %s", username)
}"#,
        )
        .unwrap();
        let findings = scan_file_for_vulns(&file, &patterns);
        assert!(!findings
            .iter()
            .any(|f| f.title == "Sensitive Data in Logging"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn go_signing_secret_requires_literal_decl_and_signedstring_use() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-go-jwt-secret-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        let file = root.join("jwt.go");
        let used = r#"package handlers
var jwtSecret = []byte("secret")
func sign(token *jwt.Token) (string, error) {
return token.SignedString(jwtSecret)
}"#;
        assert_eq!(signing_secret_sink_lines(&file, used, "go"), [2].into());
        let unused = r#"package handlers
var jwtSecret = []byte("secret")
func sign(token *jwt.Token) (string, error) {
return token.SignedString(os.Getenv("JWT_KEY"))
}"#;
        assert!(signing_secret_sink_lines(&file, unused, "go").is_empty());
        let env = r#"package handlers
var jwtSecret = []byte(os.Getenv("JWT_SECRET"))
func sign(token *jwt.Token) (string, error) {
return token.SignedString(jwtSecret)
}"#;
        assert!(signing_secret_sink_lines(&file, env, "go").is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rails_ssn_client_mask_requires_active_html_and_route() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-rails-ssn-mask-{nonce}"));
        let view = root.join("app/views/work_info/index.html.erb");
        let ctl = root.join("app/controllers/work_info_controller.rb");
        let routes = root.join("config/routes.rb");
        for path in [&view, &ctl, &routes] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
        }
        let html = "<td class=\"ssn\"><%= @user.work_info.SSN %></td>\n<!--<td class=\"ssn\"><%#= @user.work_info.last_four %></td>-->\n<script>function maskSSN(){ var fullSSN = $(\"td.ssn\").html().replace(/\\d{3}.*?\\d{2}/, \"*****\"); $(\"td.ssn\").html(fullSSN); } $(document).ready(function(){maskSSN()});</script>\n";
        fs::write(&view, html).unwrap();
        fs::write(&ctl, "class WorkInfoController < ApplicationController\n def index\n  @user = User.find_by(id: params[:user_id])\n end\nend\n").unwrap();
        fs::write(&routes, "resources :users do\n resources :work_info\nend\n").unwrap();
        let patterns = build_vuln_patterns();
        let detect = || scoped_rails_ssn_client_mask(&root, &patterns);
        assert_eq!(detect()[0].line_number, Some(1));
        fs::write(
            &view,
            html.replace(
                "<%= @user.work_info.SSN %>",
                "<%= @user.work_info.last_four %>",
            ),
        )
        .unwrap();
        assert!(detect().is_empty(), "masked on server");
        fs::write(
            &view,
            html.replace("<%= @user.work_info.SSN %>", "<%#= @user.work_info.SSN %>"),
        )
        .unwrap();
        assert!(detect().is_empty(), "commented ERB");
        fs::write(
            &view,
            html.replace("$(document).ready(", "// $(document).ready disabled("),
        )
        .unwrap();
        assert!(detect().is_empty(), "no active masking on load");
        fs::write(&view, html).unwrap();
        fs::write(
            &routes,
            "resources :reports do\n resources :work_info\nend\n",
        )
        .unwrap();
        assert!(detect().is_empty(), "unlinked route");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rails_admin_gate_bypass_requires_route_filter_and_unguarded_predicate() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-rails-admin-gate-{nonce}"));
        let files = [
            ("app/controllers/admin_controller.rb", "class AdminController < ApplicationController\n  before_action :administrative, if: :admin_param, except: [:get_user]\n  def dashboard\n  end\n  def get_user\n  end\n  private\n  def admin_param\n    params[:admin_id] != \"1\"\n  end\nend\n"),
            ("app/controllers/application_controller.rb", "class ApplicationController < ActionController::Base\n  before_action :authenticated, :has_info\n  def administrative\n    if !is_admin?\n      redirect_to root_url\n    end\n  end\nend\n"),
            ("config/routes.rb", "resources :admin do\n  get \"dashboard\"\nend\n"),
        ];
        for (path, contents) in files {
            let target = root.join(path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(target, contents).unwrap();
        }
        let patterns = build_vuln_patterns();
        let detect = || scoped_rails_admin_gate_bypass(&root, &patterns);
        let found = detect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line_number, Some(9));
        let admin = root.join("app/controllers/admin_controller.rb");
        let original = fs::read_to_string(&admin).unwrap();
        fs::write(&admin, original.replace("if: :admin_param, ", "")).unwrap();
        assert!(detect().is_empty(), "unconditional admin gate");
        fs::write(
            &admin,
            original.replace("params[:admin_id] != \"1\"", "params[:admin_id] == \"1\""),
        )
        .unwrap();
        assert!(detect().is_empty(), "predicate does not bypass on id 1");
        fs::write(
            &admin,
            original.replace(
                "params[:admin_id] != \"1\"",
                "# params[:admin_id] != \"1\"\n    true",
            ),
        )
        .unwrap();
        assert!(detect().is_empty(), "commented predicate");
        fs::write(&admin, original).unwrap();
        fs::write(
            root.join("config/routes.rb"),
            "resources :users do\n  get \"dashboard\"\nend\n",
        )
        .unwrap();
        assert!(detect().is_empty(), "not an admin route");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rails_login_redirect_requires_unsafe_framework_default_and_request_flow() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-rails-redirect-{nonce}"));
        for dir in ["config", "app/controllers"] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        let ctl = root.join("app/controllers/sessions_controller.rb");
        let app = root.join("config/application.rb");
        let vulnerable = "class SessionsController < ApplicationController\n def create\n  path = params[:url].present? ? params[:url] : home_dashboard_index_path\n  if user\n   redirect_to path\n  end\n end\nend\n";
        fs::write(&ctl, vulnerable).unwrap();
        fs::write(&app, "class Application < Rails::Application\nend\n").unwrap();
        fs::write(root.join("Gemfile.lock"), "actionpack (8.0.4)\n").unwrap();
        let patterns = build_vuln_patterns();
        let detect = || scoped_rails_login_redirect(&root, &patterns);
        assert_eq!(detect()[0].line_number, Some(5));
        fs::write(
            &app,
            "class Application < Rails::Application\n config.load_defaults 8.0\nend\n",
        )
        .unwrap();
        assert!(
            detect().is_empty(),
            "modern Rails defaults forbid other hosts"
        );
        fs::write(&app, "class Application < Rails::Application\n config.action_controller.raise_on_open_redirects = true\nend\n").unwrap();
        assert!(detect().is_empty(), "explicit host restriction");
        fs::write(&app, "class Application < Rails::Application\nend\n").unwrap();
        fs::write(
            &ctl,
            vulnerable.replace(
                "redirect_to path",
                "redirect_to path, allow_other_host: false",
            ),
        )
        .unwrap();
        assert!(detect().is_empty(), "redirect-level host restriction");
        fs::write(
            &ctl,
            vulnerable.replace(
                "params[:url].present? ? params[:url]",
                "internal_path.present? ? internal_path",
            ),
        )
        .unwrap();
        assert!(detect().is_empty(), "no request-controlled path");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rails_work_info_idor_requires_route_view_and_missing_ownership() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-rails-idor-{nonce}"));
        for dir in ["config", "app/controllers", "app/views/work_info"] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        let ctl = root.join("app/controllers/work_info_controller.rb");
        let base = root.join("app/controllers/application_controller.rb");
        let route = root.join("config/routes.rb");
        let view = root.join("app/views/work_info/index.html.erb");
        let vulnerable = "class WorkInfoController < ApplicationController\n def index\n  @user = User.find_by(id: params[:user_id])\n  if !(@user) || @user.admin\n    redirect_to dashboard_path\n  end\n end\nend\n";
        fs::write(&ctl, vulnerable).unwrap();
        fs::write(&base, "class ApplicationController < ActionController::Base\n before_action :authenticated\nend\n").unwrap();
        fs::write(&route, "resources :users do\n resources :work_info\nend\n").unwrap();
        fs::write(
            &view,
            "<%= @user.work_info.SSN %> <%= @user.work_info.income %>",
        )
        .unwrap();
        let patterns = build_vuln_patterns();
        let detect = || scoped_rails_work_info_idor(&root, &patterns);
        let found = detect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line_number, Some(3));
        fs::write(
            &ctl,
            vulnerable.replace(
                "  if !(@user)",
                "  return unless @user.id == current_user.id\n  if !(@user)",
            ),
        )
        .unwrap();
        assert!(detect().is_empty(), "ownership guard suppresses");
        fs::write(&ctl, vulnerable).unwrap();
        fs::write(&view, "<%= @user.first_name %>").unwrap();
        assert!(detect().is_empty(), "no sensitive view");
        fs::write(
            &view,
            "<%= @user.work_info.SSN %> <%= @user.work_info.income %>",
        )
        .unwrap();
        fs::write(&route, "resources :users\n").unwrap();
        assert!(detect().is_empty(), "no nested route");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rails_csrf_requires_effective_config_and_state_change() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-rails-csrf-{nonce}"));
        for dir in ["config/initializers", "app/controllers"] {
            fs::create_dir_all(root.join(dir)).unwrap();
        }
        let app = root.join("config/application.rb");
        let base = root.join("app/controllers/application_controller.rb");
        let routes = root.join("config/routes.rb");
        let schedule = root.join("app/controllers/schedule_controller.rb");
        let cookie = root.join("config/initializers/session_store.rb");
        fs::write(&app, "class Application < Rails::Application\nend\n").unwrap();
        fs::write(&base, "class ApplicationController < ActionController::Base\n  #protect_from_forgery with: :exception\nend\n").unwrap();
        fs::write(&routes, "resources :schedule\n").unwrap();
        fs::write(&schedule, "def create\n sched.save\nend\n").unwrap();
        fs::write(&cookie, "session_store :cookie_store\n").unwrap();
        fs::write(root.join("Gemfile.lock"), "actionpack (8.0.4)\n").unwrap();
        let patterns = build_vuln_patterns();
        let detect = || scoped_rails_csrf_findings(&root, &patterns);
        let findings = detect();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line_number, Some(2));
        fs::write(
            &app,
            "class Application < Rails::Application\n config.load_defaults 8.0\nend\n",
        )
        .unwrap();
        assert!(
            detect().is_empty(),
            "modern defaults protect even if controller call is commented"
        );
        fs::write(&app, "class Application < Rails::Application\nend\n").unwrap();
        fs::write(&base, "class ApplicationController < ActionController::Base\n protect_from_forgery with: :exception\nend\n").unwrap();
        assert!(detect().is_empty(), "active controller guard");
        fs::write(&base, "class ApplicationController < ActionController::Base\n #protect_from_forgery with: :exception\nend\n").unwrap();
        fs::write(&schedule, "def create\n render :index\nend\n").unwrap();
        assert!(detect().is_empty(), "no linked state-changing write");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rails_assignment_positive_and_negative_controls() {
        let create = "class UsersController < ApplicationController\n def create\n user = User.new(user_params)\n end\n private\n def user_params\n params.require(:user).permit!\n end\nend\n";
        assert_eq!(rails_assignment_sink_lines(create, "rb"), [3].into());
        assert!(
            rails_assignment_sink_lines(&create.replace("permit!", "permit(:email)"), "rb")
                .is_empty()
        );
        let update = "class UsersController < ApplicationController\n def update\n user.update(user_params_without_password)\n end\n def user_params_without_password\n params.require(:user).permit(:email, :admin, :first_name)\n end\nend\n";
        assert_eq!(rails_assignment_sink_lines(update, "rb"), [6].into());
        assert!(rails_assignment_sink_lines(&update.replace(":admin,", ""), "rb").is_empty());
        let admin = "class AdminController < ApplicationController\n def update_user\n user_params = params[:user].to_unsafe_h\n filtered_params = user_params.reject { |k, v| k == \"password\" }\n user.update(filtered_params)\n end\nend\n";
        assert_eq!(rails_assignment_sink_lines(admin, "rb"), [5].into());
        assert!(
            rails_assignment_sink_lines(&admin.replace("to_unsafe_h", "permit(:email)"), "rb")
                .is_empty()
        );
        assert!(rails_assignment_sink_lines("User.new(user_params)", "rb").is_empty());
    }

    #[test]
    fn pilot_crypto_cookie_positive_and_negative_controls() {
        let rails = "before_save :hash_password\ndef hash_password\n  self.password = Digest::MD5.hexdigest(self.password)\nend\n";
        assert_eq!(pilot_crypto_cookie_lines(rails, "rb").0, [3].into());
        assert!(
            pilot_crypto_cookie_lines("Digest::MD5.hexdigest(checksum)", "rb")
                .0
                .is_empty()
        );
        let php = "$_SESSION['last_session_id']++;\n$cookie_value = $_SESSION['last_session_id'];\nsetcookie(\"dvwaSession\", $cookie_value);\n";
        assert_eq!(pilot_crypto_cookie_lines(php, "php").1, [2].into());
        assert!(pilot_crypto_cookie_lines(
            "$cookie_value = random_bytes(20);\nsetcookie(\"dvwaSession\", $cookie_value);",
            "php"
        )
        .1
        .is_empty());
        let go = "import mathrand \"math/rand\"\ntoken := fmt.Sprintf(\"%d\", mathrand.Int63())\nrsa.GenerateKey(cryptorand.Reader, 512)\nMinVersion: tls.VersionTLS10,\nTLSConfig: tlsConfig,\nserver.ListenAndServeTLS(\"cert\", \"key\")\nhttp.SetCookie(w, &http.Cookie{\n Name: \"session\",\n Value: sessionID,\n})\n";
        let (_, tokens, rsa, tls, cookies) = pilot_crypto_cookie_lines(go, "go");
        assert_eq!(tokens, [2].into());
        assert_eq!(rsa, [3].into());
        assert_eq!(tls, [4].into());
        assert_eq!(cookies, [7].into());
        let safe = "import mathrand \"math/rand\"\nx := mathrand.Int63()\nrsa.GenerateKey(cryptorand.Reader, 2048)\nMinVersion: tls.VersionTLS12,\nhttp.SetCookie(w, &http.Cookie{\n Name: \"session\",\n Value: sessionID,\n HttpOnly: true,\n Secure: true,\n})\n";
        let (_, tokens, rsa, tls, cookies) = pilot_crypto_cookie_lines(safe, "go");
        assert!(tokens.is_empty() && rsa.is_empty() && tls.is_empty() && cookies.is_empty());
    }

    fn scan(source: &str, extension: &str) -> Vec<Finding> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("cipher-review-{nonce}.{extension}"));
        fs::write(&path, source).expect("write fixture");
        let findings = scan_file_for_vulns(&path, &build_vuln_patterns());
        fs::remove_file(path).expect("remove fixture");
        findings
    }

    #[test]
    fn go_web_pilot_five_sinks_and_controls() {
        let data = r#"func Search(w http.ResponseWriter, r *http.Request) {
q := r.URL.Query().Get("q")
w.Header().Set("Content-Type", "text/html")
fmt.Fprintf(w, "<html>%s</html>", q)
}"#;
        assert_eq!(go_html_xss_lines(data, "go"), [4].into());
        assert!(go_xpath_sink_lines(data, "go").is_empty());
        let xpath = r#"func QueryXML(w http.ResponseWriter, r *http.Request) {
username := r.URL.Query().Get("username")
query := "/users/user[@name='" + username + "']"
nodes := xmlquery.Find(doc, query)
}"#;
        assert_eq!(go_xpath_sink_lines(xpath, "go"), [4].into());
        let email = r#"func SendEmail(w http.ResponseWriter, r *http.Request) {
to := r.FormValue("to")
subject := r.FormValue("subject")
message := []byte(
"To: " + to + "\r\n" +
"Subject: " + subject + "\r\n\r\n"
)
smtp.SendMail("localhost", nil, "from", []string{to}, message)
}"#;
        assert_eq!(go_email_header_sink_lines(email, "go"), [5, 6].into());
        let files = r#"func RenderTemplate(w http.ResponseWriter, r *http.Request) {
tmplStr := r.URL.Query().Get("template")
tmpl, err := template.New("user").Parse(tmplStr)
tmpl.Execute(w, nil)
}"#;
        assert_eq!(go_template_source_sink_lines(files, "go"), [3].into());
        let network = r#"func Fetch(w http.ResponseWriter, r *http.Request) {
url := r.URL.Query().Get("url")
client := newInsecureClient()
resp, err := client.Get(url)
}"#;
        assert!(ssrf_sink_lines(network, "go").contains(&4));
        let safe = r#"package main
func handler(w http.ResponseWriter, r *http.Request) {
 q := r.FormValue("q")
 w.Header().Set("Content-Type", "text/html")
 fmt.Fprintf(w, "<p>%s</p>", html.EscapeString(q))
 xpath := "/users/user[@name='admin']"
 xmlquery.Find(doc, xpath)
 tmpl := template.New("fixed").Parse("Hello {{.Name}}")
 tmpl.Execute(w, map[string]string{"Name": q})
 subject := r.FormValue("subject")
 body := r.FormValue("body")
 msg := []byte("Subject: static\r\n\r\n" + body)
 smtp.SendMail("mail.example.com:587", nil, "from@example.com", []string{subject}, msg)
 client.Get("https://example.com/static")
 }"#;
        assert!(go_html_xss_lines(safe, "go").is_empty());
        assert!(go_xpath_sink_lines(safe, "go").is_empty());
        assert!(go_template_source_sink_lines(safe, "go").is_empty());
        assert!(go_email_header_sink_lines(safe, "go").is_empty());
        assert!(ssrf_sink_lines(safe, "go").is_empty());
    }

    #[test]
    fn php_ruby_file_and_xss_flows_have_scoped_controls() {
        let upload = r#"<?php
$target_path = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
$target_path .= basename($_FILES['uploaded']['name']);
move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path);
"#;
        assert_eq!(php_ruby_file_xss_lines(upload, "php").0, [4].into());
        let guarded_upload = format!("{upload}\ngetimagesize($uploaded_tmp);");
        assert!(php_ruby_file_xss_lines(&guarded_upload, "php").0.is_empty());
        let html = r#"<?php
$html .= '<pre>Hello ' . $_GET['name'] . '</pre>';
$name = str_replace('<script>', '', $_GET['name']);
$html .= "<pre>Hello {$name}</pre>";
$name = htmlspecialchars($_GET['name']);
$html .= "<pre>Hello {$name}</pre>";
"#;
        assert_eq!(php_ruby_file_xss_lines(html, "php").1, [2, 4].into());
        let ruby = r#"def download
path = params[:name]
file = params[:type].constantize.new(path)
send_file file, disposition: "attachment"
end"#;
        assert_eq!(php_ruby_file_xss_lines(ruby, "rb").2, [4].into());
        assert!(
            php_ruby_file_xss_lines(&ruby.replace("params[:name]", "'static.pdf'"), "rb")
                .2
                .is_empty()
        );
    }

    #[test]
    fn django_safe_filter_project_links_at_exact_lines() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-django-safe-{nonce}"));
        let write = |relative: &str, content: &str| {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        };
        write(
            "manage.py",
            "import os\nos.environ.setdefault(\"DJANGO_SETTINGS_MODULE\", \"taskManager.settings\")\n",
        );
        write(
            "taskManager/templates/taskManager/base_backend.html",
            "<span class=\"username\">{{ user.username|safe }}</span>\n<!-- {{ old|safe }} -->\n<p>{{ user.username }}</p>\n&lt;span&gt;&#123;&#123; user.username|safe &#125;&#125;&lt;/span&gt;\n",
        );
        let patterns = build_vuln_patterns();
        let hits = scoped_django_safe_filter_findings(&root, &patterns);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].title, "Unescaped Django Output (XSS)");
        assert_eq!(hits[0].line_number, Some(1));
        fs::remove_file(root.join("manage.py")).unwrap();
        assert!(scoped_django_safe_filter_findings(&root, &patterns).is_empty());
    }

    #[tokio::test]
    async fn php_ruby_pilot_project_links_at_exact_lines() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-php-ruby-file-xss-{nonce}"));
        let write = |relative: &str, content: &str| {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        };
        write("vulnerabilities/fi/index.php", "<?php\nrequire_once DVWA_WEB_PAGE_TO_ROOT . \"vulnerabilities/fi/source/{$vulnerabilityFile}\";\nif( isset( $file ) )\n include( $file );\n");
        write(
            "vulnerabilities/fi/source/low.php",
            "<?php\n$file = $_GET[ 'page' ];\n",
        );
        write(
            "vulnerabilities/xss_s/source/low.php",
            "<?php\n$name = $_POST[ 'txtName' ];\n$query = 'INSERT INTO guestbook';\n",
        );
        write(
            "vulnerabilities/xss_s/index.php",
            "<?php\ndvwaGuestbook();\n",
        );
        write("dvwa/includes/dvwaPage.inc.php", "<?php\nfunction dvwaGuestbook() {\nif( dvwaSecurityLevelGet() == 'impossible' ) {\n$name = htmlspecialchars($row[0]);\n} else {\n$name = $row[0];\n}\n$guestbook .= \"{$name}\";\n}\n// -- END (XSS Stored guestbook)\n");
        write(
            "app/controllers/users_controller.rb",
            "params.require(:user).permit(:first_name)\n",
        );
        write(
            "app/views/layouts/shared/_header.html.erb",
            "<span><%= current_user.first_name.html_safe %></span>\n",
        );
        let keys = || collect_review_findings(&root, false, None);
        let report = keys().await.unwrap();
        let present: std::collections::HashSet<(String, usize)> = report
            .findings
            .iter()
            .filter_map(|f| Some((f.title.clone(), f.line_number?)))
            .collect();
        for (title, line) in [
            ("File Inclusion", 4),
            ("Stored XSS", 6),
            ("Unescaped Rails Output (XSS)", 1),
        ] {
            assert!(
                present.contains(&(title.to_string(), line)),
                "missing {title}:{line}"
            );
        }
        fs::write(
            root.join("vulnerabilities/fi/source/low.php"),
            "<?php\n$file = 'fixed.php';\n",
        )
        .unwrap();
        fs::write(
            root.join("vulnerabilities/xss_s/source/low.php"),
            "<?php\n$name = 'fixed';\n",
        )
        .unwrap();
        fs::write(
            root.join("app/controllers/users_controller.rb"),
            "params.require(:user).permit(:email)\n",
        )
        .unwrap();
        let safe = keys().await.unwrap();
        assert!(safe.findings.iter().all(|f| !matches!(
            f.title.as_str(),
            "File Inclusion" | "Stored XSS" | "Unescaped Rails Output (XSS)"
        )));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ruby_php_query_and_shell_flows_are_scoped_to_real_sinks() {
        let rails = r##"user = User.where("id = '#{params[:user][:id]}'")[0]
User.where(id: params[:id]).first
scope :hits, ->(ip, col = "*") { select("#{col}").where(ip_address: ip) }
silence_streams(STDERR) { system("cp #{full_file_name} #{data_path}/bak#{file.original_filename}") }"##;
        let (sql, command) = ruby_php_injection_lines(rails, "rb");
        assert_eq!(sql, [1].into());
        assert_eq!(command, [4].into());
        let php = r#"$id = $_GET['id'];
$query = "SELECT name FROM users WHERE user_id = '$id'";
mysqli_query($db, $query);
$stmt = $db->prepare('SELECT name FROM users WHERE user_id = :id');
$target = $_REQUEST['ip'];
$cmd = shell_exec('ping ' . $target);"#;
        let (sql, command) = ruby_php_injection_lines(php, "php");
        assert_eq!(sql, [2].into());
        assert_eq!(command, [6].into());
        let safe = r#"$id = $_GET['id'];
$id = intval($id);
$query = "SELECT name FROM users WHERE user_id = '$id'";
mysqli_query($db, $query);
$target = $_REQUEST['ip'];
$octet = explode('.', $target);
if ((is_numeric( $octet[0] )) && (is_numeric( $octet[1] )) && (is_numeric( $octet[2] )) && (is_numeric( $octet[3] )) && (sizeof( $octet ) == 4)) {
$target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];
$cmd = shell_exec('ping ' . $target);
}"#;
        let (sql, command) = ruby_php_injection_lines(safe, "php");
        assert!(sql.is_empty());
        assert!(command.is_empty());
        let numeric_context = r#"$id = $_POST['id'];
$id = mysqli_real_escape_string($db, $id);
$query = "SELECT name FROM users WHERE user_id = $id";
mysqli_query($db, $query);"#;
        let (sql, _) = ruby_php_injection_lines(numeric_context, "php");
        assert_eq!(sql, [3].into(), "escaped value in unquoted numeric context");
        let quoted_context = r#"$id = $_POST['id'];
$id = mysqli_real_escape_string($db, $id);
$query = "SELECT name FROM users WHERE user_id = '$id'";
mysqli_query($db, $query);"#;
        let (sql, _) = ruby_php_injection_lines(quoted_context, "php");
        assert!(
            sql.is_empty(),
            "escaped value stays neutralized inside quotes"
        );
        let escaped_then_numeric = r#"$id = $_POST['id'];
$id = mysqli_real_escape_string($db, $id);
$id = intval($id);
$query = "SELECT name FROM users WHERE user_id = $id";
mysqli_query($db, $query);"#;
        let (sql, _) = ruby_php_injection_lines(escaped_then_numeric, "php");
        assert!(
            sql.is_empty(),
            "numeric cast after escaping closes the context"
        );
    }

    
