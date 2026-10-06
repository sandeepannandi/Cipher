#[test]
    fn real_sql_injection_keeps_its_title_next_to_a_where_clause_word() {
        // Negative control: SQL text and a JS line that merely mention a
        // WHERE clause stay SQL injection; only a `$where` operator moves.
        let findings = scan(
            "const name = req.query.name;\ndb.query(`SELECT * FROM users WHERE name = '${name}'`);",
            "js",
        );
        assert_eq!(titles(&findings), vec![SQLI_FLOW]);
        assert_eq!(findings[0].cwe_id.as_deref(), Some("CWE-89"));
    }

    const SQLI_FLOW: &str = "SQL Injection — String Concatenation";

    #[test]
    fn js_request_value_through_helper_chain_reaches_sql_sink() {
        let findings = scan(
            r#"function findUserByName(username) {
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    return db.prepare(query).get();
}

function lookup(name) {
    return findUserByName(name);
}

exports.getUser = (req, res) => {
    const { username } = req.query;
    return res.json(lookup(username));
};"#,
            "js",
        );
        assert_eq!(titles(&findings), vec![SQLI_FLOW]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn js_helper_using_bind_parameter_is_clean() {
        let findings = scan(
            r#"function findUserByName(username) {
    return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

exports.getUser = (req, res) => {
    const { username } = req.query;
    return res.json(findUserByName(username));
};"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_helper_called_only_with_constants_is_clean() {
        let findings = scan(
            r#"function findUserByName(username) {
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    return db.prepare(query).get();
}

exports.getAdmin = (req, res) => {
    const { id } = req.query;
    return res.json(findUserByName('admin'));
};"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_function_defined_twice_is_not_resolved() {
        let findings = scan(
            r#"function findUser(name) {
    return db.prepare(`SELECT * FROM users WHERE name = '${name}'`).get();
}

function findUser(name) {
    return db.prepare('SELECT * FROM users WHERE name = ?').get(name);
}

exports.getUser = (req, res) => {
    const { name } = req.query;
    return res.json(findUser(name));
};"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_call_on_other_receiver_is_not_resolved_to_local_function() {
        let findings = scan(
            r#"function findUser(name) {
    return db.prepare(`SELECT * FROM users WHERE name = '${name}'`).get();
}

exports.getUser = (req, res) => {
    const { name } = req.query;
    return res.json(repository.findUser(name));
};"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_caller_rebinding_to_constant_before_call_is_clean() {
        let findings = scan(
            r#"function findUser(name) {
    return db.prepare(`SELECT * FROM users WHERE name = '${name}'`).get();
}

exports.getUser = (req, res) => {
    let name = req.query.name;
    name = 'guest';
    return res.json(findUser(name));
};"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn js_only_the_tainted_parameter_position_counts() {
        let findings = scan(
            r#"function findProduct(owner, term) {
    const sql = `SELECT * FROM products WHERE name = '${term}'`;
    return db.prepare(sql).all();
}

exports.search = (req, res) => {
    const owner = req.query.owner;
    return res.json(findProduct(owner, 'widgets'));
};"#,
            "js",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_request_value_passed_to_query_helper_is_reported() {
        let findings = scan(
            r#"def find_user(conn, name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return conn.execute(query).fetchall()


@app.route("/user")
def user():
    name = request.args.get("name")
    return str(find_user(conn, name))"#,
            "py",
        );
        assert_eq!(titles(&findings), vec![SQLI_FLOW]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn python_numeric_conversion_at_call_site_is_clean() {
        let findings = scan(
            r#"def find_user(conn, user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query).fetchall()


@app.route("/user")
def user():
    user_id = request.args.get("id")
    return str(find_user(conn, int(user_id)))"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_self_method_shell_helper_is_reported_and_quote_stops_it() {
        let vulnerable = scan(
            r#"class Diagnostics:
    def run_ping(self, host):
        command = "ping -c 1 " + host
        return subprocess.check_output(command, shell=True)

    def ping(self):
        host = request.args.get("host")
        return self.run_ping(host)"#,
            "py",
        );
        assert_eq!(titles(&vulnerable), vec![CMDI]);
        assert_eq!(vulnerable[0].line_number, Some(4));

        let quoted = scan(
            r#"class Diagnostics:
    def run_ping(self, host):
        command = "ping -c 1 " + host
        return subprocess.check_output(command, shell=True)

    def ping(self):
        host = request.args.get("host")
        return self.run_ping(shlex.quote(host))"#,
            "py",
        );
        assert!(quoted.is_empty());
    }

    #[test]
    fn python_keyword_argument_call_is_not_mapped_by_position() {
        let findings = scan(
            r#"def find_user(conn, name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return conn.execute(query).fetchall()


def user():
    name = request.args.get("name")
    return find_user(conn=name, name="guest")"#,
            "py",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_request_value_passed_to_private_query_method_is_reported() {
        let vulnerable = scan(
            r#"public class UserController extends HttpServlet {
    private ResultSet findUser(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return conn.createStatement().executeQuery(sql);
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findUser(name);
    }
}"#,
            "java",
        );
        assert_eq!(titles(&vulnerable), vec![SQLI_FLOW]);
        assert_eq!(vulnerable[0].line_number, Some(4));

        let prepared = scan(
            r#"public class UserController extends HttpServlet {
    private ResultSet findUser(String name) throws SQLException {
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        stmt.setString(1, name);
        return stmt.executeQuery();
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findUser(name);
    }
}"#,
            "java",
        );
        assert!(prepared.is_empty());
    }

    #[test]
    fn java_overloaded_methods_are_not_resolved() {
        let findings = scan(
            r#"public class UserController {
    private ResultSet findUser(String name) throws SQLException {
        return conn.createStatement().executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    private ResultSet findUser(String name, int limit) throws SQLException {
        return null;
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findUser(name, 10);
    }
}"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_request_value_passed_to_query_function_is_reported() {
        let vulnerable = scan(
            r#"func findUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	findUser(name)
}"#,
            "go",
        );
        assert_eq!(titles(&vulnerable), vec![SQLI_FLOW]);
        assert_eq!(vulnerable[0].line_number, Some(3));

        let parameterized = scan(
            r#"func findUser(name string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE name = $1", name)
}

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	findUser(name)
}"#,
            "go",
        );
        assert!(parameterized.is_empty());
    }

    #[test]
    fn go_method_with_receiver_is_not_resolved_from_bare_call() {
        let findings = scan(
            r#"func (s *Store) findUser(name string) (*sql.Rows, error) {
	return s.db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	store.findUser(name)
}"#,
            "go",
        );
        assert!(findings.is_empty());
    }

    /// Write a small project and return `(relative path, title, line)` for
    /// every flow-family finding the review path produces across its files.
    fn scan_project(files: &[(&str, &str)]) -> Vec<(String, String, usize)> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("cipher-xfile-{nonce}"));
        let mut paths = Vec::new();
        for (relative, source) in files {
            let path = root.join(relative);
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            fs::write(&path, source).expect("write fixture");
            // node_modules fixtures sit on disk for import resolution but are
            // never scanned directly, mirroring production scans.
            if !relative.starts_with("node_modules/") && !relative.contains("/node_modules/") {
                paths.push(path);
            }
        }
        let cross_file = cross_file_flow_sinks(&paths, &root);
        let patterns = build_vuln_patterns();
        let mut found = Vec::new();
        let mut collect = |path: &std::path::Path, finding: &Finding| {
            let relative = path
                .strip_prefix(&root)
                .expect("relative")
                .to_string_lossy()
                .replace('\\', "/");
            found.push((
                relative,
                finding.title.clone(),
                finding.line_number.unwrap_or(0),
            ));
        };
        for path in &paths {
            for finding in
                scan_file_for_vulns_with(path, &patterns, cross_file.get(path), Some(&root))
            {
                // Only the flow families; unrelated pattern rules (IDOR on
                // `id` lookups, etc.) are covered by their own tests.
                if ![SQLI_FLOW, NOSQL_WHERE_TITLE, CMDI, SSRF, "Code Injection"]
                    .contains(&finding.title.as_str())
                {
                    continue;
                }
                collect(path, &finding);
            }
        }
        // Package entries resolved through node_modules emit flow-only
        // findings, mirroring the production scan loop.
        let scanned: std::collections::HashSet<&std::path::PathBuf> = paths.iter().collect();
        for (path, sinks) in &cross_file {
            if !scanned.contains(path) {
                for finding in scan_file_flow_only(path, sinks) {
                    collect(path, &finding);
                }
            }
        }
        fs::remove_dir_all(&root).expect("cleanup");
        found.sort();
        found
    }

    const JS_PKG_DEP: &str = r#"const { exec } = require('child_process');

function run(c) {
    exec('sh -c ' + c);
}

module.exports = { run };
"#;

    const JS_PKG_APP_TAINTED: &str = r#"const dep = require('dep');

exports.run = (req, res) => {
    const { cmd } = req.query;
    return res.json(dep.run(cmd));
};
"#;

    #[test]
    fn js_package_import_sink_is_reported_in_node_modules_entry() {
        let found = scan_project(&[
            (
                "node_modules/dep/package.json",
                r#"{"name":"dep","main":"index.js"}"#,
            ),
            ("node_modules/dep/index.js", JS_PKG_DEP),
            ("src/app.js", JS_PKG_APP_TAINTED),
        ]);
        assert!(
            found.contains(&("node_modules/dep/index.js".to_string(), CMDI.to_string(), 4)),
            "{found:?}"
        );
    }

    #[test]
    fn js_package_import_with_constant_argument_is_clean() {
        let found = scan_project(&[
            (
                "node_modules/dep/package.json",
                r#"{"name":"dep","main":"index.js"}"#,
            ),
            ("node_modules/dep/index.js", JS_PKG_DEP),
            (
                "src/app.js",
                r#"const dep = require('dep');
dep.run('uptime');
"#,
            ),
        ]);
        assert!(
            !found
                .iter()
                .any(|(file, _, _)| file.contains("node_modules")),
            "{found:?}"
        );
    }

    #[test]
    fn js_package_subpath_import_stays_unresolved() {
        let found = scan_project(&[
            (
                "node_modules/dep/package.json",
                r#"{"name":"dep","main":"index.js"}"#,
            ),
            ("node_modules/dep/index.js", JS_PKG_DEP),
            (
                "src/app.js",
                r#"const sub = require('dep/sub');

exports.run = (req, res) => {
    const { cmd } = req.query;
    return res.json(sub.run(cmd));
};
"#,
            ),
        ]);
        assert!(
            !found
                .iter()
                .any(|(file, _, _)| file.contains("node_modules")),
            "{found:?}"
        );
    }

    #[test]
    fn go_test_file_call_into_package_is_reported() {
        let found = scan_project(&[
            ("go.mod", "module example.com/t\n\ngo 1.22\n"),
            (
                "store.go",
                r#"package main

import "database/sql"

func FindUser(db *sql.DB, name string) {
	db.Query("SELECT id FROM users WHERE name = '" + name + "'")
}
"#,
            ),
            (
                "main_test.go",
                r#"package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	FindUser(db, name)
}
"#,
            ),
        ]);
        assert!(
            found.contains(&("store.go".to_string(), SQLI_FLOW.to_string(), 6)),
            "{found:?}"
        );
    }

    #[test]
    fn go_non_test_file_never_resolves_test_only_function() {
        let found = scan_project(&[
            ("go.mod", "module example.com/t\n\ngo 1.22\n"),
            (
                "main.go",
                r#"package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	ExecRaw(q)
}
"#,
            ),
            (
                "main_test.go",
                r#"package main

import "database/sql"

func ExecRaw(q string) {
	db.Query("SELECT id FROM users WHERE name = '" + q + "'")
}
"#,
            ),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    const JS_USERS_SERVICE: &str = r#"const db = require('../db');

function findByName(name) {
    const sql = `SELECT id FROM users WHERE name = '${name}'`;
    return db.prepare(sql).all();
}

function findById(id) {
    return db.prepare('SELECT id FROM users WHERE id = ?').get(id);
}

module.exports = { findByName, findById };"#;

    #[test]
    fn js_controller_to_service_module_call_is_reported_in_service() {
        let found = scan_project(&[
            (
                "src/routes/users.js",
                r#"const users = require('../services/users');

exports.search = (req, res) => {
    const { name } = req.query;
    return res.json(users.findByName(name));
};"#,
            ),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_named_import_and_destructured_require_resolve() {
        for import in [
            "import { findByName as lookup } from '../services/users';",
            "const { findByName: lookup } = require('../services/users');",
        ] {
            let route = format!(
                "{import}\n\nexports.search = (req, res) => {{\n    const name = req.query.name;\n    return res.json(lookup(name));\n}};"
            );
            let found = scan_project(&[
                ("src/routes/users.js", route.as_str()),
                ("src/services/users.js", JS_USERS_SERVICE),
            ]);
            assert_eq!(found.len(), 1, "{import}");
            assert_eq!(found[0].2, 5, "{import}");
        }
    }

    #[test]
    fn js_multiline_import_and_require_resolve() {
        for import in [
            "import {\n    findByName as lookup\n} from '../services/users';",
            "const {\n    findByName: lookup\n} = require('../services/users');",
        ] {
            let route = format!(
                "{import}\n\nexports.search = (req, res) => {{\n    const name = req.query.name;\n    return res.json(lookup(name));\n}};"
            );
            let found = scan_project(&[
                ("src/routes/users.js", route.as_str()),
                ("src/services/users.js", JS_USERS_SERVICE),
            ]);
            assert_eq!(found.len(), 1, "{import}");
            assert_eq!(found[0].2, 5, "{import}");
        }
    }

    #[test]
    fn js_multiline_reexport_resolves() {
        let barrel = "export {\n    findByName\n} from './users';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", barrel),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_instance_variable_mixed_import_call_is_reported_in_service() {
        let route = r#"import Repo, { helper } from '../services/repo';

class Handler {
    constructor() {
        this.repo = new Repo();
    }

    async search(req, res) {
        const { name } = req.query;
        return res.json(await this.repo.findByName(name));
    }
}

module.exports = new Handler();
"#;
        let repo = r#"const db = require('../db');

class Repo {
    async findByName(name) {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    }
}

module.exports = Repo;
"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/repo.js", repo),
        ]);
        assert_eq!(
            found,
            vec![("src/services/repo.js".to_string(), SQLI_FLOW.to_string(), 6)]
        );
    }

    #[test]
    fn js_instance_variable_call_is_reported_in_service() {
        let route = r#"const Repo = require('../services/repo');

class Handler {
    constructor() {
        this.repo = new Repo();
    }

    async search(req, res) {
        const { name } = req.query;
        return res.json(await this.repo.findByName(name));
    }
}

module.exports = new Handler();
"#;
        let repo = r#"const db = require('../db');

class Repo {
    async findByName(name) {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    }
}

module.exports = Repo;
"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/repo.js", repo),
        ]);
        assert_eq!(
            found,
            vec![("src/services/repo.js".to_string(), SQLI_FLOW.to_string(), 6)]
        );
    }

    #[test]
    fn js_instance_variable_other_name_call_is_reported_in_service() {
        let route = r#"const Repo = require('../services/repo');

class Handler {
    constructor() {
        this.store = new Repo();
    }

    async search(req, res) {
        const { name } = req.query;
        return res.json(await this.store.findByName(name));
    }
}

module.exports = new Handler();
"#;
        let repo = r#"const db = require('../db');

class Repo {
    async findByName(name) {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    }
}

module.exports = Repo;
"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/repo.js", repo),
        ]);
        assert_eq!(
            found,
            vec![("src/services/repo.js".to_string(), SQLI_FLOW.to_string(), 6)]
        );
    }

    #[test]
    fn js_instance_variable_default_import_call_is_reported_in_service() {
        let route = r#"import Repo from '../services/repo';

class Handler {
    constructor() {
        this.repo = new Repo();
    }

    async search(req, res) {
        const { name } = req.query;
        return res.json(await this.repo.findByName(name));
    }
}

export default new Handler();
"#;
        let repo = r#"import db from '../db';

export default class Repo {
    async findByName(name) {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    }
}
"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/repo.js", repo),
        ]);
        assert_eq!(
            found,
            vec![("src/services/repo.js".to_string(), SQLI_FLOW.to_string(), 6)]
        );
    }

    #[test]
    fn js_instance_variable_named_import_call_is_reported_in_service() {
        let route = r#"import { Repo } from '../services/repo';

class Handler {
    constructor() {
        this.repo = new Repo();
    }

    async search(req, res) {
        const { name } = req.query;
        return res.json(await this.repo.findByName(name));
    }
}

export default new Handler();
"#;
        let repo = r#"import db from '../db';

export class Repo {
    async findByName(name) {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    }
}
"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/repo.js", repo),
        ]);
        assert_eq!(
            found,
            vec![("src/services/repo.js".to_string(), SQLI_FLOW.to_string(), 6)]
        );
    }

    #[test]
    fn js_instance_variable_aliased_import_call_is_reported_in_service() {
        let route = r#"import { Repo as Store } from '../services/repo';

class Handler {
    constructor() {
        this.repo = new Store();
    }

    async search(req, res) {
        const { name } = req.query;
        return res.json(await this.repo.findByName(name));
    }
}

export default new Handler();
"#;
        let repo = r#"import db from '../db';

export class Repo {
    async findByName(name) {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    }
}
"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/repo.js", repo),
        ]);
        assert_eq!(
            found,
            vec![("src/services/repo.js".to_string(), SQLI_FLOW.to_string(), 6)]
        );
    }

    #[test]
    fn js_unassigned_instance_variable_call_is_not_resolved() {
        let route = r#"const Repo = require('../services/repo');

class Handler {
    async search(req, res) {
        const { name } = req.query;
        return res.json(await this.repo.findByName(name));
    }
}

module.exports = new Handler();
"#;
        let repo = r#"const db = require('../db');

class Repo {
    async findByName(name) {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    }
}

module.exports = Repo;
"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/repo.js", repo),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_instance_variable_without_import_is_not_resolved() {
        let route = r#"class Handler {
    constructor() {
        this.repo = new Repo();
    }

    async search(req, res) {
        const { name } = req.query;
        return res.json(await this.repo.findByName(name));
    }
}

module.exports = new Handler();
"#;
        let repo = r#"const db = require('../db');

class Repo {
    async findByName(name) {
        const sql = `SELECT id FROM users WHERE name = '${name}'`;
        return db.prepare(sql).all();
    }
}

module.exports = Repo;
"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/repo.js", repo),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn python_instance_variable_call_is_reported_in_store() {
        let views = r#"from .repository import Store


class Views:
    def __init__(self):
        self.store = Store()

    @app.route("/orders")
    def orders(self):
        customer = request.args.get("customer")
        return {"orders": self.store.find_orders(customer)}
"#;
        let repository = r#"import sqlite3


class Store:
    def find_orders(self, customer):
        conn = sqlite3.connect("shop.db")
        query = "SELECT id FROM orders WHERE customer = '%s'" % customer
        return conn.execute(query).fetchall()
"#;
        let found = scan_project(&[("app/views.py", views), ("app/repository.py", repository)]);
        assert_eq!(
            found,
            vec![("app/repository.py".to_string(), SQLI_FLOW.to_string(), 8)]
        );
    }

    #[test]
    fn python_instance_variable_module_call_is_reported_in_store() {
        let views = r#"from . import repository


class Views:
    def __init__(self):
        self.store = repository.Store()

    @app.route("/orders")
    def orders(self):
        customer = request.args.get("customer")
        return {"orders": self.store.find_orders(customer)}
"#;
        let repository = r#"import sqlite3


class Store:
    def find_orders(self, customer):
        conn = sqlite3.connect("shop.db")
        query = "SELECT id FROM orders WHERE customer = '%s'" % customer
        return conn.execute(query).fetchall()
"#;
        let found = scan_project(&[("app/views.py", views), ("app/repository.py", repository)]);
        assert_eq!(
            found,
            vec![("app/repository.py".to_string(), SQLI_FLOW.to_string(), 8)]
        );
    }

    #[test]
    fn python_unassigned_instance_variable_call_is_not_resolved() {
        let views = r#"from .repository import Store


class Views:
    @app.route("/orders")
    def orders(self):
        customer = request.args.get("customer")
        return {"orders": self.store.find_orders(customer)}
"#;
        let repository = r#"import sqlite3


class Store:
    def find_orders(self, customer):
        conn = sqlite3.connect("shop.db")
        query = "SELECT id FROM orders WHERE customer = '%s'" % customer
        return conn.execute(query).fetchall()
"#;
        let found = scan_project(&[("app/views.py", views), ("app/repository.py", repository)]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn python_instance_variable_without_import_is_not_resolved() {
        let views = r#"class Views:
    def __init__(self):
        self.store = Store()

    @app.route("/orders")
    def orders(self):
        customer = request.args.get("customer")
        return {"orders": self.store.find_orders(customer)}
"#;
        let repository = r#"import sqlite3


class Store:
    def find_orders(self, customer):
        conn = sqlite3.connect("shop.db")
        query = "SELECT id FROM orders WHERE customer = '%s'" % customer
        return conn.execute(query).fetchall()
"#;
        let found = scan_project(&[("app/views.py", views), ("app/repository.py", repository)]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_default_export_call_is_reported_in_service() {
        let service = r#"const db = require('../db');

export default function findByName(name) {
    const sql = `SELECT id FROM users WHERE name = '${name}'`;
    return db.prepare(sql).all();
}
"#;
        for import in [
            "import findByName from '../services/users';",
            "import lookup from '../services/users';",
        ] {
            let callee = if import.contains("lookup") {
                "lookup"
            } else {
                "findByName"
            };
            let route = format!(
                "{import}\n\nexports.search = (req, res) => {{\n    const name = req.query.name;\n    return res.json({callee}(name));\n}};"
            );
            let found = scan_project(&[
                ("src/routes/users.js", route.as_str()),
                ("src/services/users.js", service),
            ]);
            assert_eq!(
                found,
                vec![(
                    "src/services/users.js".to_string(),
                    SQLI_FLOW.to_string(),
                    5
                )],
                "{import}"
            );
        }
    }

    #[test]
    fn js_default_export_reference_form_is_reported_in_service() {
        let service = r#"const db = require('../db');

function findByName(name) {
    const sql = `SELECT id FROM users WHERE name = '${name}'`;
    return db.prepare(sql).all();
}

export default findByName;
"#;
        let route = r#"import findByName from '../services/users';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/users.js", service),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_mixed_default_and_named_import_resolve() {
        let service = r#"const db = require('../db');

export default function findByName(name) {
    const sql = `SELECT id FROM users WHERE name = '${name}'`;
    return db.prepare(sql).all();
}

export function findById(id) {
    return db.prepare('SELECT id FROM users WHERE id = ?').get(id);
}
"#;
        let route = r#"import findByName, { findById } from '../services/users';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/users.js", service),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_default_export_parameterized_stays_clean() {
        let service = r#"const db = require('../db');

export default function findByName(name) {
    return db.prepare('SELECT id FROM users WHERE name = ?').all(name);
}
"#;
        let route = r#"import findByName from '../services/users';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/users.js", service),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_default_import_without_default_export_is_not_resolved() {
        let route = r#"import findByName from '../services/users';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_named_reexport_through_barrel_is_reported_in_service() {
        let barrel = "export { findByName } from './users';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", barrel),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_glob_reexport_through_barrel_is_reported_in_service() {
        let barrel = "export * from './users';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", barrel),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_chained_barrel_reexport_is_reported_in_service() {
        let outer_barrel = "export { findByName } from './v2';";
        let inner_barrel = "export { findByName } from './users';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", outer_barrel),
            ("src/services/v2.js", inner_barrel),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_glob_chained_through_named_barrel_is_reported_in_service() {
        let outer_barrel = "export * from './v2';";
        let inner_barrel = "export { findByName } from './users';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", outer_barrel),
            ("src/services/v2.js", inner_barrel),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_deep_barrel_chain_converges_in_service() {
        // Seven re-export hops: beyond the old fixed pass bound.
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            (
                "src/services/index.js",
                "export { findByName } from './v2';",
            ),
            ("src/services/v2.js", "export { findByName } from './v3';"),
            ("src/services/v3.js", "export { findByName } from './v4';"),
            ("src/services/v4.js", "export { findByName } from './v5';"),
            ("src/services/v5.js", "export { findByName } from './v6';"),
            ("src/services/v6.js", "export { findByName } from './v7';"),
            (
                "src/services/v7.js",
                "export { findByName } from './users';",
            ),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_long_same_file_helper_chain_converges() {
        // Nine functions deep: beyond the old fixed summary rounds.
        let route = r#"const store = require('../services/users');

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(store.findByName(name));
};"#;
        let service = r#"const db = require('../db');

function h8(name) {
    const sql = `SELECT id, name FROM users WHERE name = '${name}'`;
    return db.prepare(sql).all();
}

function h7(name) {
    return h8(name);
}

function h6(name) {
    return h7(name);
}

function h5(name) {
    return h6(name);
}

function h4(name) {
    return h5(name);
}

function h3(name) {
    return h4(name);
}

function h2(name) {
    return h3(name);
}

function findByName(name) {
    return h2(name);
}

module.exports = { findByName };"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/users.js", service),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_barrel_reexport_cycle_is_not_resolved() {
        let outer_barrel = "export { findByName } from './v2';";
        let inner_barrel = "export { findByName } from './index';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", outer_barrel),
            ("src/services/v2.js", inner_barrel),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_chained_barrel_ambiguous_source_is_not_resolved() {
        let barrel = "export { findByName } from './a';\nexport { findByName } from './b';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", barrel),
            ("src/services/a.js", JS_USERS_SERVICE),
            ("src/services/b.js", JS_USERS_SERVICE),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    
