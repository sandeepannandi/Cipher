#[test]
    fn js_two_import_hop_is_reported_in_final_service() {
        let route = r#"const search = require('../services/search');

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(search.byName(name));
};"#;
        let middle = r#"const store = require('./db-users');

function byName(name) {
    return store.findByName(name);
}

module.exports = { byName };"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/search.js", middle),
            ("src/services/db-users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/db-users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_two_import_hop_parameterized_service_is_clean() {
        let route = r#"const search = require('../services/search');

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(search.byName(name));
};"#;
        let middle = r#"const store = require('./db-users');

function byName(name) {
    return store.findByName(name);
}

module.exports = { byName };"#;
        let service = r#"const db = require('../db');

function findByName(name) {
    return db.prepare('SELECT id, name FROM users WHERE name = ?').get(name);
}

module.exports = { findByName };"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/search.js", middle),
            ("src/services/db-users.js", service),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_two_import_hop_ambiguous_middle_import_is_not_resolved() {
        let route = r#"const search = require('../services/search');

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(search.byName(name));
};"#;
        let middle = r#"const { findByName } = require('./a');
const { findByName } = require('./b');

function byName(name) {
    return findByName(name);
}

module.exports = { byName };"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/search.js", middle),
            ("src/services/a.js", JS_USERS_SERVICE),
            ("src/services/b.js", JS_USERS_SERVICE),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_three_import_hops_converge_in_final_service() {
        let route = r#"const gateway = require('../services/gateway');

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(gateway.byName(name));
};"#;
        let gateway = r#"const search = require('./search');

function byName(name) {
    return search.byName(name);
}

module.exports = { byName };"#;
        let middle = r#"const store = require('./db-users');

function byName(name) {
    return store.findByName(name);
}

module.exports = { byName };"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/gateway.js", gateway),
            ("src/services/search.js", middle),
            ("src/services/db-users.js", JS_USERS_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/db-users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn js_three_import_hops_parameterized_service_is_clean() {
        let route = r#"const gateway = require('../services/gateway');

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(gateway.byName(name));
};"#;
        let gateway = r#"const search = require('./search');

function byName(name) {
    return search.byName(name);
}

module.exports = { byName };"#;
        let middle = r#"const store = require('./db-users');

function byName(name) {
    return store.findByName(name);
}

module.exports = { byName };"#;
        let service = r#"const db = require('../db');

function findByName(name) {
    return db.prepare('SELECT id, name FROM users WHERE name = ?').get(name);
}

module.exports = { findByName };"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/gateway.js", gateway),
            ("src/services/search.js", middle),
            ("src/services/db-users.js", service),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_ambiguous_glob_reexport_is_not_resolved() {
        let other = r#"const db = require('../db');

function findByName(name) {
    const sql = `SELECT id FROM users WHERE name = '${name}'`;
    return db.prepare(sql).all();
}

module.exports = { findByName };"#;
        let barrel = "export * from './users';
export * from './other';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", barrel),
            ("src/services/users.js", JS_USERS_SERVICE),
            ("src/services/other.js", other),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_aliased_reexport_through_barrel_is_reported_in_service() {
        let barrel = "export { findByName as lookup } from './users';";
        let route = r#"import { lookup } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(lookup(name));
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
    fn js_namespace_reexport_through_barrel_is_reported_in_service() {
        let barrel = "export * as users from './users';";
        let route = r#"import { users } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(users.findByName(name));
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
    fn java_import_resolving_outside_the_project_does_not_panic() {
        // `import java.io.File` names no class in the project; with a second
        // Java file present the class resolver used to index its empty match
        // list eagerly and panic the whole review.
        let reader = r#"package com.example;
import java.io.File;
public class A {
    public String read(String path) { return new File(path).getName(); }
}
"#;
        let other = r#"package com.example;
public class B {
    public String go(String p) { return p; }
}
"#;
        let found = scan_project(&[("src/A.java", reader), ("src/B.java", other)]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn python_star_import_name_offered_by_two_modules_resolves_to_neither() {
        let repository = r#"import sqlite3


def find_orders(customer):
    conn = sqlite3.connect("shop.db")
    query = "SELECT id FROM orders WHERE customer = '%s'" % customer
    return conn.execute(query).fetchall()"#;
        let views = r#"from .repository_a import *
from .repository_b import *


@app.route("/orders")
def orders():
    customer = request.args.get("customer")
    return {"orders": find_orders(customer)}
"#;
        let found = scan_project(&[
            ("app/views.py", views),
            ("app/repository_a.py", repository),
            ("app/repository_b.py", repository),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn python_star_import_into_repository_is_reported() {
        let repository = r#"import sqlite3


def find_orders(customer):
    conn = sqlite3.connect("shop.db")
    query = "SELECT id FROM orders WHERE customer = '%s'" % customer
    return conn.execute(query).fetchall()"#;
        let views = r#"from .repository import *


@app.route("/orders")
def orders():
    customer = request.args.get("customer")
    return {"orders": find_orders(customer)}
"#;
        let found = scan_project(&[("app/views.py", views), ("app/repository.py", repository)]);
        assert_eq!(
            found,
            vec![("app/repository.py".to_string(), SQLI_FLOW.to_string(), 7)],
            "star import"
        );
    }

    #[test]
    fn js_default_reexport_through_barrel_is_reported_in_service() {
        let service = r#"const db = require('../db');

export default function findByName(name) {
    const sql = `SELECT id FROM users WHERE name = '${name}'`;
    return db.prepare(sql).all();
}
"#;
        let barrel = "export { default as findByName } from './users';";
        let route = r#"import { findByName } from '../services';

exports.search = (req, res) => {
    const name = req.query.name;
    return res.json(findByName(name));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", barrel),
            ("src/services/users.js", service),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/services/users.js".to_string(),
                SQLI_FLOW.to_string(),
                5
            )],
            "default-as reexport"
        );
    }

    #[test]
    fn js_reexport_of_parameterized_service_stays_clean() {
        let barrel = "export { findById } from './users';";
        let route = r#"import { findById } from '../services';

exports.get = (req, res) => {
    const id = req.params.id;
    return res.json(findById(id));
};"#;
        let found = scan_project(&[
            ("src/routes/users.js", route),
            ("src/services/index.js", barrel),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_parameterized_service_function_stays_clean() {
        let found = scan_project(&[
            (
                "src/routes/users.js",
                r#"const users = require('../services/users');

exports.get = (req, res) => {
    const id = req.params.id;
    return res.json(users.findById(id));
};"#,
            ),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_unexported_or_package_functions_are_not_resolved() {
        let found = scan_project(&[
            (
                "src/routes/users.js",
                r#"const users = require('../services/users');
const pkg = require('users');

exports.search = (req, res) => {
    const { name } = req.query;
    pkg.findByName(name);
    return res.json(users.findHidden(name));
};"#,
            ),
            (
                "src/services/users.js",
                r#"const db = require('../db');

function findHidden(name) {
    return db.prepare(`SELECT id FROM users WHERE name = '${name}'`).all();
}

module.exports = {};"#,
            ),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn js_service_called_only_with_constants_stays_clean() {
        let found = scan_project(&[
            (
                "src/routes/users.js",
                r#"const users = require('../services/users');

exports.admins = (req, res) => {
    const { page } = req.query;
    return res.json(users.findByName('admin'));
};"#,
            ),
            ("src/services/users.js", JS_USERS_SERVICE),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn python_relative_import_into_repository_is_reported() {
        let repository = r#"import sqlite3


def find_orders(customer):
    conn = sqlite3.connect("shop.db")
    query = "SELECT id FROM orders WHERE customer = '%s'" % customer
    return conn.execute(query).fetchall()"#;
        for (import, call) in [
            (
                "from .repository import find_orders",
                "find_orders(customer)",
            ),
            (
                "from . import repository",
                "repository.find_orders(customer)",
            ),
        ] {
            let views = format!(
                "{import}\n\n\n@app.route(\"/orders\")\ndef orders():\n    customer = request.args.get(\"customer\")\n    return {{\"orders\": {call}}}\n"
            );
            let found = scan_project(&[
                ("app/views.py", views.as_str()),
                ("app/repository.py", repository),
            ]);
            assert_eq!(
                found,
                vec![("app/repository.py".to_string(), SQLI_FLOW.to_string(), 7)],
                "{import}"
            );
        }
    }

    #[test]
    fn python_try_except_import_into_repository_is_reported() {
        let repository = r#"import sqlite3


def find_orders(customer):
    conn = sqlite3.connect("shop.db")
    query = "SELECT id FROM orders WHERE customer = '%s'" % customer
    return conn.execute(query).fetchall()"#;
        let views = r#"try:
    from .repository import find_orders
except ImportError:
    find_orders = None


@app.route("/orders")
def orders():
    customer = request.args.get("customer")
    return {"orders": find_orders(customer)}
"#;
        let found = scan_project(&[("app/views.py", views), ("app/repository.py", repository)]);
        assert_eq!(
            found,
            vec![("app/repository.py".to_string(), SQLI_FLOW.to_string(), 7)],
            "try/except import"
        );
    }

    #[test]
    fn python_absolute_star_import_into_repository_is_reported() {
        let repository = r#"import sqlite3


def find_orders(customer):
    conn = sqlite3.connect("shop.db")
    query = "SELECT id FROM orders WHERE customer = '%s'" % customer
    return conn.execute(query).fetchall()"#;
        let views = r#"from repository import *


@app.route("/orders")
def orders():
    customer = request.args.get("customer")
    return {"orders": find_orders(customer)}
"#;
        let found = scan_project(&[("app/views.py", views), ("app/repository.py", repository)]);
        assert_eq!(
            found,
            vec![("app/repository.py".to_string(), SQLI_FLOW.to_string(), 7)],
            "absolute star"
        );
    }

    #[test]
    fn python_parenthesized_import_into_repository_is_reported() {
        let repository = r#"import sqlite3


def find_orders(customer):
    conn = sqlite3.connect("shop.db")
    query = "SELECT id FROM orders WHERE customer = '%s'" % customer
    return conn.execute(query).fetchall()"#;
        for import in [
            "from .repository import (find_orders)",
            "from .repository import (\n    find_orders,\n)",
            "from . import (repository)",
        ] {
            let (import, call) = if import.contains("repository)") {
                (import, "repository.find_orders(customer)")
            } else {
                (import, "find_orders(customer)")
            };
            let views = format!(
                "{import}\n\n\n@app.route(\"/orders\")\ndef orders():\n    customer = request.args.get(\"customer\")\n    return {{\"orders\": {call}}}\n"
            );
            let found = scan_project(&[
                ("app/views.py", views.as_str()),
                ("app/repository.py", repository),
            ]);
            assert_eq!(
                found,
                vec![("app/repository.py".to_string(), SQLI_FLOW.to_string(), 7)],
                "{import}"
            );
        }
    }

    #[test]
    fn python_numeric_conversion_before_cross_file_call_is_clean() {
        let found = scan_project(&[
            (
                "app/views.py",
                r#"from .repository import find_orders


@app.route("/orders")
def orders():
    customer_id = int(request.args.get("customer_id", "0"))
    return {"orders": find_orders(customer_id)}"#,
            ),
            (
                "app/repository.py",
                r#"def find_orders(customer_id):
    query = "SELECT id FROM orders WHERE customer_id = %d" % customer_id
    return conn.execute(query).fetchall()"#,
            ),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    const JAVA_USER_SERVICE: &str = r#"package com.example.demo;

import java.sql.*;

public class UserService {
    private static Connection conn;

    public static ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
"#;

    const JAVA_USER_CONTROLLER: &str = r#"package com.example.demo;

import java.sql.*;
import javax.servlet.http.*;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        UserService.findByName(name);
    }
}
"#;

    const GO_STORE: &str = r#"package main

import (
	"database/sql"
	"fmt"
)

var db *sql.DB

func findUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}
"#;

    #[test]
    fn java_same_package_static_call_is_reported_in_service() {
        let found = scan_project(&[
            ("src/UserController.java", JAVA_USER_CONTROLLER),
            ("src/UserService.java", JAVA_USER_SERVICE),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/UserService.java".to_string(),
                SQLI_FLOW.to_string(),
                11
            )]
        );
    }

    #[test]
    fn java_import_resolved_static_call_is_reported_in_service() {
        let controller = r#"package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import com.example.service.UserService;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        UserService.findByName(name);
    }
}
"#;
        let service = r#"package com.example.service;

import java.sql.*;

public class UserService {
    private static Connection conn;

    public static ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
"#;
        let found = scan_project(&[
            ("src/com/example/web/UserController.java", controller),
            ("src/com/example/service/UserService.java", service),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/com/example/service/UserService.java".to_string(),
                SQLI_FLOW.to_string(),
                11
            )]
        );
    }

    #[test]
    fn java_parameterized_cross_file_call_is_clean() {
        let service = r#"package com.example.demo;

import java.sql.*;

public class UserService {
    private static Connection conn;

    public static ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = ?";
        PreparedStatement stmt = conn.prepareStatement(sql);
        stmt.setString(1, name);
        return stmt.executeQuery();
    }
}
"#;
        let found = scan_project(&[
            ("src/UserController.java", JAVA_USER_CONTROLLER),
            ("src/UserService.java", service),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    const JAVA_SERVICE_PACKAGE: &str = r#"package com.example.service;

import java.sql.*;

public class UserService {
    private static Connection conn;

    public static ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
"#;

    #[test]
    fn java_import_static_call_is_reported_in_service() {
        let controller = r#"package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import static com.example.service.UserService.findByName;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findByName(name);
    }
}
"#;
        let found = scan_project(&[
            ("src/com/example/web/UserController.java", controller),
            (
                "src/com/example/service/UserService.java",
                JAVA_SERVICE_PACKAGE,
            ),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/com/example/service/UserService.java".to_string(),
                SQLI_FLOW.to_string(),
                11
            )]
        );
    }

    #[test]
    fn java_import_static_wildcard_call_is_reported_in_service() {
        let controller = r#"package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import static com.example.service.UserService.*;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findByName(name);
    }
}
"#;
        let found = scan_project(&[
            ("src/com/example/web/UserController.java", controller),
            (
                "src/com/example/service/UserService.java",
                JAVA_SERVICE_PACKAGE,
            ),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/com/example/service/UserService.java".to_string(),
                SQLI_FLOW.to_string(),
                11
            )]
        );
    }

    #[test]
    fn java_package_wildcard_call_is_reported_in_service() {
        let controller = r#"package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import com.example.service.*;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        UserService.findByName(name);
    }
}
"#;
        let found = scan_project(&[
            ("src/com/example/web/UserController.java", controller),
            (
                "src/com/example/service/UserService.java",
                JAVA_SERVICE_PACKAGE,
            ),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/com/example/service/UserService.java".to_string(),
                SQLI_FLOW.to_string(),
                11
            )]
        );
    }

    #[test]
    fn java_package_wildcard_resolves_among_many_same_package_siblings() {
        // Large packages are where sibling and class lookups used to go
        // quadratic; the indexed lookup must give the same answer.
        let controller = r#"package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import com.example.service.*;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        UserService.findByName(name);
    }
}
"#;
        let mut files: Vec<(String, String)> = vec![
            (
                "src/com/example/web/UserController.java".to_string(),
                controller.to_string(),
            ),
            (
                "src/com/example/service/UserService.java".to_string(),
                JAVA_SERVICE_PACKAGE.to_string(),
            ),
        ];
        for index in 0..150 {
            files.push((
                format!("src/com/example/service/Filler{index}.java"),
                format!(
                    "package com.example.service;\n\npublic class Filler{index} {{\n    int value() {{ return {index}; }}\n}}\n"
                ),
            ));
        }
        let refs: Vec<(&str, &str)> = files
            .iter()
            .map(|(path, content)| (path.as_str(), content.as_str()))
            .collect();
        let found = scan_project(&refs);
        assert_eq!(
            found,
            vec![(
                "src/com/example/service/UserService.java".to_string(),
                SQLI_FLOW.to_string(),
                11
            )]
        );
    }

    #[test]
    fn java_explicit_import_of_class_declared_twice_in_package_resolves_to_neither() {
        let controller = r#"package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import com.example.service.UserService;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        UserService.findByName(name);
    }
}
"#;
        let found = scan_project(&[
            ("src/com/example/web/UserController.java", controller),
            (
                "src/com/example/service/UserService.java",
                JAVA_SERVICE_PACKAGE,
            ),
            (
                "src/com/example/service/other/UserService.java",
                JAVA_SERVICE_PACKAGE,
            ),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn java_import_static_shadowed_by_own_method_is_not_resolved() {
        let controller = r#"package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import static com.example.service.UserService.findByName;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findByName(name);
    }

    private void findByName(String name) {
        System.out.println(name);
    }
}
"#;
        let found = scan_project(&[
            ("src/com/example/web/UserController.java", controller),
            (
                "src/com/example/service/UserService.java",
                JAVA_SERVICE_PACKAGE,
            ),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn java_import_static_private_method_is_not_resolved() {
        let controller = r#"package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import static com.example.service.UserService.findByName;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findByName(name);
    }
}
"#;
        let service = r#"package com.example.service;

import java.sql.*;

public class UserService {
    private static Connection conn;

    private static ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
"#;
        let found = scan_project(&[
            ("src/com/example/web/UserController.java", controller),
            ("src/com/example/service/UserService.java", service),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn java_import_static_ambiguous_members_are_not_resolved() {
        let controller = r#"package com.example.web;

import java.sql.*;
import javax.servlet.http.*;
import static com.example.service.UserService.findByName;
import static com.example.other.UserService.findByName;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        findByName(name);
    }
}
"#;
        let other = r#"package com.example.other;

import java.sql.*;

public class UserService {
    private static Connection conn;

    public static ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
"#;
        let found = scan_project(&[
            ("src/com/example/web/UserController.java", controller),
            (
                "src/com/example/service/UserService.java",
                JAVA_SERVICE_PACKAGE,
            ),
            ("src/com/example/other/UserService.java", other),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn java_instance_method_call_is_not_resolved() {
        let controller = r#"package com.example.demo;

import java.sql.*;
import javax.servlet.http.*;

public class UserController extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws SQLException {
        String name = request.getParameter("name");
        UserService service = new UserService();
        service.findByName(name);
    }
}
"#;
        let service = r#"package com.example.demo;

import java.sql.*;

public class UserService {
    private Connection conn;

    public ResultSet findByName(String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
"#;
        let found = scan_project(&[
            ("src/UserController.java", controller),
            ("src/UserService.java", service),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn go_same_package_call_is_reported_in_store() {
        let handler = r#"package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	findUser(name)
}
"#;
        let found = scan_project(&[("handler.go", handler), ("store.go", GO_STORE)]);
        assert_eq!(
            found,
            vec![("store.go".to_string(), SQLI_FLOW.to_string(), 12)]
        );
    }

    #[test]
    fn go_numeric_conversion_before_cross_file_call_is_clean() {
        let handler = r#"package main

import (
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	id, _ := strconv.Atoi(name)
	findUser(id)
}
"#;
        let found = scan_project(&[("handler.go", handler), ("store.go", GO_STORE)]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn go_cross_package_call_is_reported_in_store() {
        let store = r#"package store

import (
	"database/sql"
	"fmt"
)

var db *sql.DB

func FindUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}
"#;
        for (import, call) in [
            ("\"example.com/shop/store\"", "store.FindUser(name)"),
            ("st \"example.com/shop/store\"", "st.FindUser(name)"),
        ] {
            let main = format!(
                "package main\n\nimport (\n\t\"net/http\"\n\n\t{import}\n)\n\nfunc handler(w http.ResponseWriter, r *http.Request) {{\n\tname := r.URL.Query().Get(\"name\")\n\t{call}\n}}\n"
            );
            let found = scan_project(&[
                ("go.mod", "module example.com/shop\n"),
                ("main.go", main.as_str()),
                ("store/store.go", store),
            ]);
            assert_eq!(
                found,
                vec![("store/store.go".to_string(), SQLI_FLOW.to_string(), 12)],
                "{import}"
            );
        }
    }

    #[test]
    fn go_dot_import_name_offered_by_two_packages_resolves_to_neither() {
        let store = r#"package store

import (
	"database/sql"
	"fmt"
)

var db *sql.DB

func FindUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}
"#;
        let main = r#"package main

import (
	"net/http"

	. "example.com/shop/store"
	. "example.com/shop/store2"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	FindUser(name)
}
"#;
        let found = scan_project(&[
            (
                "go.mod",
                "module example.com/shop
",
            ),
            ("main.go", main),
            ("store/store.go", store),
            ("store2/store2.go", store),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn go_dot_import_call_is_reported_in_store() {
        let store = r#"package store

import (
	"database/sql"
	"fmt"
)

var db *sql.DB

func FindUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}
"#;
        let main = r#"package main

import (
	"net/http"

	. "example.com/shop/store"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	FindUser(name)
}
"#;
        let found = scan_project(&[
            (
                "go.mod",
                "module example.com/shop
",
            ),
            ("main.go", main),
            ("store/store.go", store),
        ]);
        assert_eq!(
            found,
            vec![("store/store.go".to_string(), SQLI_FLOW.to_string(), 12)],
            "dot import"
        );
    }

    #[test]
    fn go_replace_module_call_is_reported_in_store() {
        let main = r#"package main

import (
	"net/http"

	"example.com/inventory/store"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	store.FindUser(name)
}
"#;
        let store = r#"package store

import (
	"database/sql"
	"fmt"
)

var db *sql.DB

func FindUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}
"#;
        for go_mod in [
            "module example.com/shop\n\nrequire example.com/inventory v0.0.0\n\nreplace example.com/inventory => ./inventory\n",
            "module example.com/shop\n\nreplace (\n\texample.com/inventory => ./inventory\n)\n",
        ] {
            let found = scan_project(&[
                ("go.mod", go_mod),
                ("main.go", main),
                ("inventory/store/store.go", store),
            ]);
            assert_eq!(
                found,
                vec![(
                    "inventory/store/store.go".to_string(),
                    SQLI_FLOW.to_string(),
                    12
                )],
                "{go_mod}"
            );
        }
    }

    #[test]
    fn go_nested_module_call_is_reported_in_store() {
        let main = r#"package main

import (
	"net/http"

	"example.com/inventory/store"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	store.FindUser(name)
}
"#;
        let store = r#"package store

import (
	"database/sql"
	"fmt"
)

var db *sql.DB

func FindUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}
"#;
        let found = scan_project(&[
            ("go.mod", "module example.com/shop\n"),
            ("main.go", main),
            ("inventory/go.mod", "module example.com/inventory\n"),
            ("inventory/store/store.go", store),
        ]);
        assert_eq!(
            found,
            vec![(
                "inventory/store/store.go".to_string(),
                SQLI_FLOW.to_string(),
                12
            )]
        );
    }

    #[test]
    fn go_replace_module_parameterized_is_clean() {
        let main = r#"package main

import (
	"net/http"

	"example.com/inventory/store"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	store.FindUser(name)
}
"#;
        let store = r#"package store

import "database/sql"

var db *sql.DB

func FindUser(name string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE name = ?", name)
}
"#;
        let found = scan_project(&[
            (
                "go.mod",
                "module example.com/shop\n\nreplace example.com/inventory => ./inventory\n",
            ),
            ("main.go", main),
            ("inventory/store/store.go", store),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn go_unexported_cross_package_call_is_not_resolved() {
        let main = r#"package main

import (
	"net/http"

	"example.com/shop/store"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	store.findUser(name)
}
"#;
        let store = r#"package store

import (
	"database/sql"
	"fmt"
)

var db *sql.DB

func findUser(name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}
"#;
        let found = scan_project(&[
            ("go.mod", "module example.com/shop\n"),
            ("main.go", main),
            ("store/store.go", store),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    const RUST_STORE: &str = r#"use sqlx::PgPool;

pub async fn find_user(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    let query = format!("SELECT * FROM users WHERE name = '{name}'");
    sqlx::query(&query).execute(pool).await?;
    Ok(())
}
"#;

    #[test]
    fn rust_mod_path_call_is_reported_in_store() {
        let main = r#"mod store;

use actix_web::{get, HttpRequest, HttpResponse};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    store::find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main), ("src/store.rs", RUST_STORE)]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_use_crate_function_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::find_user;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        for main_file in ["src/main.rs", "src/lib.rs"] {
            let found = scan_project(&[(main_file, main), ("src/store.rs", RUST_STORE)]);
            assert_eq!(
                found,
                vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)],
                "{main_file}"
            );
        }
    }

    #[test]
    fn rust_use_glob_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::*;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main), ("src/store.rs", RUST_STORE)]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    
