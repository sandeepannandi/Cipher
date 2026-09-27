use std::{fs, process::Command};

#[test]
fn spring_realworld_http_routes_are_not_sql_injection() {
    let root = std::env::temp_dir().join(format!("cipher-sql-http-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let routes = [
        "/articles/{slug}/comments/{id}",
        "/articles/{slug}/favorite",
        "/articles/{slug}",
        "/profiles/{username}/follow",
    ];
    let source = routes
        .iter()
        .map(|route| format!("given().when().delete(\"{route}\", slug, id);"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(root.join("SpringRoutes.java"), source).unwrap();
    fs::write(
        root.join("RealSql.java"),
        concat!("entityManager.createNative", "Query(\"SELECT * FROM users WHERE id = {id}\");"),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cipher-ai"))
        .args([
            "review",
            "--format",
            "json",
            "--max-findings",
            "0",
            "--path",
        ])
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json = stdout
        .find("{\n  \"findings\"")
        .expect("JSON report in output");
    let report: serde_json::Value = serde_json::from_str(&stdout[json..]).unwrap();
    let findings = report["findings"].as_array().unwrap();
    let sql: Vec<_> = findings
        .iter()
        .filter(|f| f["title"].as_str().unwrap_or("").contains("SQL Injection"))
        .collect();
    assert_eq!(sql.len(), 2, "{sql:?}");
    assert!(sql[0]["file_path"]
        .as_str()
        .unwrap()
        .ends_with("RealSql.java"));
    fs::remove_dir_all(&root).unwrap();
}
