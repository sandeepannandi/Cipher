#[test]
    fn rust_grouped_use_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{find_user, list_users};

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

    #[test]
    fn rust_grouped_use_alias_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{find_user as fetch_user};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    fetch_user(&POOL, name).await.ok();
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
    fn rust_grouped_use_glob_item_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{POOL_ALIAS, *};

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

    const RUST_HANDLER: &str = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::find_user;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;

    #[test]
    fn rust_pub_use_named_reexport_is_reported_in_store() {
        let lib = "mod store;\n\npub use store::find_user;";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", RUST_HANDLER),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_pub_use_crate_path_reexport_is_reported_in_store() {
        let lib = "mod store;\n\npub use crate::store::find_user;";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", RUST_HANDLER),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_pub_use_grouped_reexport_is_reported_in_store() {
        let lib = "mod store;\n\npub use store::{find_user};";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", RUST_HANDLER),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_pub_use_glob_reexport_is_reported_in_store() {
        let lib = "mod store;\n\npub use store::*;";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", RUST_HANDLER),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_pub_use_alias_reexport_is_reported_in_store() {
        let lib = "mod store;\n\npub use store::find_user as locate_user;";
        let handler = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::locate_user;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    locate_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", handler),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_pub_use_ambiguous_glob_is_not_resolved() {
        let lib = "mod a;\nmod b;\n\npub use a::*;\npub use b::*;";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", RUST_HANDLER),
            ("src/a.rs", RUST_STORE),
            ("src/b.rs", RUST_STORE),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rust_pub_use_parameterized_store_is_clean() {
        let lib = "mod store;\n\npub use store::find_user;";
        let store = r#"use sqlx::{Pool, Postgres};

pub async fn find_user(pool: &Pool<Postgres>, name: &str) -> Option<String> {
    sqlx::query("SELECT name FROM users WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}
"#;
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", RUST_HANDLER),
            ("src/store.rs", store),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rust_pub_use_chained_reexport_is_reported_in_store() {
        let lib = "mod intermediate;\nmod store;\n\npub use intermediate::find_user;";
        let intermediate = "pub use crate::store::find_user;";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/intermediate.rs", intermediate),
            ("src/handler.rs", RUST_HANDLER),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_pub_use_chained_glob_reexport_is_reported_in_store() {
        let lib = "mod intermediate;\nmod store;\n\npub use intermediate::*;";
        let intermediate = "pub use crate::store::*;";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/intermediate.rs", intermediate),
            ("src/handler.rs", RUST_HANDLER),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_deep_pub_use_chain_converges_in_store() {
        // Six re-export hops: beyond the old fixed pass bound.
        let lib =
            "mod m1;\nmod m2;\nmod m3;\nmod m4;\nmod m5;\nmod store;\n\npub use m1::find_user;";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/m1.rs", "pub use crate::m2::find_user;"),
            ("src/m2.rs", "pub use crate::m3::find_user;"),
            ("src/m3.rs", "pub use crate::m4::find_user;"),
            ("src/m4.rs", "pub use crate::m5::find_user;"),
            ("src/m5.rs", "pub use crate::store::find_user;"),
            ("src/handler.rs", RUST_HANDLER),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_pub_use_reexport_cycle_is_not_resolved() {
        let lib = "mod intermediate;\n\npub use intermediate::find_user;";
        let intermediate = "pub use crate::find_user;";
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/intermediate.rs", intermediate),
            ("src/handler.rs", RUST_HANDLER),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rust_two_import_hop_is_reported_in_store() {
        let lib = "mod intermediate;\nmod store;";
        let handler = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::intermediate::find_user;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let intermediate = r#"use sqlx::PgPool;

use crate::store::query_user;

pub async fn find_user(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    query_user(pool, name).await
}
"#;
        // Built from RUST_STORE so the fixture adds no extra copy of the
        // sink string to this file (the policy baseline counts duplicates).
        let store = RUST_STORE.replace("find_user", "query_user");
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", handler),
            ("src/intermediate.rs", intermediate),
            ("src/store.rs", store.as_str()),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_three_import_hops_converge_in_store() {
        let lib = "mod intermediate;\nmod relay;\nmod store;";
        let handler = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::intermediate::find_user;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let intermediate = r#"use sqlx::PgPool;

use crate::relay::find_user as relay_user;

pub async fn find_user(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    relay_user(pool, name).await
}
"#;
        let relay = r#"use sqlx::PgPool;

use crate::store::find_user as query_user;

pub async fn find_user(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    query_user(pool, name).await
}
"#;
        // Reuses RUST_STORE directly so the fixture adds no extra copy of
        // the sink string (the policy baseline counts duplicates).
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", handler),
            ("src/intermediate.rs", intermediate),
            ("src/relay.rs", relay),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_two_import_hop_cycle_without_sink_is_clean() {
        let lib = "mod intermediate;\nmod store;";
        let handler = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::intermediate::find_user;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let intermediate = r#"use sqlx::PgPool;

use crate::store::query_user;

pub async fn find_user(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    query_user(pool, name).await
}
"#;
        let store = r#"use sqlx::PgPool;

use crate::intermediate::find_user;

pub async fn query_user(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    find_user(pool, name).await
}
"#;
        let found = scan_project(&[
            ("src/lib.rs", lib),
            ("src/handler.rs", handler),
            ("src/intermediate.rs", intermediate),
            ("src/store.rs", store),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rust_grouped_use_parameterized_store_is_clean() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{find_user, list_users};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let store = r#"use sqlx::{Pool, Postgres};

pub async fn find_user(pool: &Pool<Postgres>, name: &str) -> Option<String> {
    sqlx::query("SELECT name FROM users WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}

pub async fn list_users(pool: &Pool<Postgres>) -> Vec<String> {
    Vec::new()
}
"#;
        let found = scan_project(&[("src/main.rs", main), ("src/store.rs", store)]);
        assert!(found.is_empty());
    }

    #[test]
    fn rust_deep_nested_mod_path_converges_in_leaf() {
        let main = r#"mod api;

use actix_web::{get, HttpRequest, HttpResponse};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    api::v1::users::lookup(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        // `api::v1::users::lookup(...)` walks three module bindings: api,
        // v1 inside api, users inside v1. Built from RUST_STORE so the
        // fixture adds no extra copy of the sink string to this file (the
        // policy baseline counts duplicates).
        let users = RUST_STORE.replace("find_user", "lookup");
        let found = scan_project(&[
            ("src/main.rs", main),
            (
                "src/api.rs",
                "pub mod v1;
",
            ),
            (
                "src/api/v1.rs",
                "pub mod users;
",
            ),
            ("src/api/v1/users.rs", users.as_str()),
        ]);
        assert_eq!(
            found,
            vec![("src/api/v1/users.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );

        // Without `pub mod users;` in v1.rs the chain stays unresolved.
        let found = scan_project(&[
            ("src/main.rs", main),
            (
                "src/api.rs",
                "pub mod v1;
",
            ),
            ("src/api/v1.rs", ""),
            ("src/api/v1/users.rs", users.as_str()),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rust_crate_glob_import_call_is_reported_in_store() {
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
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)],
            "crate glob"
        );
    }

    #[test]
    fn rust_double_super_use_call_is_reported_in_store() {
        let api = "pub mod users;";
        let users = r#"use actix_web::{get, HttpRequest, HttpResponse};
use super::super::store::find_user;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let main = "mod api;
mod store;
";
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/api.rs", api),
            ("src/api/users.rs", users),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)],
            "double super use"
        );
    }

    #[test]
    fn rust_super_glob_import_call_is_reported_in_store() {
        let api = "pub mod users;";
        let users = r#"use actix_web::{get, HttpRequest, HttpResponse};
use super::super::store::*;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let main = "mod api;
mod store;
";
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/api.rs", api),
            ("src/api/users.rs", users),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)],
            "super glob"
        );
    }

    #[test]
    fn rust_pubuse_barrel_call_is_reported_in_store() {
        let barrel = "pub use crate::store::find_user;";
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::barrel::find_user;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/barrel.rs", barrel),
            ("src/store.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store.rs".to_string(), SQLI_FLOW.to_string(), 5)],
            "pub use barrel"
        );
    }

    #[test]
    fn rust_multiline_grouped_use_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{
    find_user,
    list_users,
};

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

    #[test]
    fn rust_multiline_nested_group_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{
    inner::{
        find_user
    }
};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let store = "pub mod inner;
";
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/store.rs", store),
            ("src/store/inner.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store/inner.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_multiline_grouped_use_with_comment_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{
    find_user, // the lookup
    list_users,
};

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

    #[test]
    fn rust_nested_group_missing_module_is_clean() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{inner::{find_user}};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main), ("src/store.rs", RUST_STORE)]);
        assert!(found.is_empty());
    }

    #[test]
    fn rust_nested_group_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{inner::{find_user}};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let store = "pub mod inner;
";
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/store.rs", store),
            ("src/store/inner.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store/inner.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_nested_group_alias_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{inner::{find_user as fetch_user}};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    fetch_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let store = "pub mod inner;
";
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/store.rs", store),
            ("src/store/inner.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store/inner.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_nested_group_glob_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{inner::{*}};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let store = "pub mod inner;
";
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/store.rs", store),
            ("src/store/inner.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store/inner.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_nested_path_item_call_is_reported_in_store() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{inner::find_user};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let store = "pub mod inner;
";
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/store.rs", store),
            ("src/store/inner.rs", RUST_STORE),
        ]);
        assert_eq!(
            found,
            vec![("src/store/inner.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_nested_mod_path_call_is_reported_in_store() {
        let main = r#"mod api;

use actix_web::{get, HttpRequest, HttpResponse};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    api::users::lookup(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let api = r#"pub mod users;
"#;
        let users = r#"use sqlx::PgPool;

pub async fn lookup(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    let query = format!("SELECT * FROM users WHERE name = '{name}'");
    sqlx::query(&query).execute(pool).await?;
    Ok(())
}
"#;
        // `api::users::lookup(...)` resolves through one nested hop: each
        // module declares the next (`mod api;` + `pub mod users;`).
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/api.rs", api),
            ("src/api/users.rs", users),
        ]);
        assert_eq!(
            found,
            vec![("src/api/users.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );

        // Without `pub mod users;` in api.rs the chain stays unresolved.
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/api.rs", ""),
            ("src/api/users.rs", users),
        ]);
        assert!(found.is_empty(), "{found:?}");

        let main_use = main.replace("mod api;", "use crate::api::users::lookup;");
        let main_use = main_use.replace(
            "api::users::lookup(&POOL, name).await.ok();",
            "lookup(&POOL, name).await.ok();",
        );
        let found = scan_project(&[
            ("src/main.rs", main_use.as_str()),
            ("src/api.rs", api),
            ("src/api/users.rs", users),
        ]);
        assert_eq!(
            found,
            vec![("src/api/users.rs".to_string(), SQLI_FLOW.to_string(), 5)]
        );
    }

    #[test]
    fn rust_triple_mod_path_call_is_reported_in_leaf() {
        let main = r#"mod api;

use actix_web::{get, HttpRequest, HttpResponse};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    api::inner::users::lookup(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let api = "pub mod inner;\n";
        let inner = "pub mod users;\n";
        let users = r#"use sqlx::PgPool;

pub async fn lookup(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    let query = format!("SELECT * FROM users WHERE name = '{name}'");
    sqlx::query(&query).execute(pool).await?;
    Ok(())
}
"#;
        let found = scan_project(&[
            ("src/main.rs", main),
            ("src/api.rs", api),
            ("src/api/inner.rs", inner),
            ("src/api/inner/users.rs", users),
        ]);
        assert_eq!(
            found,
            vec![(
                "src/api/inner/users.rs".to_string(),
                SQLI_FLOW.to_string(),
                5
            )]
        );
    }

    #[test]
    fn rust_non_pub_function_is_not_exported() {
        let store = r#"use sqlx::PgPool;

async fn find_user(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    let query = format!("SELECT * FROM users WHERE name = '{name}'");
    sqlx::query(&query).execute(pool).await?;
    Ok(())
}
"#;
        let main = r#"mod store;

use actix_web::{get, HttpRequest, HttpResponse};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    store::find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main), ("src/store.rs", store)]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rust_parse_conversion_before_call_is_clean() {
        let main = r#"mod store;

use actix_web::{get, HttpRequest, HttpResponse};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    let id: i64 = name.parse::<i64>().unwrap_or(0);
    store::find_user_by_id(id).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let store = r#"use sqlx::PgPool;

pub async fn find_user_by_id(id: i64) -> Result<(), sqlx::Error> {
    let query = format!("SELECT * FROM users WHERE id = {id}");
    sqlx::query(&query).execute(&POOL).await?;
    Ok(())
}
"#;
        let found = scan_project(&[("src/main.rs", main), ("src/store.rs", store)]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rust_same_file_helper_call_is_reported() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use sqlx::PgPool;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    run(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}

async fn run(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    let query = format!("SELECT * FROM users WHERE name = '{name}'");
    sqlx::query(&query).execute(pool).await?;
    Ok(())
}
"#;
        let found = scan_project(&[("src/main.rs", main)]);
        assert_eq!(
            found,
            vec![("src/main.rs".to_string(), SQLI_FLOW.to_string(), 13)]
        );
    }

    #[test]
    fn rust_command_chain_from_request_is_reported() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use std::process::Command;

#[get("/ping")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let host = req.match_info().get("host").unwrap_or("");
    Command::new("sh").arg("-c").arg(format!("ping {host}")).output().ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main)]);
        assert_eq!(
            found,
            vec![("src/main.rs".to_string(), CMDI.to_string(), 7)]
        );
    }

    #[test]
    fn rust_command_without_shell_is_clean() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};
use std::process::Command;

#[get("/ping")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let host = req.match_info().get("host").unwrap_or("");
    Command::new("ping").arg(host).output().ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main)]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn rust_reqwest_url_from_request_is_reported() {
        let main = r#"use actix_web::{get, HttpRequest, HttpResponse};

#[get("/fetch")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let url = req.match_info().get("url").unwrap_or("");
    reqwest::get(url).await.ok();
    HttpResponse::Ok().finish()
}
"#;
        let found = scan_project(&[("src/main.rs", main)]);
        assert_eq!(
            found,
            vec![("src/main.rs".to_string(), SSRF.to_string(), 6)]
        );
    }

    #[test]
    fn rust_format_macro_embedded_request_read_is_reported() {
        let findings = scan(
            "let query = format!(\"SELECT * FROM users WHERE name = '{}'\", params.get(\"name\"));\nsqlx::query(&query)",
            "rs",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn rust_inline_request_read_at_sink_is_reported() {
        let findings = scan(
            "sqlx::query(&format!(\"SELECT * FROM users WHERE name = '{}'\", params.get(\"name\")))",
            "rs",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
    }

    #[test]
    fn rust_inline_request_read_as_parameter_is_clean() {
        let findings = scan(
            r#"conn.execute("INSERT INTO users (name) VALUES ($1)", &[&params.get("name")])"#,
            "rs",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_gin_query_param_reaching_query_is_reported() {
        let findings = scan(
            r#"name := c.Query("name")
query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
rows, err := db.QueryContext(ctx, query)"#,
            "go",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn go_echo_path_param_reaching_query_is_reported() {
        let findings = scan(
            r#"name := c.Param("name")
query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
rows, err := db.QueryContext(ctx, query)"#,
            "go",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn go_gin_bind_struct_field_reaching_query_is_reported() {
        let findings = scan(
            r#"var input UserInput
if err := c.ShouldBindJSON(&input); err != nil {
	return
}
query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", input.Name)
rows, err := db.QueryContext(ctx, query)"#,
            "go",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(6));
    }

    #[test]
    fn go_gin_parameterized_query_is_clean() {
        let findings = scan(
            r#"name := c.Query("name")
rows, err := db.QueryContext(ctx, "SELECT * FROM users WHERE name = $1", name)"#,
            "go",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_gin_param_sanitized_by_atoi_is_clean() {
        let findings = scan(
            r#"id, _ := strconv.Atoi(c.Param("id"))
query := fmt.Sprintf("SELECT * FROM users WHERE id = %d", id)
rows, err := db.QueryContext(ctx, query)"#,
            "go",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn go_gin_handler_to_store_cross_file_is_reported() {
        let handler = r#"package main

import "github.com/gin-gonic/gin"

func handler(c *gin.Context) {
	name := c.Query("name")
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
    fn java_spring_request_param_reaching_statement_is_reported() {
        let findings = scan(
            r#"@GetMapping("/user")
public String getUser(@RequestParam String name) throws SQLException {
	String sql = "SELECT * FROM users WHERE name = '" + name + "'";
	Statement stmt = conn.createStatement();
	ResultSet rs = stmt.executeQuery(sql);
	return "ok";
}"#,
            "java",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(5));
    }

    #[test]
    fn java_spring_prepared_statement_is_clean() {
        let findings = scan(
            r#"@GetMapping("/user")
public String getUser(@RequestParam String name) throws SQLException {
	PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
	ps.setString(1, name);
	ResultSet rs = ps.executeQuery();
	return "ok";
}"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_spring_unannotated_param_is_not_seeded() {
        let findings = scan(
            r#"public String getUser(String name) throws SQLException {
	String sql = "SELECT * FROM users WHERE name = '" + name + "'";
	Statement stmt = conn.createStatement();
	ResultSet rs = stmt.executeQuery(sql);
	return "ok";
}"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_spring_controller_to_static_service_cross_file_is_reported() {
        let controller = r#"package com.example.demo;

import java.sql.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    @GetMapping("/user/{name}")
    public ResultSet getUser(@PathVariable String name) throws SQLException {
        return UserService.findByName(name);
    }
}
"#;
        let service = r#"package com.example.demo;

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
            ("src/UserController.java", controller),
            ("src/UserService.java", service),
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
    fn java_spring_multiline_annotated_params_reaching_statement_is_reported() {
        let findings = scan(
            r#"@GetMapping("/user")
public String getUser(
        @RequestParam String name,
        @RequestParam String city) throws SQLException {
	String sql = "SELECT * FROM users WHERE city = '" + city + "'";
	Statement stmt = conn.createStatement();
	ResultSet rs = stmt.executeQuery(sql);
	return "ok";
}"#,
            "java",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(7));
    }

    #[test]
    fn java_spring_multiline_param_with_value_is_reported() {
        let findings = scan(
            r#"@GetMapping("/user")
public String getUser(
        @RequestParam("name") String name) throws SQLException {
	String sql = "SELECT * FROM users WHERE name = '" + name + "'";
	Statement stmt = conn.createStatement();
	ResultSet rs = stmt.executeQuery(sql);
	return "ok";
}"#,
            "java",
        );
        assert_eq!(titles(&findings), vec![SQLI]);
        assert_eq!(findings[0].line_number, Some(6));
    }

    #[test]
    fn java_spring_multiline_unannotated_param_is_not_seeded() {
        let findings = scan(
            r#"@GetMapping("/user")
public String getUser(
        @RequestParam String name,
        String safe) throws SQLException {
	String sql = "SELECT * FROM users WHERE name = '" + safe + "'";
	Statement stmt = conn.createStatement();
	ResultSet rs = stmt.executeQuery(sql);
	return "ok";
}"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_spring_inline_unannotated_param_is_not_seeded() {
        let findings = scan(
            r#"public String getUser(@RequestParam String name, String safe) throws SQLException {
	String sql = "SELECT * FROM users WHERE name = '" + safe + "'";
	Statement stmt = conn.createStatement();
	ResultSet rs = stmt.executeQuery(sql);
	return "ok";
}"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_spring_multiline_prepared_statement_is_clean() {
        let findings = scan(
            r#"@GetMapping("/user")
public String getUser(
        @RequestParam String name) throws SQLException {
	PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
	ps.setString(1, name);
	ResultSet rs = ps.executeQuery();
	return "ok";
}"#,
            "java",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_spring_multiline_controller_to_static_service_cross_file_is_reported() {
        let controller = r#"package com.example.demo;

import java.sql.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    @GetMapping("/user/{name}")
    public ResultSet getUser(
            @PathVariable String name) throws SQLException {
        return UserService.findByName(name);
    }
}
"#;
        let service = r#"package com.example.demo;

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
            ("src/UserController.java", controller),
            ("src/UserService.java", service),
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
    fn go_external_import_is_not_resolved() {
        let main = r#"package main

import (
	"net/http"

	"github.com/other/store"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	store.FindUser(name)
}
"#;
        let found = scan_project(&[
            ("go.mod", "module example.com/shop\n"),
            ("main.go", main),
            ("store/store.go", GO_STORE),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn go_duplicate_function_names_across_siblings_are_not_resolved() {
        let handler = r#"package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	findUser(name)
}
"#;
        let found = scan_project(&[
            ("handler.go", handler),
            ("store.go", GO_STORE),
            ("extra.go", GO_STORE),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }
