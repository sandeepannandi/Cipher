use sqlx::{Pool, Postgres};

pub async fn query_user(pool: &Pool<Postgres>, name: &str) -> Option<String> {
    sqlx::query("SELECT name FROM users WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}
