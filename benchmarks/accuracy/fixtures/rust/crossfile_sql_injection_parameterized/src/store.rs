use sqlx::PgPool;

pub async fn find_user(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT * FROM users WHERE name = $1")
        .bind(name)
        .execute(pool)
        .await?;
    Ok(())
}
