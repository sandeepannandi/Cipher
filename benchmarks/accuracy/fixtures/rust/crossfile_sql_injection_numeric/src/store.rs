use sqlx::PgPool;

pub async fn find_user(pool: &PgPool, id: i64) -> Result<(), sqlx::Error> {
    let query = format!("SELECT * FROM users WHERE id = {id}");
    sqlx::query(&query).execute(pool).await?;
    Ok(())
}
