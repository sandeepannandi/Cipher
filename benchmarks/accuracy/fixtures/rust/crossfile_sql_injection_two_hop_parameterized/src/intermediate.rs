use sqlx::PgPool;

use crate::store::query_user;

pub async fn find_user(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    query_user(pool, name).await
}
