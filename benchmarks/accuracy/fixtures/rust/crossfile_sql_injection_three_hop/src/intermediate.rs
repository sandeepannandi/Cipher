use sqlx::PgPool;

use crate::relay::find_user as relay_user;

pub async fn find_user(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    relay_user(pool, name).await
}
