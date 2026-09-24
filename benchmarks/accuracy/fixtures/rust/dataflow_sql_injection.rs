use actix_web::{get, HttpRequest, HttpResponse};
use sqlx::PgPool;

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    run_query(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}

async fn run_query(pool: &PgPool, name: &str) -> Result<(), sqlx::Error> {
    let query = format!("SELECT * FROM users WHERE name = '{name}'");
    sqlx::query(&query).execute(pool).await?;
    Ok(())
}
