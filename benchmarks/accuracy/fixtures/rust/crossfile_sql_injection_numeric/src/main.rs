mod store;

use actix_web::{get, HttpRequest, HttpResponse};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let id: i64 = req
        .match_info()
        .get("id")
        .unwrap_or("")
        .parse::<i64>()
        .unwrap_or(0);
    store::find_user(&POOL, id).await.ok();
    HttpResponse::Ok().finish()
}
