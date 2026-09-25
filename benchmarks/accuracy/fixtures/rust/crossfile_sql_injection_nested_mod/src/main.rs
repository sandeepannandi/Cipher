mod api;

use actix_web::{get, HttpRequest, HttpResponse};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    api::users::lookup(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
