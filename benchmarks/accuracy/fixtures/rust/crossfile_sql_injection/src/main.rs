mod store;

use actix_web::{get, HttpRequest, HttpResponse};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    store::find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
