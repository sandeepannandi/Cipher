use actix_web::{get, HttpRequest, HttpResponse};
use crate::store::{find_user, list_users};

#[get("/user")]
async fn handler(req: HttpRequest) -> HttpResponse {
    let name = req.match_info().get("name").unwrap_or("");
    find_user(&POOL, name).await.ok();
    HttpResponse::Ok().finish()
}
