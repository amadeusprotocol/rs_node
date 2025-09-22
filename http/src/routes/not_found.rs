use crate::views;
use axum::{http::StatusCode, response::Html};

pub async fn not_found_handler() -> (StatusCode, Html<String>) {
    (StatusCode::NOT_FOUND, Html(views::not_found::page()))
}