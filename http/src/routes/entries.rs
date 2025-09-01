use crate::views;
use ama_core::Context;
use axum::{Router, extract::State, response::Html, routing::get};
use std::sync::Arc;

pub fn router(ctx: Arc<Context>) -> Router {
    Router::new().route("/", get(index)).with_state(ctx)
}

async fn index(State(ctx): State<Arc<Context>>) -> Html<String> {
    let entries = ctx.get_entries().await;
    Html(views::entries::page(&entries))
}
