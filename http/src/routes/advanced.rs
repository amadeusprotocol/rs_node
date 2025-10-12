use crate::views;
use amadeus_node::Context;
use axum::{Router, extract::State, response::Html, routing::get};
use std::sync::Arc;

pub fn router(ctx: Arc<Context>) -> Router {
    Router::new().route("/", get(index)).with_state(ctx)
}

async fn index(State(ctx): State<Arc<Context>>) -> Html<String> {
    let snapshot = ctx.get_metrics_snapshot();
    let peers_summary = ctx.get_peers_summary().await.ok();
    Html(views::advanced::page(&snapshot, &peers_summary, &ctx))
}
