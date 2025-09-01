use ama_core::Context;
use axum::{Router, extract::State, response::Json, routing::get};
use serde_json::Value;
use std::sync::Arc;

pub mod advanced;
pub mod dashboard;
pub mod entries;
pub mod errors;
pub mod incoming;
pub mod network;
pub mod outgoing;
pub mod peers;

pub fn app(ctx: Arc<Context>) -> Router {
    Router::new()
        .merge(dashboard::router(ctx.clone()))
        .nest("/advanced", advanced::router(ctx.clone()))
        .nest("/peers", peers::router(ctx.clone()))
        .nest("/incoming", incoming::router(ctx.clone()))
        .nest("/outgoing", outgoing::router(ctx.clone()))
        .nest("/network", network::router(ctx.clone()))
        .nest("/errors", errors::router(ctx.clone()))
        .nest("/entries", entries::router(ctx.clone()))
        .nest("/api", api_router(ctx.clone()))
}

async fn api_peers(State(ctx): State<Arc<Context>>) -> Json<Value> {
    let peers = ctx.get_peers().await;
    Json(serde_json::to_value(peers).unwrap_or_default())
}

async fn api_metrics(State(ctx): State<Arc<Context>>) -> Json<Value> {
    let metrics = ctx.get_metrics_snapshot();
    Json(serde_json::to_value(metrics).unwrap_or_default())
}

fn api_router(ctx: Arc<Context>) -> Router {
    Router::new()
        .route("/peers", get(api_peers))
        .route("/metrics", get(api_metrics))
        .with_state(ctx)
}
