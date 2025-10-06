use crate::openapi;
use ama_core::Context;
use axum::http::{StatusCode, header};
use axum::{
    Router,
    extract::State,
    response::{Json, Response},
    routing::get,
};
use serde_json::Value;
use std::sync::Arc;

pub mod advanced;
pub mod api;
pub mod not_found;

pub fn app(ctx: Arc<Context>) -> Router {
    Router::new()
        .merge(advanced::router(ctx.clone()))
        .nest("/api", api::api_router(ctx.clone()).merge(openapi::openapi_route()))
        .nest("/v2", api::v2_router(ctx.clone()))
        .merge(system_router(ctx))
        .fallback(not_found::not_found_handler)
}

async fn prometheus_metrics(State(ctx): State<Arc<Context>>) -> Response<String> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
        .body(ctx.get_prometheus_metrics())
        .unwrap()
}

async fn health(State(ctx): State<Arc<Context>>) -> Json<Value> {
    Json(ctx.get_json_health())
}

fn system_router(ctx: Arc<Context>) -> Router {
    Router::new().route("/metrics", get(prometheus_metrics)).route("/health", get(health)).with_state(ctx)
}
