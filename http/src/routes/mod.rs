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
        .merge(system_router(ctx))
}

async fn api_peers(State(ctx): State<Arc<Context>>) -> Json<Value> {
    let peers = ctx.get_peers().await;
    Json(serde_json::to_value(peers).unwrap_or_default())
}

async fn api_metrics(State(ctx): State<Arc<Context>>) -> Json<Value> {
    let metrics = ctx.get_metrics_snapshot();
    let mut metrics_value = serde_json::to_value(metrics).unwrap_or_default();

    // Get system stats
    let system_stats = ctx.get_system_stats();

    // Add additional fields for the advanced dashboard
    if let Some(obj) = metrics_value.as_object_mut() {
        obj.insert(
            "block_height".to_string(),
            serde_json::Value::Number(serde_json::Number::from(ctx.get_block_height())),
        );
        obj.insert(
            "temporal_height".to_string(),
            serde_json::Value::Number(serde_json::Number::from(ctx.get_temporal_height())),
        );
        obj.insert(
            "rooted_height".to_string(),
            serde_json::Value::Number(serde_json::Number::from(ctx.get_rooted_height())),
        );
        obj.insert("uptime_formatted".to_string(), serde_json::Value::String(ctx.get_uptime()));
        obj.insert(
            "cpu_usage".to_string(),
            serde_json::Value::Number(
                serde_json::Number::from_f64(system_stats.cpu_usage as f64).unwrap_or(serde_json::Number::from(0)),
            ),
        );
        obj.insert(
            "memory_usage".to_string(),
            serde_json::Value::Number(serde_json::Number::from(system_stats.memory_usage)),
        );
        obj.insert(
            "total_memory".to_string(),
            serde_json::Value::Number(serde_json::Number::from(system_stats.total_memory)),
        );
        obj.insert(
            "cores_available".to_string(),
            serde_json::Value::Number(serde_json::Number::from(system_stats.cores_available)),
        );
    }

    Json(metrics_value)
}

fn api_router(ctx: Arc<Context>) -> Router {
    Router::new().route("/peers", get(api_peers)).route("/metrics", get(api_metrics)).with_state(ctx)
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
