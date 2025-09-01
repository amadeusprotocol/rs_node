use ama_core::Context;
use axum::Router;
use std::sync::Arc;

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
        .nest("/peers", peers::router(ctx.clone()))
        .nest("/incoming", incoming::router(ctx.clone()))
        .nest("/outgoing", outgoing::router(ctx.clone()))
        .nest("/network", network::router(ctx.clone()))
        .nest("/errors", errors::router(ctx.clone()))
        .nest("/entries", entries::router(ctx.clone()))
}
