pub mod models;
pub mod openapi;
mod routes;
pub mod utils;
mod views {
    pub mod advanced;
    pub mod not_found;
}

use ama_core::Context;
use axum::http::{StatusCode, header};
use axum::routing::get;
use std::process;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

async fn favicon() -> impl axum::response::IntoResponse {
    match tokio::fs::read("http/static/favicon.ico").await {
        Ok(content) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "image/x-icon"), (header::CACHE_CONTROL, "public, max-age=86400")],
            content,
        ),
        Err(_) => {
            (StatusCode::NOT_FOUND, [(header::CONTENT_TYPE, "text/plain"), (header::CACHE_CONTROL, "no-cache")], vec![])
        }
    }
}

pub async fn serve(socket: TcpListener, ctx: Arc<Context>) -> anyhow::Result<()> {
    let app = routes::app(ctx.clone())
        .route("/favicon.ico", get(favicon))
        .nest_service("/static", ServeDir::new("http/static"))
        // Add timeout for regular requests (SSE streams handle their own timeouts)
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(TraceLayer::new_for_http());

    if let Err(e) = axum::serve(socket, app).with_graceful_shutdown(shutdown_signal()).await {
        error!("http server error: {}", e);
    }
    Ok(())
}

async fn shutdown_signal() {
    // wait for ctrl-c or termination signal
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("shutdown signal received");

    process::exit(0);
}
