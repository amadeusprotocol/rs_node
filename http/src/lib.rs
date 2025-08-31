pub mod models;
mod routes;
mod views {
    pub mod metrics;
    pub mod peers;
}

use ama_core::Context;
use axum::{response::Html, routing::get};
use std::process;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

pub async fn serve(socket: TcpListener, ctx: Arc<Context>) -> anyhow::Result<()> {
    let app = routes::app(ctx.clone())
        .route(
            "/",
            get(|| async {
                info!("GET /");
                Html(get_embedded_simple_dashboard())
            }),
        )
        .route(
            "/advanced",
            get(|| async {
                info!("GET /advanced");
                Html(get_embedded_dashboard())
            }),
        )
        .nest_service("/static", ServeDir::new("http/static"))
        // Add timeout for regular requests (SSE streams handle their own timeouts)
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(TraceLayer::new_for_http());

    info!(
        "http server listening on {}",
        socket.local_addr().map(|a| a.to_string()).unwrap_or_else(|_| "unknown".into())
    );

    if let Err(e) = axum::serve(socket, app).with_graceful_shutdown(shutdown_signal()).await {
        error!("http server error: {}", e);
    }
    Ok(())
}

fn get_embedded_simple_dashboard() -> String {
    include_str!("../static/simple-dashboard.html").to_string()
}

fn get_embedded_dashboard() -> String {
    include_str!("../static/dashboard.html").to_string()
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
