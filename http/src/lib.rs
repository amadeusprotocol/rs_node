pub mod models;
mod routes;
pub mod utils;
mod views {
    pub mod advanced;
    pub mod dashboard;
    pub mod entries;
    pub mod errors;
    pub mod incoming;
    pub mod network;
    pub mod outgoing;
    pub mod peers;
}

use ama_core::Context;
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
