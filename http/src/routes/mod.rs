use ama_core::Context;
use axum::{Router, extract::State, response::Json, routing::get};
use serde_json::Value;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use sysinfo::{ProcessesToUpdate, System};
use tokio::time::{Duration, interval};

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

/// Global system monitor instance that persists between calls
static SYSTEM_MONITOR: LazyLock<Mutex<System>> = LazyLock::new(|| {
    let mut system = System::new_all();
    system.refresh_all();
    Mutex::new(system)
});

/// Cached system stats - updated periodically by background task
static CACHED_CPU_USAGE: AtomicU32 = AtomicU32::new(0); // Store as u32 (percentage * 100 for precision)
static CACHED_MEMORY_USAGE: AtomicU64 = AtomicU64::new(0);
static STATS_UPDATER_STARTED: std::sync::Once = std::sync::Once::new();

/// Start the background system stats updater
fn ensure_stats_updater_started() {
    STATS_UPDATER_STARTED.call_once(|| {
        tokio::spawn(async {
            let mut interval = interval(Duration::from_millis(500)); // Update every 500ms

            loop {
                interval.tick().await;

                if let Ok(current_pid) = sysinfo::get_current_pid() {
                    if let Ok(mut system) = SYSTEM_MONITOR.lock() {
                        system.refresh_processes(ProcessesToUpdate::Some(&[current_pid]), true);

                        if let Some(process) = system.process(current_pid) {
                            let cpu_usage = process.cpu_usage();
                            let memory_usage = process.memory();

                            // Store CPU usage with precision (multiply by 100)
                            CACHED_CPU_USAGE.store((cpu_usage * 100.0) as u32, Ordering::Relaxed);
                            CACHED_MEMORY_USAGE.store(memory_usage, Ordering::Relaxed);
                        }
                    }
                }
            }
        });
    });
}

/// Get current process CPU and memory usage from cache
fn get_system_stats() -> (f32, u64, usize) {
    ensure_stats_updater_started();

    let cpu_usage = CACHED_CPU_USAGE.load(Ordering::Relaxed) as f32 / 100.0;
    let memory_usage = CACHED_MEMORY_USAGE.load(Ordering::Relaxed);

    // Get number of logical CPU cores available to the system
    let cores_available = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1); // Fallback to 1 if unable to determine

    (cpu_usage, memory_usage, cores_available)
}

async fn api_metrics(State(ctx): State<Arc<Context>>) -> Json<Value> {
    let metrics = ctx.get_metrics_snapshot();
    let mut metrics_value = serde_json::to_value(metrics).unwrap_or_default();

    // Get system stats
    let (cpu_usage, memory_usage, cores_available) = get_system_stats();

    // Add additional fields for the advanced dashboard
    if let Some(obj) = metrics_value.as_object_mut() {
        obj.insert(
            "block_height".to_string(),
            serde_json::Value::Number(serde_json::Number::from(ctx.get_block_height())),
        );
        obj.insert("uptime_formatted".to_string(), serde_json::Value::String(ctx.get_uptime()));
        obj.insert(
            "cpu_usage".to_string(),
            serde_json::Value::Number(
                serde_json::Number::from_f64(cpu_usage as f64).unwrap_or(serde_json::Number::from(0)),
            ),
        );
        obj.insert("memory_usage".to_string(), serde_json::Value::Number(serde_json::Number::from(memory_usage)));
        obj.insert("cores_available".to_string(), serde_json::Value::Number(serde_json::Number::from(cores_available)));
    }

    Json(metrics_value)
}

fn api_router(ctx: Arc<Context>) -> Router {
    Router::new().route("/peers", get(api_peers)).route("/metrics", get(api_metrics)).with_state(ctx)
}
