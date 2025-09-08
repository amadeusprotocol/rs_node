/// System metrics for CPU and memory usage
#[derive(Debug, Clone)]
pub struct SystemStats {
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub cores_available: usize,
}

impl Default for SystemStats {
    fn default() -> Self {
        Self {
            cpu_usage: 0.0,
            memory_usage: 0,
            cores_available: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        }
    }
}

#[cfg(feature = "system-metrics")]
mod inner {
    use std::sync::LazyLock;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use sysinfo::{ProcessesToUpdate, System};
    use tokio::time::{Duration, interval};

    use super::*;

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
    pub fn get_system_stats() -> SystemStats {
        ensure_stats_updater_started();

        let cpu_usage = CACHED_CPU_USAGE.load(Ordering::Relaxed) as f32 / 100.0;
        let memory_usage = CACHED_MEMORY_USAGE.load(Ordering::Relaxed);
        let cores_available = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);

        SystemStats { cpu_usage, memory_usage, cores_available }
    }
}

/// Get current system statistics (CPU, memory usage and available cores)
/// Returns default values when system-metrics feature is disabled
pub fn get_system_stats() -> SystemStats {
    #[cfg(feature = "system-metrics")]
    {
        inner::get_system_stats()
    }
    #[cfg(not(feature = "system-metrics"))]
    {
        SystemStats::default()
    }
}
