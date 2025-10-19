#![allow(dead_code)]

pub mod bic;
pub mod config;
pub mod consensus;
pub mod context;
pub mod metrics;
pub mod node;
pub mod socket;

// Re-export utility modules
pub use amadeus_utils as utils;
pub use amadeus_utils::{Database, DatabaseError};

// Re-export runtime modules
pub use amadeus_runtime::{bic as runtime_bic, wasm, ApplyCtx, Mutation, Op};

pub use config::Config;
pub use context::{Context, SoftforkStatus};
pub use metrics::{MetricsSnapshot, UdpStats};
pub use node::peers::{PeerInfo, PeersSummary};
pub use utils::system_metrics::{SystemStats, get_system_stats};
pub use utils::version::Ver;
