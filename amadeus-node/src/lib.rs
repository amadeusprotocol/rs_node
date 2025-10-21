#![allow(dead_code)]

pub mod bic;
pub mod config;
pub mod consensus;
pub mod context;
pub mod kv;
pub mod metrics;
pub mod node;
pub mod socket;
pub mod wasm;

// Re-export utility modules
pub use amadeus_utils as utils;
pub use amadeus_utils::{Database, DatabaseError};

// Re-export consensus modules (primary API - use these!)
pub use amadeus_consensus::consensus::{consensus_apply, consensus_kv, consensus_muts};
pub use amadeus_consensus::consensus::consensus_apply::{ApplyEnv, CallerEnv};
pub use amadeus_consensus::consensus::consensus_muts::Mutation;

// Re-export local kv module (legacy - used only by WASM runtime internally)
pub use kv::{ApplyCtx as ApplyCtxLegacy, Mutation as MutationLegacy, Op as OpLegacy};

pub use config::Config;
pub use context::{Context, SoftforkStatus};
pub use metrics::{MetricsSnapshot, UdpStats};
pub use node::peers::{PeerInfo, PeersSummary};
pub use utils::system_metrics::{SystemStats, get_system_stats};
pub use utils::version::Ver;
