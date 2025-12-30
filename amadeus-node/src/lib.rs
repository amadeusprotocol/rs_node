pub mod attestation;
pub mod config;
pub mod consensus;
pub mod context;
pub mod metrics;
pub mod node;
pub mod socket;

// Re-export utility modules
pub use amadeus_utils as utils;
pub use amadeus_utils::{Database, DatabaseError};

// Re-export consensus modules (primary API - use these!)
pub use amadeus_runtime::consensus::consensus_apply::{ApplyEnv, CallerEnv};
pub use amadeus_runtime::consensus::consensus_muts::Mutation;
pub use amadeus_runtime::consensus::{consensus_apply, consensus_kv, consensus_muts};

// Re-export BIC modules from amadeus-runtime with an alias to avoid conflicts
pub use amadeus_runtime::consensus::bic as runtime_bic;

// Re-export commonly needed constants for HTTP API
pub use amadeus_utils::constants::{CF_CONTRACTSTATE, CF_TX, CF_TX_ACCOUNT_NONCE};

// Re-export coin utilities for HTTP API
pub use amadeus_runtime::consensus::bic::coin::from_flat;

// Re-export base58 decoding utilities for HTTP API
pub use amadeus_utils::misc::{decode_base58_array, decode_base58_hash, decode_base58_pk};

pub use config::Config;
pub use context::{Context, SoftforkStatus};
pub use metrics::{MetricsSnapshot, UdpStats};
pub use node::peers::{PeerInfo, PeersSummary};
pub use utils::system_metrics::{SystemStats, get_system_stats};
pub use utils::version::Ver;
