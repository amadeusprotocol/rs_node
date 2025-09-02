#![allow(dead_code)]

use crate::node::{anr, peers};

pub mod bic;
pub mod config;
pub mod consensus;
pub mod context;
pub mod genesis;
pub mod metrics;
pub mod node;
pub mod socket;
pub mod utils;
pub mod wasm;

pub use context::{Context, PeerInfo};
pub use metrics::{MetricsSnapshot, UdpStats};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Fabric(#[from] consensus::fabric::Error),
    #[error(transparent)]
    Archiver(#[from] utils::archiver::Error),
    #[error(transparent)]
    Protocol(#[from] node::protocol::Error),
    #[error(transparent)]
    Config(#[from] config::Error),
    #[error(transparent)]
    Anr(#[from] anr::Error),
    #[error(transparent)]
    Peers(#[from] peers::Error),
    #[error("{0}")]
    String(String),
}
