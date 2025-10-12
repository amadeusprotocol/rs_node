use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// Simplified response using Axum best practices
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiResponse<T> {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self { error: "ok".to_string(), data: Some(data) }
    }

    pub fn error(msg: &str) -> Self {
        Self { error: msg.to_string(), data: None }
    }
}

// Core data types
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(title = "ANR")]
pub struct Anr {
    pub ip4: String,
    pub pk: String,
    pub pop: String,
    pub port: u16,
    pub signature: String,
    pub ts: u64,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anr_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anr_desc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NodeInfo {
    pub pk: String,
    pub ip4: String,
    pub version: String,
    pub latency: u64,
    pub last_message: u64,
    pub online: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChainStats {
    pub height: u64,
    pub total_transactions: u64,
    pub total_accounts: u64,
    pub network_hash_rate: String,
    pub difficulty: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlockEntry {
    pub hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub previous_hash: String,
    pub merkle_root: String,
    pub signature: String,
    pub mask: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Transaction {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub amount: String,
    pub symbol: String,
    pub fee: String,
    pub nonce: u64,
    pub timestamp: u64,
    pub signature: String,
    #[serde(rename = "type")]
    pub tx_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlockEntryWithTxs {
    #[serde(flatten)]
    pub entry: BlockEntry,
    pub txs: Vec<Transaction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Balance {
    pub symbol: String,
    pub flat: u64,
    pub float: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RichlistEntry {
    pub address: String,
    pub balance: String,
    pub rank: u64,
}

// From trait implementations for automatic conversions
impl From<&amadeus_node::node::anr::Anr> for Anr {
    fn from(anr_data: &amadeus_node::node::anr::Anr) -> Self {
        Self {
            ip4: anr_data.ip4.to_string(),
            pk: bs58::encode(&anr_data.pk).into_string(),
            pop: bs58::encode(&anr_data.pop).into_string(),
            port: anr_data.port,
            signature: bs58::encode(&anr_data.signature).into_string(),
            ts: anr_data.ts as u64,
            version: anr_data.version.to_string(),
            anr_name: anr_data.anr_name.clone(),
            anr_desc: anr_data.anr_desc.clone(),
        }
    }
}

impl Balance {
    pub fn new(symbol: &str, flat: u64, float: f64) -> Self {
        Self { symbol: symbol.to_string(), flat, float }
    }
}

// Response type aliases using generic ApiResponse
pub type AnrResponse = ApiResponse<Anr>;
pub type AnrsResponse = ApiResponse<Vec<Anr>>;
pub type TrainersResponse = ApiResponse<Vec<String>>;
pub type ChainStatsResponse = ApiResponse<ChainStats>;
pub type ChainTipResponse = ApiResponse<BlockEntry>;
pub type EntriesResponse = ApiResponse<Vec<BlockEntry>>;
pub type EntriesWithTxsResponse = ApiResponse<Vec<BlockEntryWithTxs>>;
pub type TransactionResponse = ApiResponse<Option<Transaction>>;
pub type BalanceResponse = ApiResponse<Balance>;
pub type AllBalancesResponse = ApiResponse<Vec<Balance>>;
pub type RichlistResponse = ApiResponse<Vec<RichlistEntry>>;

// Special response types that don't fit the generic pattern
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransactionEventsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub txs: Vec<Transaction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransactionSubmitResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl TransactionSubmitResponse {
    pub fn ok(tx_hash: String) -> Self {
        Self { error: "ok".to_string(), tx_hash: Some(tx_hash), message: None }
    }

    pub fn error(msg: &str) -> Self {
        Self { error: msg.to_string(), tx_hash: None, message: Some(msg.to_string()) }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BytecodeValidationResponse {
    pub error: String,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_estimate: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

impl BytecodeValidationResponse {
    pub fn ok(valid: bool, gas_estimate: Option<u64>, warnings: Option<Vec<String>>) -> Self {
        Self { error: "ok".to_string(), valid, gas_estimate, warnings }
    }

    pub fn error(msg: &str) -> Self {
        Self { error: msg.to_string(), valid: false, gas_estimate: None, warnings: None }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EpochScoreResponse {
    pub error: String,
    pub score: f64,
    pub epoch: u64,
    pub rank: u64,
}

impl EpochScoreResponse {
    pub fn ok(score: f64, epoch: u64, rank: u64) -> Self {
        Self { error: "ok".to_string(), score, epoch, rank }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EmissionAddressResponse {
    pub error: String,
    pub emission_address: String,
}

impl EmissionAddressResponse {
    pub fn ok(emission_address: String) -> Self {
        Self { error: "ok".to_string(), emission_address }
    }
}

// Simplified aliases
pub type TransactionsInEntryResponse = ApiResponse<Vec<Transaction>>;
pub type ErrorResponse = ApiResponse<()>;
