use amadeus_node::Context;
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use serde_json::Value;
use std::sync::Arc;

pub mod chain;
pub mod contract;
pub mod epoch;
pub mod peer;
pub mod transaction;
pub mod wallet;

pub fn api_router(ctx: Arc<Context>) -> Router {
    Router::new()
        .route("/peer/anr/{publicKey}", get(peer::get_peer_anr))
        .route("/peer/anr_validators", get(peer::get_validator_anrs))
        .route("/peer/anr", get(peer::get_all_anrs))
        .route("/peer/nodes", get(peer::get_all_nodes))
        .route("/peer/trainers", get(peer::get_trainers))
        .route("/peer/removed_trainers", get(peer::get_removed_trainers))
        .route("/chain/stats", get(chain::get_chain_stats))
        .route("/chain/tip", get(chain::get_chain_tip))
        .route("/chain/height/{height}", get(chain::get_entries_by_height))
        .route("/chain/height_with_txs/{height}", get(chain::get_entries_by_height_with_txs))
        .route("/chain/tx/{tx_id}", get(chain::get_transaction_by_id))
        .route("/chain/tx_events_by_account/{account}", get(chain::get_transaction_events_by_account))
        .route("/chain/txs_in_entry/{entry_hash}", get(chain::get_transactions_in_entry))
        .route("/wallet/balance/{public_key}", get(wallet::get_wallet_balance))
        .route("/wallet/balance/{public_key}/{symbol}", get(wallet::get_wallet_balance_by_symbol))
        .route("/wallet/balance_all/{public_key}", get(wallet::get_all_wallet_balances))
        .route("/tx/submit", post(transaction::submit_transaction))
        .route("/tx/submit/{tx_packed_base58}", get(transaction::submit_transaction_via_url))
        .route("/contract/validate_bytecode", post(contract::validate_contract_bytecode))
        .route("/contract/get/{contract_address}/{key}", get(contract::get_contract_state))
        .route("/contract/richlist", get(contract::get_token_richlist))
        .route("/epoch/score", get(epoch::get_current_epoch_score))
        .route("/epoch/score/{public_key}", get(epoch::get_epoch_score_by_validator))
        .route("/epoch/get_emission_address/{public_key}", get(epoch::get_emission_address))
        .with_state(ctx)
}

pub fn v2_router(ctx: Arc<Context>) -> Router {
    Router::new().route("/peers", get(api_peers)).route("/metrics", get(api_metrics)).with_state(ctx)
}

async fn api_peers(State(ctx): State<Arc<Context>>) -> Json<Value> {
    let peers = ctx.get_peers().await;
    Json(serde_json::to_value(peers).unwrap_or_default())
}

async fn api_metrics(State(ctx): State<Arc<Context>>) -> Json<Value> {
    let metrics = ctx.get_metrics_snapshot();
    let mut metrics_value = serde_json::to_value(metrics).unwrap_or_default();

    // Get system stats
    let system_stats = ctx.get_system_stats();

    // Add additional fields for the advanced dashboard
    if let Some(obj) = metrics_value.as_object_mut() {
        obj.insert(
            "block_height".to_string(),
            serde_json::Value::Number(serde_json::Number::from(ctx.get_rooted_height())),
        );
        obj.insert(
            "temporal_height".to_string(),
            serde_json::Value::Number(serde_json::Number::from(ctx.get_temporal_height())),
        );
        obj.insert(
            "rooted_height".to_string(),
            serde_json::Value::Number(serde_json::Number::from(ctx.get_rooted_height())),
        );
        obj.insert("uptime_formatted".to_string(), serde_json::Value::String(ctx.get_uptime()));
        obj.insert(
            "cpu_usage".to_string(),
            serde_json::Value::Number(
                serde_json::Number::from_f64(system_stats.cpu_usage as f64).unwrap_or(serde_json::Number::from(0)),
            ),
        );
        obj.insert(
            "memory_usage".to_string(),
            serde_json::Value::Number(serde_json::Number::from(system_stats.memory_usage)),
        );
        obj.insert(
            "total_memory".to_string(),
            serde_json::Value::Number(serde_json::Number::from(system_stats.total_memory)),
        );
        obj.insert(
            "cores_available".to_string(),
            serde_json::Value::Number(serde_json::Number::from(system_stats.cores_available)),
        );
    }

    Json(metrics_value)
}
