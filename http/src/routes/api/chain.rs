use crate::models::*;
use amadeus_node::utils::Hash;
use amadeus_node::{Context, decode_base58_hash, decode_base58_pk};
use axum::{
    Json,
    extract::{Path, State},
};
use std::sync::Arc;
use utoipa;

#[utoipa::path(
    get,
    path = "/api/chain/stats",
    summary = "Get blockchain statistics",
    description = "Retrieves current blockchain statistics including height, transaction counts, and network metrics.",
    responses(
        (status = 200, description = "Chain statistics retrieved successfully", body = ChainStatsResponse)
    ),
    tag = "chain"
)]
pub async fn get_chain_stats(State(ctx): State<Arc<Context>>) -> Json<ChainStatsResponse> {
    let stats = ChainStats {
        height: ctx.get_rooted_height(),
        total_transactions: 0, // would need to scan CF_TX
        total_accounts: 0,     // would need to scan CF_CONTRACTSTATE
        network_hash_rate: format!("{} H/s", ctx.get_chain_total_sols()),
        difficulty: format!("0x{:08x}", ctx.get_chain_diff_bits()),
    };

    Json(ChainStatsResponse::ok(stats))
}

#[utoipa::path(
    get,
    path = "/api/chain/tip",
    summary = "Get chain tip",
    description = "Retrieves the current tip (latest block) of the blockchain",
    responses(
        (status = 200, description = "Chain tip retrieved successfully", body = ChainTipResponse)
    ),
    tag = "chain"
)]
pub async fn get_chain_tip(State(ctx): State<Arc<Context>>) -> Json<ChainTipResponse> {
    match ctx.get_temporal_entry() {
        Ok(Some(entry)) => {
            let block_entry = BlockEntry::from(&entry);
            Json(ChainTipResponse::ok(block_entry))
        }
        Ok(None) => Json(ChainTipResponse::error("no_tip_found")),
        Err(_) => Json(ChainTipResponse::error("query_failed")),
    }
}

#[utoipa::path(
    get,
    path = "/api/chain/height/{height}",
    summary = "Get entries by height",
    description = "Retrieves blockchain entries at a specific height",
    responses(
        (status = 200, description = "Entries retrieved successfully", body = EntriesResponse)
    ),
    params(
        ("height" = u64, Path, description = "Block height to query", example = 12345)
    ),
    tag = "chain"
)]
pub async fn get_entries_by_height(State(ctx): State<Arc<Context>>, Path(height): Path<u64>) -> Json<EntriesResponse> {
    match ctx.get_entries_by_height(height) {
        Ok(entries) => {
            let block_entries: Vec<BlockEntry> = entries.into_iter().map(|entry| BlockEntry::from(&entry)).collect();
            Json(EntriesResponse::ok(block_entries))
        }
        Err(_) => Json(EntriesResponse::ok(vec![])),
    }
}

#[utoipa::path(
    get,
    path = "/api/chain/height_with_txs/{height}",
    summary = "Get entries by height with transactions",
    description = "Retrieves blockchain entries at a specific height including all transactions",
    responses(
        (status = 200, description = "Entries with transactions retrieved successfully", body = EntriesWithTxsResponse)
    ),
    params(
        ("height" = u64, Path, description = "Block height to query", example = 12345)
    ),
    tag = "chain"
)]
pub async fn get_entries_by_height_with_txs(
    State(ctx): State<Arc<Context>>,
    Path(height): Path<u64>,
) -> Json<EntriesWithTxsResponse> {
    match ctx.get_entries_by_height(height) {
        Ok(entries) => {
            let entries_with_txs: Vec<BlockEntryWithTxs> = entries
                .into_iter()
                .map(|entry| {
                    let block_entry = BlockEntry::from(&entry);
                    let txs: Vec<Transaction> = entry.txs.iter().map(Transaction::from).collect();
                    BlockEntryWithTxs { entry: block_entry, txs }
                })
                .collect();
            Json(EntriesWithTxsResponse::ok(entries_with_txs))
        }
        Err(_) => Json(EntriesWithTxsResponse::ok(vec![])),
    }
}

#[utoipa::path(
    get,
    path = "/api/chain/tx/{tx_id}",
    summary = "Get transaction by ID",
    description = "Retrieves a specific transaction by its ID",
    responses(
        (status = 200, description = "Transaction retrieved successfully", body = TransactionResponse),
        (status = 404, description = "Transaction not found", body = TransactionResponse)
    ),
    params(
        ("tx_id" = String, Path, description = "Transaction ID", example = "tx_12345")
    ),
    tag = "chain"
)]
pub async fn get_transaction_by_id(
    State(ctx): State<Arc<Context>>,
    Path(tx_id): Path<String>,
) -> Json<TransactionResponse> {
    use amadeus_node::CF_TX;

    let tx_hash = match decode_base58_hash(&tx_id) {
        Some(hash) => hash,
        None => return Json(TransactionResponse::error("invalid_tx_hash")),
    };

    // Query CF_TX to get entry_hash
    let entry_hash = match ctx.db_get(CF_TX, tx_hash.as_ref()) {
        Ok(Some(hash)) if hash.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);
            arr
        }
        _ => return Json(TransactionResponse::error("not_found")),
    };

    if let Some(entry) = ctx.get_entry_by_hash(&Hash::from(entry_hash)) {
        for tx in &entry.txs {
            if tx.hash == tx_hash {
                let mut transaction = Transaction::from(tx);
                transaction.hash = tx_id;
                return Json(TransactionResponse::ok(Some(transaction)));
            }
        }
    }

    Json(TransactionResponse::error("not_found"))
}

#[utoipa::path(
    get,
    path = "/api/chain/tx_events_by_account/{account}",
    summary = "Get transaction events by account",
    description = "Retrieves transaction events for a specific account",
    responses(
        (status = 200, description = "Transaction events retrieved successfully", body = TransactionEventsResponse)
    ),
    params(
        ("account" = String, Path, description = "Account public key", example = "7EVUJfpnEqK32KrzUAaR4Yf26KgT66AWwW63xSHw5mbgdQhV8iwL1NkHMAqTi5Hv3h")
    ),
    tag = "chain"
)]
pub async fn get_transaction_events_by_account(
    State(ctx): State<Arc<Context>>,
    Path(account): Path<String>,
) -> Json<TransactionEventsResponse> {
    use amadeus_node::{CF_TX, CF_TX_ACCOUNT_NONCE};

    // Decode account public key from base58
    let account_bytes = match decode_base58_pk(&account) {
        Some(pk) => pk,
        None => return Json(TransactionEventsResponse { cursor: None, txs: vec![] }),
    };

    // Scan CF_TX_ACCOUNT_NONCE with account prefix
    let mut transactions = Vec::new();
    if let Ok(items) = ctx.db_iter_prefix(CF_TX_ACCOUNT_NONCE, account_bytes.as_ref()) {
        // Limit to first 20 transactions for performance
        for (_key, tx_hash) in items.into_iter().take(20) {
            if tx_hash.len() != 32 {
                continue;
            }

            let mut tx_hash_arr = [0u8; 32];
            tx_hash_arr.copy_from_slice(&tx_hash);

            // Get entry hash from CF_TX
            if let Ok(Some(entry_hash)) = ctx.db_get(CF_TX, &tx_hash_arr) {
                if entry_hash.len() != 32 {
                    continue;
                }

                let mut entry_hash_arr = [0u8; 32];
                entry_hash_arr.copy_from_slice(&entry_hash);

                if let Some(entry) = ctx.get_entry_by_hash(&Hash::from(entry_hash_arr)) {
                    for tx in &entry.txs {
                        if tx.hash == tx_hash_arr {
                            transactions.push(Transaction::from(tx));
                            break;
                        }
                    }
                }
            }
        }
    }

    Json(TransactionEventsResponse {
        cursor: if transactions.len() == 20 { Some("next".to_string()) } else { None },
        txs: transactions,
    })
}

#[utoipa::path(
    get,
    path = "/api/chain/txs_in_entry/{entry_hash}",
    summary = "Get transactions in entry",
    description = "Retrieves all transactions within a specific blockchain entry",
    responses(
        (status = 200, description = "Transactions retrieved successfully", body = TransactionsInEntryResponse)
    ),
    params(
        ("entry_hash" = String, Path, description = "Entry hash", example = "0x1234567890abcdef")
    ),
    tag = "chain"
)]
pub async fn get_transactions_in_entry(
    State(ctx): State<Arc<Context>>,
    Path(entry_hash): Path<String>,
) -> Json<TransactionsInEntryResponse> {
    // Decode hash from base58
    let hash_bytes = match decode_base58_hash(&entry_hash) {
        Some(hash) => hash,
        None => return Json(TransactionsInEntryResponse::ok(vec![])),
    };

    if let Some(entry) = ctx.get_entry_by_hash(&hash_bytes) {
        let transactions: Vec<Transaction> = entry.txs.iter().map(Transaction::from).collect();
        Json(TransactionsInEntryResponse::ok(transactions))
    } else {
        Json(TransactionsInEntryResponse::ok(vec![]))
    }
}
