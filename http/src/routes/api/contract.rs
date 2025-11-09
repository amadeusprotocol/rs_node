use crate::models::*;
use amadeus_node::{Context, decode_base58_pk};
use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
};
use serde_json::Value;
use std::sync::Arc;
use utoipa;

// Router function not needed - routes defined in mod.rs

#[utoipa::path(
    post,
    path = "/api/contract/validate_bytecode",
    summary = "Validate contract bytecode",
    description = "Validates WebAssembly bytecode for contract deployment",
    request_body = Vec<u8>,
    responses(
        (status = 200, description = "Bytecode validation result", body = BytecodeValidationResponse)
    ),
    tag = "contract"
)]
pub async fn validate_contract_bytecode(
    State(_ctx): State<Arc<Context>>,
    body: Bytes,
) -> Result<Json<BytecodeValidationResponse>, StatusCode> {
    // placeholder implementation - would validate WASM bytecode

    if body.is_empty() {
        return Ok(Json(BytecodeValidationResponse::error("invalid_bytecode")));
    }

    // simple validation - check if it looks like WASM
    let is_wasm = body.starts_with(b"\x00asm");

    if is_wasm {
        Ok(Json(BytecodeValidationResponse::ok(
            true,
            Some(100000),
            Some(vec!["Contract uses experimental features".to_string()]),
        )))
    } else {
        Ok(Json(BytecodeValidationResponse::error("invalid_bytecode")))
    }
}

#[utoipa::path(
    get,
    path = "/api/contract/get/{contract_address}/{key}",
    summary = "Get contract state",
    description = "Retrieves a specific key from a smart contract's state",
    responses(
        (status = 200, description = "Contract state value retrieved", content_type = "application/json")
    ),
    params(
        ("contract_address" = String, Path, description = "Contract address", example = "7EVUJfpnEqK32KrzUAaR4Yf26KgT66AWwW63xSHw5mbgdQhV8iwL1NkHMAqTi5Hv3h"),
        ("key" = String, Path, description = "State key to retrieve", example = "balance")
    ),
    tag = "contract"
)]
pub async fn get_contract_state(
    State(ctx): State<Arc<Context>>,
    Path((contract_address, key)): Path<(String, String)>,
) -> Json<Value> {
    let contract_bytes = match decode_base58_pk(&contract_address) {
        Some(pk) => pk,
        None => {
            return Json(serde_json::json!({
                "error": "invalid_contract_address"
            }));
        }
    };

    match ctx.get_contract_state(&contract_bytes, key.as_bytes()) {
        Some(value) => Json(serde_json::json!({
            "value": bs58::encode(&value).into_string(),
            "value_utf8": String::from_utf8_lossy(&value).to_string(),
        })),
        None => Json(serde_json::json!({
            "error": "key_not_found"
        })),
    }
}

#[utoipa::path(
    get,
    path = "/api/contract/richlist",
    summary = "Get token richlist",
    description = "Retrieves the richlist showing top token holders",
    responses(
        (status = 200, description = "Token richlist retrieved successfully", body = RichlistResponse)
    ),
    tag = "contract"
)]
pub async fn get_token_richlist(State(ctx): State<Arc<Context>>) -> Json<RichlistResponse> {
    use amadeus_node::CF_CONTRACTSTATE;
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;

    // Define AMA token balance prefix - "bic:balance:AMA:"
    let prefix = b"bic:balance:AMA:";

    // Use a BinaryHeap to keep top 100 holders
    let mut top_balances = BinaryHeap::new();

    if let Ok(items) = ctx.db_iter_prefix(CF_CONTRACTSTATE, prefix) {
        for (key, value) in items {
            // Extract account from key: "bic:balance:AMA:<48_byte_account>"
            if key.len() != prefix.len() + 48 {
                continue;
            }

            let account_bytes = &key[prefix.len()..];
            let account = bs58::encode(account_bytes).into_string();

            // Parse balance from value (stored as i128)
            if value.len() == 16 {
                let balance = i128::from_le_bytes(value.as_slice().try_into().unwrap_or([0; 16]));
                if balance > 0 {
                    // Keep only top 100
                    if top_balances.len() < 100 {
                        top_balances.push(Reverse((balance, account)));
                    } else if let Some(&Reverse((min_balance, _))) = top_balances.peek() {
                        if balance > min_balance {
                            top_balances.pop();
                            top_balances.push(Reverse((balance, account)));
                        }
                    }
                }
            }
        }
    }

    // Convert heap to sorted vector
    let mut richlist_entries = Vec::new();
    while let Some(Reverse((balance, account))) = top_balances.pop() {
        richlist_entries.push((balance, account));
    }
    richlist_entries.sort_by(|a, b| b.0.cmp(&a.0)); // Sort descending by balance

    // Create response with ranks
    let richlist: Vec<RichlistEntry> = richlist_entries
        .into_iter()
        .take(20) // Return top 20 for UI
        .enumerate()
        .map(|(idx, (balance, address))| RichlistEntry {
            address,
            balance: format!("{}", balance as f64 / 1e9), // Convert from nanoAMA to AMA
            rank: (idx + 1) as u64,
        })
        .collect();

    Json(RichlistResponse::ok(richlist))
}
