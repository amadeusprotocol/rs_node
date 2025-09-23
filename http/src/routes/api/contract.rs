use crate::models::*;
use ama_core::Context;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    Json,
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
        Ok(Json(BytecodeValidationResponse::ok(true, Some(100000), Some(vec!["Contract uses experimental features".to_string()]))))
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
    State(_ctx): State<Arc<Context>>,
    Path((_contract_address, key)): Path<(String, String)>,
) -> Json<Value> {
    // placeholder implementation - would query contract state from fabric

    // simulate different contract state values
    let value = match key.as_str() {
        "balance" => serde_json::json!({
            "value": "1000000000000",
            "type": "uint256"
        }),
        "owner" => serde_json::json!({
            "value": "7EVUJfpnEqK32KrzUAaR4Yf26KgT66AWwW63xSHw5mbgdQhV8iwL1NkHMAqTi5Hv3h",
            "type": "address"
        }),
        "name" => serde_json::json!({
            "value": "MyToken",
            "type": "string"
        }),
        _ => serde_json::json!({
            "error": "key_not_found"
        }),
    };

    Json(value)
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
pub async fn get_token_richlist(State(_ctx): State<Arc<Context>>) -> Json<RichlistResponse> {
    // placeholder implementation - would query top token holders from fabric
    let richlist = vec![
        RichlistEntry {
            address: "7EVUJfpnEqK32KrzUAaR4Yf26KgT66AWwW63xSHw5mbgdQhV8iwL1NkHMAqTi5Hv3h".to_string(),
            balance: "10000000.0".to_string(),
            rank: 1,
        },
        RichlistEntry {
            address: "8FWVKgqoFrL43LszVBbS5Zg27LhU67BWxX74yTIx6ocheRiW9jxM2OlINBrTj6Iw4i".to_string(),
            balance: "5000000.0".to_string(),
            rank: 2,
        },
        RichlistEntry {
            address: "6DVTIepmDpJ21KqzTAaQ3Xe25JfS55ATvV52wRGw4lbgcPgT7hvK1MjGLApSh4Gt2g".to_string(),
            balance: "2500000.0".to_string(),
            rank: 3,
        },
        RichlistEntry {
            address: "9HXZNhroGsK54MtzWCcT6Yh38MgV78CWyY85zUIy7pdifSjX0kzN3QmJOCsTk7Jx5j".to_string(),
            balance: "1000000.0".to_string(),
            rank: 4,
        },
        RichlistEntry {
            address: "5JYWIhsnHqP32LqzSBaR3Xe24JeQ44ATuU41wQFw3kbgbOfS6guJ0LjFKApQh3Fu1h".to_string(),
            balance: "500000.0".to_string(),
            rank: 5,
        },
    ];

    Json(RichlistResponse::ok(richlist))
}