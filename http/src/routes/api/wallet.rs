use crate::models::*;
use amadeus_node::{Context, decode_base58_pk};
use axum::{
    Json,
    extract::{Path, State},
};
use std::sync::Arc;
use utoipa;

#[utoipa::path(
    get,
    path = "/api/wallet/balance/{public_key}",
    summary = "Get wallet balance",
    description = "Retrieves the AMA token balance for a specific public key",
    responses(
        (status = 200, description = "Balance retrieved successfully", body = BalanceResponse)
    ),
    params(
        ("public_key" = String, Path, description = "Base58-encoded public key", example = "7EVUJfpnEqK32KrzUAaR4Yf26KgT66AWwW63xSHw5mbgdQhV8iwL1NkHMAqTi5Hv3h")
    ),
    tag = "wallet"
)]
pub async fn get_wallet_balance(
    State(ctx): State<Arc<Context>>,
    Path(public_key): Path<String>,
) -> Json<BalanceResponse> {
    let pk_bytes = match decode_base58_pk(&public_key) {
        Some(pk) => pk,
        None => return Json(BalanceResponse::error("invalid_public_key")),
    };

    let flat = ctx.get_wallet_balance(&pk_bytes, b"AMA");
    use amadeus_node::from_flat;
    Json(BalanceResponse::ok(Balance::new("AMA", flat as u64, from_flat(flat))))
}

#[utoipa::path(
    get,
    path = "/api/wallet/balance/{public_key}/{symbol}",
    summary = "Get wallet balance by symbol",
    description = "Retrieves the balance for a specific token symbol and public key",
    responses(
        (status = 200, description = "Balance retrieved successfully", body = BalanceResponse)
    ),
    params(
        ("public_key" = String, Path, description = "Base58-encoded public key", example = "7EVUJfpnEqK32KrzUAaR4Yf26KgT66AWwW63xSHw5mbgdQhV8iwL1NkHMAqTi5Hv3h"),
        ("symbol" = String, Path, description = "Token symbol", example = "AMA")
    ),
    tag = "wallet"
)]
pub async fn get_wallet_balance_by_symbol(
    State(ctx): State<Arc<Context>>,
    Path((public_key, symbol)): Path<(String, String)>,
) -> Json<BalanceResponse> {
    let pk_bytes = match decode_base58_pk(&public_key) {
        Some(pk) => pk,
        None => return Json(BalanceResponse::error("invalid_public_key")),
    };

    let flat = ctx.get_wallet_balance(&pk_bytes, symbol.as_bytes());
    use amadeus_node::from_flat;
    Json(BalanceResponse::ok(Balance::new(&symbol, flat as u64, from_flat(flat))))
}

#[utoipa::path(
    get,
    path = "/api/wallet/balance_all/{public_key}",
    summary = "Get all wallet balances",
    description = "Retrieves balances for all tokens held by a specific public key",
    responses(
        (status = 200, description = "All balances retrieved successfully", body = AllBalancesResponse)
    ),
    params(
        ("public_key" = String, Path, description = "Base58-encoded public key", example = "7EVUJfpnEqK32KrzUAaR4Yf26KgT66AWwW63xSHw5mbgdQhV8iwL1NkHMAqTi5Hv3h")
    ),
    tag = "wallet"
)]
pub async fn get_all_wallet_balances(
    State(ctx): State<Arc<Context>>,
    Path(public_key): Path<String>,
) -> Json<AllBalancesResponse> {
    let pk_bytes = match decode_base58_pk(&public_key) {
        Some(pk) => pk,
        None => return Json(AllBalancesResponse::error("invalid_public_key")),
    };

    use amadeus_node::from_flat;
    let balances: Vec<Balance> = ctx
        .get_all_wallet_balances(&pk_bytes)
        .into_iter()
        .map(|(symbol, flat)| {
            let symbol_str = String::from_utf8_lossy(&symbol).to_string();
            Balance::new(&symbol_str, flat as u64, from_flat(flat))
        })
        .collect();
    Json(AllBalancesResponse::ok(balances))
}
