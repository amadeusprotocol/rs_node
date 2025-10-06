use crate::models::*;
use ama_core::Context;
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
    State(_ctx): State<Arc<Context>>,
    Path(_public_key): Path<String>,
) -> Json<BalanceResponse> {
    Json(BalanceResponse::ok(Balance::new("AMA", 1000000000000, 1000.0)))
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
    State(_ctx): State<Arc<Context>>,
    Path((_public_key, symbol)): Path<(String, String)>,
) -> Json<BalanceResponse> {
    let balance = match symbol.as_str() {
        "AMA" => Balance::new("AMA", 1000000000000, 1000.0),
        "USDT" => Balance::new("USDT", 500000000, 500.0),
        _ => Balance::new(&symbol, 0, 0.0),
    };
    Json(BalanceResponse::ok(balance))
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
    State(_ctx): State<Arc<Context>>,
    Path(_public_key): Path<String>,
) -> Json<AllBalancesResponse> {
    let balances = vec![
        Balance::new("AMA", 1000000000000, 1000.0),
        Balance::new("USDT", 500000000, 500.0),
        Balance::new("ETH", 2000000000000000000, 2.0),
    ];
    Json(AllBalancesResponse::ok(balances))
}
