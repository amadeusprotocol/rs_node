use crate::models::*;
use ama_core::Context;
use axum::{
    extract::{Path, State},
    Json,
};
use std::sync::Arc;
use utoipa;

// Router function not needed - routes defined in mod.rs

#[utoipa::path(
    get,
    path = "/api/epoch/score",
    summary = "Get current epoch score",
    description = "Retrieves the current node's epoch score and ranking",
    responses(
        (status = 200, description = "Epoch score retrieved successfully", body = EpochScoreResponse)
    ),
    tag = "epoch"
)]
pub async fn get_current_epoch_score(State(_ctx): State<Arc<Context>>) -> Json<EpochScoreResponse> {
    // placeholder implementation - would query current node's epoch score
    Json(EpochScoreResponse::ok(95.5, 203, 5))
}

#[utoipa::path(
    get,
    path = "/api/epoch/score/{public_key}",
    summary = "Get epoch score by validator",
    description = "Retrieves epoch score and ranking for a specific validator",
    responses(
        (status = 200, description = "Validator epoch score retrieved successfully", body = EpochScoreResponse)
    ),
    params(
        ("public_key" = String, Path, description = "Validator's Base58-encoded public key", example = "7EVUJfpnEqK32KrzUAaR4Yf26KgT66AWwW63xSHw5mbgdQhV8iwL1NkHMAqTi5Hv3h")
    ),
    tag = "epoch"
)]
pub async fn get_epoch_score_by_validator(
    State(_ctx): State<Arc<Context>>,
    Path(public_key): Path<String>,
) -> Json<EpochScoreResponse> {
    // placeholder implementation - would query specific validator's epoch score

    // simulate different scores based on public key
    let (score, rank) = if public_key.starts_with("7EVU") {
        (98.2, 1)
    } else if public_key.starts_with("8FWV") {
        (97.1, 2)
    } else if public_key.starts_with("6DVT") {
        (89.3, 8)
    } else {
        (75.0, 15)
    };

    Json(EpochScoreResponse::ok(score, 203, rank))
}

#[utoipa::path(
    get,
    path = "/api/epoch/get_emission_address/{public_key}",
    summary = "Get emission address",
    description = "Retrieves the emission address for a specific validator",
    responses(
        (status = 200, description = "Emission address retrieved successfully", body = EmissionAddressResponse)
    ),
    params(
        ("public_key" = String, Path, description = "Validator's Base58-encoded public key", example = "7EVUJfpnEqK32KrzUAaR4Yf26KgT66AWwW63xSHw5mbgdQhV8iwL1NkHMAqTi5Hv3h")
    ),
    tag = "epoch"
)]
pub async fn get_emission_address(
    State(_ctx): State<Arc<Context>>,
    Path(public_key): Path<String>,
) -> Json<EmissionAddressResponse> {
    // placeholder implementation - would derive emission address for validator

    // simulate emission address generation
    let emission_address = format!("emission_{}", &public_key[..8]);

    Json(EmissionAddressResponse::ok(emission_address))
}