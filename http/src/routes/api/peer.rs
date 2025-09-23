use crate::models::*;
use ama_core::Context;
use axum::{
    extract::{Path, State},
    Json,
};
use std::sync::Arc;
use utoipa;


#[utoipa::path(
    get,
    path = "/api/peer/anr/{publicKey}",
    summary = "Get ANR by public key",
    description = "Retrieves the Amadeus Node Record (ANR) for a specific peer by their public key. ANRs contain peer connection information, signatures, and metadata.",
    responses(
        (status = 200, description = "ANR found successfully", body = AnrResponse),
        (status = 404, description = "ANR not found", body = ErrorResponse)
    ),
    params(
        ("publicKey" = String, Path, description = "Base58-encoded public key of the peer", example = "7EVUJfpnEqK32KrzUAaR4Yf26KgT66AWwW63xSHw5mbgdQhV8iwL1NkHMAqTi5Hv3h")
    ),
    tag = "peer"
)]
pub async fn get_peer_anr(
    State(ctx): State<Arc<Context>>,
    Path(public_key): Path<String>,
) -> Json<AnrResponse> {
    match ctx.get_anr_by_pk_b58(&public_key).await {
        Some(anr_data) => Json(AnrResponse::ok((&anr_data).into())),
        None => Json(AnrResponse::error("not_found")),
    }
}

#[utoipa::path(
    get,
    path = "/api/peer/anr_validators",
    summary = "Get validator ANRs",
    description = "Retrieves ANRs for all current validator nodes in the network",
    responses(
        (status = 200, description = "Validator ANRs retrieved successfully", body = AnrsResponse)
    ),
    tag = "peer"
)]
pub async fn get_validator_anrs(State(ctx): State<Arc<Context>>) -> Json<AnrsResponse> {
    let anrs = ctx.get_validator_anrs().await
        .iter()
        .map(Into::into)
        .collect();
    Json(AnrsResponse::ok(anrs))
}

#[utoipa::path(
    get,
    path = "/api/peer/anr",
    summary = "Get all ANRs",
    description = "Retrieves ANRs for all known peers in the network",
    responses(
        (status = 200, description = "All ANRs retrieved successfully", body = AnrsResponse)
    ),
    tag = "peer"
)]
pub async fn get_all_anrs(State(ctx): State<Arc<Context>>) -> Json<AnrsResponse> {
    let anrs = ctx.get_all_anrs().await
        .iter()
        .map(Into::into)
        .collect();
    Json(AnrsResponse::ok(anrs))
}

#[utoipa::path(
    get,
    path = "/api/peer/nodes",
    summary = "Get all nodes for web display",
    description = "Retrieves formatted node information suitable for web interfaces",
    responses(
        (status = 200, description = "Nodes retrieved successfully", body = serde_json::Value)
    ),
    tag = "peer"
)]
pub async fn get_all_nodes(State(ctx): State<Arc<Context>>) -> Json<serde_json::Value> {
    // get peer information formatted for web display with online status based on handshake
    let peers = ctx.get_peers().await;
    let all_anrs = ctx.get_all_anrs().await;

    // create a map from IP to public key via ANRs
    let ip_to_pk: std::collections::HashMap<String, String> = all_anrs
        .iter()
        .map(|anr| (anr.ip4.to_string(), bs58::encode(&anr.pk).into_string()))
        .collect();

    let nodes: std::collections::HashMap<String, NodeInfo> = peers
        .into_iter()
        .map(|(ip, peer_info)| {
            let node_info = NodeInfo {
                pk: ip_to_pk.get(&ip).cloned().unwrap_or_else(|| "unknown".to_string()),
                ip4: ip,
                version: peer_info.version.map(|v| v.to_string()).unwrap_or_else(|| "unknown".to_string()),
                latency: peer_info.latency,
                last_message: peer_info.last_ts,
                online: matches!(peer_info.handshake_status, ama_core::node::peers::HandshakeStatus::Completed),
            };
            (node_info.ip4.clone(), node_info)
        })
        .collect();
    Json(serde_json::to_value(nodes).unwrap_or_default())
}

#[utoipa::path(
    get,
    path = "/api/peer/trainers",
    summary = "Get trainer nodes",
    description = "Retrieves information about all trainer/validator nodes",
    responses(
        (status = 200, description = "Trainers retrieved successfully", body = TrainersResponse)
    ),
    tag = "peer"
)]
pub async fn get_trainers(State(_ctx): State<Arc<Context>>) -> Json<TrainersResponse> {
    // placeholder implementation - in a real system, this would query the trainer registry
    let trainers = vec![
        "7EVUJfpnEqK32KrzUAaR4Yf26KgT66AWwW63xSHw5mbgdQhV8iwL1NkHMAqTi5Hv3h".to_string(),
        "8FWVKgqoFrL43LszVBbS5Zg27LhU67BWxX74yTIx6ocheRiW9jxM2OlINBrTj6Iw4i".to_string(),
    ];

    Json(TrainersResponse::ok(trainers))
}

#[utoipa::path(
    get,
    path = "/api/peer/removed_trainers",
    summary = "Get removed trainers",
    description = "Retrieves information about trainers that have been removed from the network",
    responses(
        (status = 200, description = "Removed trainers retrieved successfully", body = TrainersResponse)
    ),
    tag = "peer"
)]
pub async fn get_removed_trainers(State(_ctx): State<Arc<Context>>) -> Json<TrainersResponse> {
    // placeholder implementation - in a real system, this would query removed trainers
    let removed_trainers = vec![
        "6DVTIepmDpJ21KqzTAaQ3Xe25JfS55ATvV52wRGw4lbgcPgT7hvK1MjGLApSh4Gt2g".to_string(),
    ];

    Json(TrainersResponse::ok(removed_trainers))
}