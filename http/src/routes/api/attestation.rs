//! SGX Attestation API endpoints
//!
//! Provides REST API for retrieving SGX attestation quotes and verification data

use amadeus_node::attestation::{get_attestation_report, get_attestation_with_pubkey, is_attestation_available};
use amadeus_node::utils::PublicKey;
use amadeus_node::Context;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Response for attestation availability check
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationAvailabilityResponse {
    /// Whether SGX attestation is available
    pub available: bool,
    /// Attestation type if available (e.g., "dcap", "none")
    pub attestation_type: Option<String>,
    /// Node's public key (base58-encoded)
    pub node_public_key: String,
}

/// Response containing SGX attestation quote
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationQuoteResponse {
    /// Base64-encoded SGX quote
    pub quote: String,
    /// Attestation type (e.g., "dcap")
    pub attestation_type: String,
    /// Size of the quote in bytes
    pub quote_size: usize,
    /// User report data embedded in the quote (base64-encoded)
    pub user_report_data: String,
    /// Node's public key that was hashed into report data (base58-encoded)
    pub node_public_key: String,
    /// SHA256 hash of the public key (hex-encoded) - this should match first 32 bytes of user_report_data
    pub pubkey_hash: String,
}

/// Error response for attestation endpoints
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationErrorResponse {
    /// Error message
    pub error: String,
    /// Error details
    pub details: Option<String>,
}

impl IntoResponse for AttestationErrorResponse {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response()
    }
}

/// GET /api/attestation/available
///
/// Check if SGX attestation is available on this node
///
/// # Returns
///
/// - `200 OK` with availability status and node public key
///
/// # Example Response
///
/// ```json
/// {
///   "available": true,
///   "attestation_type": "dcap",
///   "node_public_key": "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn"
/// }
/// ```
pub async fn get_attestation_availability(
    State(ctx): State<Arc<Context>>,
) -> Result<Json<AttestationAvailabilityResponse>, AttestationErrorResponse> {
    let available = is_attestation_available();

    let attestation_type = if available {
        match amadeus_node::attestation::get_attestation_type() {
            Ok(t) => Some(t),
            Err(_) => None,
        }
    } else {
        None
    };

    let node_public_key = bs58::encode(ctx.get_public_key()).into_string();

    Ok(Json(AttestationAvailabilityResponse {
        available,
        attestation_type,
        node_public_key,
    }))
}

/// GET /api/attestation/quote
///
/// Get SGX attestation quote with node's public key embedded
///
/// The quote contains:
/// - SGX enclave measurements (MRENCLAVE, MRSIGNER)
/// - Node's public key hash in the user report data field
/// - Complete certificate chain for DCAP verification
///
/// Remote verifiers can:
/// 1. Verify the quote against Intel's DCAP infrastructure
/// 2. Extract and verify the node's public key hash from user_report_data
/// 3. Establish that they're communicating with a genuine SGX enclave running the expected code
///
/// # Returns
///
/// - `200 OK` with SGX quote and metadata
/// - `500 Internal Server Error` if attestation fails or is not available
///
/// # Example Response
///
/// ```json
/// {
///   "quote": "AwACAAAAAAAHAA4Ak5pyM...(base64)...",
///   "attestation_type": "dcap",
///   "quote_size": 4321,
///   "user_report_data": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a0000...(base64)...",
///   "node_public_key": "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn",
///   "pubkey_hash": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
/// }
/// ```
pub async fn get_attestation_quote(
    State(ctx): State<Arc<Context>>,
) -> Result<Json<AttestationQuoteResponse>, AttestationErrorResponse> {
    let public_key = ctx.get_public_key();

    // Get attestation with pubkey embedded
    let report = get_attestation_with_pubkey(public_key.as_ref()).map_err(|e| AttestationErrorResponse {
        error: "Failed to generate attestation quote".to_string(),
        details: Some(format!("{}", e)),
    })?;

    // Calculate pubkey hash for response (for convenience)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(<PublicKey as AsRef<[u8]>>::as_ref(&public_key));
    let pubkey_hash = hex::encode(hasher.finalize());

    let node_public_key = bs58::encode(<PublicKey as AsRef<[u8]>>::as_ref(&public_key)).into_string();

    Ok(Json(AttestationQuoteResponse {
        quote: report.quote,
        attestation_type: report.attestation_type,
        quote_size: report.quote_size,
        user_report_data: report.user_report_data,
        node_public_key,
        pubkey_hash,
    }))
}

/// GET /api/attestation/quote/raw
///
/// Get raw SGX quote without any custom user data
///
/// This endpoint generates a quote with zero-filled user report data,
/// useful for basic attestation without embedding node-specific information.
///
/// # Returns
///
/// - `200 OK` with raw SGX quote
/// - `500 Internal Server Error` if attestation fails or is not available
pub async fn get_raw_attestation_quote(
    State(_ctx): State<Arc<Context>>,
) -> Result<Json<serde_json::Value>, AttestationErrorResponse> {
    let report = get_attestation_report(None).map_err(|e| AttestationErrorResponse {
        error: "Failed to generate attestation quote".to_string(),
        details: Some(format!("{}", e)),
    })?;

    Ok(Json(serde_json::json!({
        "quote": report.quote,
        "attestation_type": report.attestation_type,
        "quote_size": report.quote_size,
        "user_report_data": report.user_report_data,
    })))
}
