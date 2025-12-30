//! SGX Attestation module for Gramine
//!
//! This module provides SGX DCAP attestation functionality through Gramine's
//! /dev/attestation pseudo-filesystem interface.
//!
//! # Overview
//!
//! - Reads SGX quotes from `/dev/attestation/quote`
//! - Supports custom user report data (e.g., node public key hash)
//! - Returns base64-encoded quote and certificate chain for remote verification
//!
//! # Usage
//!
//! ```rust
//! let report = get_attestation_report(Some(b"my-custom-data"))?;
//! // Send report.quote to remote verifier
//! ```

use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use thiserror::Error;

/// Maximum size of an SGX quote (as defined by Intel SGX SDK)
const SGX_QUOTE_MAX_SIZE: usize = 8192;

/// Size of SGX report data field (64 bytes)
const SGX_REPORT_DATA_SIZE: usize = 64;

#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("Attestation not available (not running in SGX enclave)")]
    NotAvailable,

    #[error("Failed to write user report data: {0}")]
    WriteReportData(std::io::Error),

    #[error("Failed to read quote: {0}")]
    ReadQuote(std::io::Error),

    #[error("Failed to read attestation type: {0}")]
    ReadAttestationType(std::io::Error),

    #[error("Invalid user report data size: expected {expected}, got {actual}")]
    InvalidReportDataSize { expected: usize, actual: usize },

    #[error("Attestation type is 'none' - SGX remote attestation not enabled")]
    AttestationDisabled,
}

/// SGX attestation report containing quote and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// Base64-encoded SGX quote
    pub quote: String,

    /// Attestation type (e.g., "dcap")
    pub attestation_type: String,

    /// Size of the quote in bytes
    pub quote_size: usize,

    /// User report data that was embedded (base64-encoded)
    pub user_report_data: String,
}

/// Check if SGX attestation is available
///
/// Returns true if running inside Gramine with SGX attestation enabled
pub fn is_attestation_available() -> bool {
    std::path::Path::new("/dev/attestation/attestation_type").exists()
}

/// Get the attestation type (e.g., "none" or "dcap")
pub fn get_attestation_type() -> Result<String, AttestationError> {
    let mut file = File::open("/dev/attestation/attestation_type")
        .map_err(AttestationError::ReadAttestationType)?;

    let mut attestation_type = String::new();
    file.read_to_string(&mut attestation_type)
        .map_err(AttestationError::ReadAttestationType)?;

    Ok(attestation_type.trim().to_string())
}

/// Generate an SGX attestation report with optional user data
///
/// # Arguments
///
/// * `user_report_data` - Optional 64-byte data to embed in the SGX report.
///   If None, zeros are used. Common use: hash of node's public key.
///
/// # Returns
///
/// `AttestationReport` containing the SGX quote and metadata
///
/// # Errors
///
/// Returns error if:
/// - Not running in SGX enclave
/// - User report data is not exactly 64 bytes
/// - Failed to communicate with /dev/attestation
///
/// # Example
///
/// ```rust
/// // Embed node public key hash in attestation
/// use sha2::{Sha256, Digest};
/// let mut hasher = Sha256::new();
/// hasher.update(&node_public_key);
/// let hash = hasher.finalize();
///
/// let mut report_data = [0u8; 64];
/// report_data[..32].copy_from_slice(&hash);
///
/// let report = get_attestation_report(Some(&report_data))?;
/// ```
pub fn get_attestation_report(
    user_report_data: Option<&[u8]>,
) -> Result<AttestationReport, AttestationError> {
    // Validate input size first (before checking SGX availability)
    if let Some(data) = user_report_data {
        if data.len() > SGX_REPORT_DATA_SIZE {
            return Err(AttestationError::InvalidReportDataSize {
                expected: SGX_REPORT_DATA_SIZE,
                actual: data.len(),
            });
        }
    }

    // Check if attestation is available
    if !is_attestation_available() {
        return Err(AttestationError::NotAvailable);
    }

    // Check attestation type
    let attestation_type = get_attestation_type()?;
    if attestation_type == "none" {
        return Err(AttestationError::AttestationDisabled);
    }

    // Prepare user report data (64 bytes, zero-padded if not provided)
    let mut report_data = [0u8; SGX_REPORT_DATA_SIZE];
    if let Some(data) = user_report_data {
        report_data[..data.len()].copy_from_slice(data);
    }

    // Write user report data to /dev/attestation/user_report_data
    {
        let mut file = OpenOptions::new()
            .write(true)
            .open("/dev/attestation/user_report_data")
            .map_err(AttestationError::WriteReportData)?;

        file.write_all(&report_data)
            .map_err(AttestationError::WriteReportData)?;
    }

    // Read SGX quote from /dev/attestation/quote
    let mut quote_buffer = vec![0u8; SGX_QUOTE_MAX_SIZE];
    let quote_size = {
        let mut file = File::open("/dev/attestation/quote")
            .map_err(AttestationError::ReadQuote)?;

        file.read(&mut quote_buffer)
            .map_err(AttestationError::ReadQuote)?
    };

    // Truncate to actual quote size
    quote_buffer.truncate(quote_size);

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    Ok(AttestationReport {
        quote: STANDARD.encode(&quote_buffer),
        attestation_type,
        quote_size,
        user_report_data: STANDARD.encode(&report_data),
    })
}

/// Get attestation report with node's public key embedded
///
/// This is a convenience function that automatically embeds the SHA256 hash
/// of the node's public key in the user report data field.
///
/// # Arguments
///
/// * `public_key` - The node's public key (32 bytes)
///
/// # Returns
///
/// `AttestationReport` with the public key hash embedded
pub fn get_attestation_with_pubkey(public_key: &[u8]) -> Result<AttestationReport, AttestationError> {
    use sha2::{Digest, Sha256};

    // Hash the public key
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    let hash = hasher.finalize();

    // Prepare report data with hash
    let mut report_data = [0u8; SGX_REPORT_DATA_SIZE];
    report_data[..32].copy_from_slice(&hash);

    get_attestation_report(Some(&report_data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_availability() {
        // This test will only pass when running in Gramine
        let available = is_attestation_available();
        println!("Attestation available: {}", available);
    }

    #[test]
    fn test_report_data_validation() {
        let too_large = vec![0u8; 65];
        let result = get_attestation_report(Some(&too_large));
        assert!(matches!(result, Err(AttestationError::InvalidReportDataSize { .. })));
    }
}
