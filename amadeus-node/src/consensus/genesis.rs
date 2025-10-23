use crate::consensus::doms::attestation::Attestation;

use crate::consensus::doms::entry::{Entry, EntryHeader};
/// Translation of the Elixir EntryGenesis module.
/// This module exposes static genesis values (signer, PoP, attestation, entry)
/// and provides a deterministic builder + signer for the genesis entry.
/// Some Elixir dependencies (BIC.Base.call_exit) are not implemented in Rust yet; see generate().

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing environment var: {0}")]
    MissingEnv(&'static str),
    #[error("unimplemented: {0}")]
    Unimplemented(&'static str),
    #[error(transparent)]
    Bls(#[from] crate::utils::bls12_381::Error),
}

#[derive(Debug, Clone)]
pub struct GenesisHeaderUnpacked {
    pub slot: i64,
    pub height: i64,
    pub prev_slot: i64,
    pub prev_hash: Vec<u8>,
    pub dr: [u8; 32],
    pub vr: Vec<u8>,
    pub signer: [u8; 48],
    pub txs_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct GenesisEntry {
    /// Header encoded as ETF binary (exact bytes from Elixir @genesis_entry.header)
    pub header: Vec<u8>,
    /// Entry signature (96 bytes, compressed G2, min_pk scheme)
    pub signature: [u8; 96],
    /// Entry hash (32 bytes) as in Elixir @genesis_entry.hash
    pub hash: [u8; 32],
    /// Unpacked header fields (for convenience)
    pub header_unpacked: GenesisHeaderUnpacked,
    /// Transactions list (empty for genesis)
    pub txs: Vec<Vec<u8>>,
}

// --- Static constants copied from the original Elixir module comments ---
// Signer pk (48 bytes in compressed G1)
const SIGNER: [u8; 48] = [
    140, 27, 75, 245, 48, 112, 140, 244, 78, 114, 11, 45, 8, 201, 199, 184, 71, 69, 96, 112, 52, 204, 31, 56, 143, 115,
    222, 87, 7, 185, 3, 168, 252, 90, 91, 114, 16, 244, 47, 228, 198, 82, 12, 130, 10, 126, 118, 193,
];

// Proof of possession signature over pk in DST_POP (96 bytes)
const POP: [u8; 96] = [
    175, 176, 86, 129, 118, 228, 182, 86, 225, 187, 236, 131, 170, 81, 121, 174, 164, 44, 71, 123, 136, 151, 170, 187,
    43, 43, 211, 181, 163, 103, 93, 122, 11, 207, 92, 1, 190, 71, 46, 129, 210, 134, 62, 169, 152, 161, 189, 58, 18,
    246, 6, 151, 128, 196, 116, 93, 20, 204, 153, 217, 81, 205, 1, 133, 65, 204, 177, 138, 74, 8, 104, 109, 214, 59,
    245, 51, 47, 218, 15, 207, 190, 73, 40, 128, 108, 147, 250, 88, 241, 61, 129, 47, 189, 173, 118, 76,
];

// Attestation constants
const ATTESTATION_SIGNATURE: [u8; 96] = [
    151, 160, 206, 230, 190, 143, 68, 181, 248, 53, 105, 176, 56, 44, 82, 68, 252, 20, 61, 83, 33, 137, 74, 216, 149,
    11, 242, 157, 237, 53, 139, 120, 202, 52, 30, 65, 9, 155, 243, 52, 53, 41, 236, 86, 235, 128, 52, 74, 12, 80, 187,
    82, 174, 138, 121, 69, 159, 251, 97, 201, 238, 119, 163, 203, 122, 207, 179, 5, 178, 32, 145, 32, 183, 62, 184,
    189, 136, 134, 80, 7, 193, 218, 133, 171, 154, 215, 219, 77, 33, 161, 152, 129, 142, 35, 9, 183,
];
const ATTESTATION_MUTATIONS_HASH: [u8; 32] = [
    72, 67, 216, 106, 224, 102, 200, 77, 84, 86, 71, 38, 221, 89, 178, 87, 170, 13, 141, 117, 29, 103, 251, 177, 92,
    143, 88, 218, 21, 177, 139, 196,
];
const ATTESTATION_ENTRY_HASH: [u8; 32] = [
    250, 154, 199, 170, 114, 250, 155, 84, 2, 215, 37, 236, 138, 98, 19, 87, 19, 163, 21, 138, 131, 205, 205, 189, 176,
    217, 5, 112, 225, 13, 15, 217,
];

// Genesis entry constants
const GENESIS_SIGNATURE: [u8; 96] = [
    179, 146, 253, 87, 173, 166, 85, 68, 73, 181, 204, 201, 40, 101, 234, 64, 243, 202, 202, 35, 214, 166, 101, 4, 82,
    168, 131, 119, 230, 126, 98, 253, 153, 117, 239, 112, 203, 145, 116, 17, 53, 235, 113, 23, 73, 26, 91, 171, 11, 28,
    244, 153, 250, 238, 23, 205, 114, 124, 195, 112, 171, 200, 45, 108, 129, 26, 219, 122, 24, 43, 162, 187, 120, 106,
    116, 236, 25, 140, 129, 215, 83, 78, 184, 11, 9, 108, 22, 132, 47, 26, 250, 246, 119, 252, 81, 91,
];
const GENESIS_HASH: [u8; 32] = ATTESTATION_ENTRY_HASH; // same as in attestation section

const GENESIS_HEADER_UNPACKED_DR: [u8; 32] = [
    85, 13, 37, 23, 114, 150, 131, 140, 136, 174, 76, 72, 122, 45, 180, 165, 94, 229, 194, 27, 2, 87, 249, 159, 121,
    177, 233, 167, 179, 0, 217, 219,
];
const GENESIS_HEADER_UNPACKED_VR: [u8; 96] = [
    181, 221, 57, 62, 159, 101, 228, 75, 242, 59, 58, 92, 179, 234, 71, 120, 2, 232, 181, 156, 102, 142, 148, 152, 180,
    116, 198, 158, 94, 152, 24, 27, 115, 224, 103, 169, 12, 237, 98, 44, 113, 237, 198, 210, 218, 83, 162, 181, 5, 65,
    253, 232, 57, 140, 196, 121, 187, 108, 46, 68, 159, 45, 220, 62, 254, 201, 44, 135, 201, 126, 206, 74, 140, 239,
    177, 95, 169, 40, 181, 104, 167, 84, 50, 207, 85, 35, 42, 10, 36, 196, 9, 13, 156, 79, 186, 117,
];
const GENESIS_HEADER_UNPACKED_TXS_HASH: [u8; 32] = [
    175, 19, 73, 185, 245, 249, 161, 166, 160, 64, 77, 234, 54, 220, 201, 73, 155, 203, 37, 201, 173, 193, 18, 183,
    204, 154, 147, 202, 228, 31, 50, 98,
];

// --- Public API ---

pub fn signer() -> [u8; 48] {
    SIGNER
}

pub fn pop() -> [u8; 96] {
    POP
}

pub fn attestation() -> Attestation {
    Attestation {
        entry_hash: ATTESTATION_ENTRY_HASH,
        mutations_hash: ATTESTATION_MUTATIONS_HASH,
        signer: SIGNER,
        signature: ATTESTATION_SIGNATURE,
    }
}

pub fn get_gen_entry() -> Entry {
    let header = EntryHeader {
        slot: 0,
        height: 0,
        prev_slot: -1,
        prev_hash: [0; 32],
        dr: GENESIS_HEADER_UNPACKED_DR,
        vr: GENESIS_HEADER_UNPACKED_VR,
        signer: SIGNER,
        txs_hash: GENESIS_HEADER_UNPACKED_TXS_HASH,
    };

    Entry { header, signature: GENESIS_SIGNATURE, hash: GENESIS_HASH, mask: None, txs: vec![] }
}

/// Generate the same tuple as the Elixir generate/0 would: {entry_signed, attestation, pop}.
/// NOTE: at the moment, some required building blocks are not implemented in Rust:
/// - Entry.sign/1 and pack/unpack equivalents are not present in consensus::entry
/// - BIC.Base.call_exit/1 is not implemented (see bic::base::call_exit_todo)
/// - Trainer keys source is unspecified (Elixir uses Application.fetch_env!)
///
/// Because deterministic ETF encoding order affects signatures/hashes, we keep the static values above.
/// This function returns an explicit Unimplemented error with targeted questions for the integrator.
pub fn generate() -> Result<(GenesisEntry, Attestation, [u8; 96]), Error> {
    Err(Error::Unimplemented(
        "Entry genesis generation requires: (1) source of trainer_pk/sk in Rust (env names?), \
         (2) Entry signing/packing API over ETF header (consensus::entry), and (3) BIC.Base.call_exit mutations. \
         Please advise on keys sourcing and whether to hardcode provided constants or implement full deterministic build.",
    ))
}
