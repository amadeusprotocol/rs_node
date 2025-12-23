// Domain separation tags (DST) for BLS signatures
pub const DST: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
pub const DST_POP: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
pub const DST_ATT: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ATTESTATION_";
pub const DST_ENTRY: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ENTRY_";
pub const DST_VRF: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_VRF_";
pub const DST_TX: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_TX_";
pub const DST_MOTION: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_MOTION_";
pub const DST_NODE: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NODE_";
pub const DST_ANR: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ANR_";
pub const DST_ANR_CHALLENGE: &[u8] = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ANRCHALLENGE_";

// RocksDB column family names
pub const CF_DEFAULT: &str = "default";
pub const CF_SYSCONF: &str = "sysconf";
pub const CF_ENTRY: &str = "entry";
pub const CF_ENTRY_META: &str = "entry_meta";
pub const CF_ATTESTATION: &str = "attestation";
pub const CF_TX: &str = "tx";
pub const CF_TX_FILTER: &str = "tx_filter";
pub const CF_TX_ACCOUNT_NONCE: &str = "tx_account_nonce";
pub const CF_TX_RECEIVER_NONCE: &str = "tx_receiver_nonce";
pub const CF_CONTRACTSTATE: &str = "contractstate";

#[deprecated(note = "Replaced by CF_ENTRY_META")]
pub const CF_ENTRY_BY_HEIGHT: &str = "entry_by_height|height->entryhash";
#[deprecated(note = "Replaced by CF_ENTRY_META")]
pub const CF_ENTRY_BY_SLOT: &str = "entry_by_slot|slot->entryhash";
#[deprecated(note = "Replaced by CF_ENTRY_META")]
pub const CF_MY_SEEN_TIME_FOR_ENTRY: &str = "my_seen_time_entry|entryhash->ts_sec";
#[deprecated(note = "Replaced by CF_ATTESTATION")]
pub const CF_MY_ATTESTATION_FOR_ENTRY: &str = "my_attestation_for_entry|entryhash->attestation";
#[deprecated(note = "No longer used")]
pub const CF_MUTS_REV: &str = "muts_rev";
#[deprecated(note = "No longer used")]
pub const CF_MUTS: &str = "muts";
#[deprecated(note = "Replaced by CF_ATTESTATION")]
pub const CF_CONSENSUS_BY_ENTRYHASH: &str = "consensus_by_entryhash|Map<mutationshash,consensus>";
