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

#[inline(always)]
fn get_bit(mask: &[u8], i: usize) -> bool {
    (mask[i >> 3] >> (i & 7)) & 1 == 1
}

pub fn unmask_trainers<'a>(trainers: &'a [Vec<u8>], mask: &[u8], mask_size: usize) -> Vec<&'a [u8]> {
    let mut out = Vec::with_capacity(mask_size);
    for i in 0..mask_size {
        if get_bit(mask, i) { out.push(trainers[i].as_slice()) }
    }
    out
}
