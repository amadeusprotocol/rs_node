/// This module provides bloom-related helpers: constants, FPR simulation
/// hashing to indices using BLAKE3 split into little-endian 128-bit words
/// and segment calculation (page, bit_offset)
#[allow(dead_code)]
use blake3::Hasher;

pub const PAGES: u32 = 256;
pub const PAGE_SIZE: u32 = 65_536; // 8 KiB pages of bits
pub const M: u64 = (PAGES as u64) * (PAGE_SIZE as u64); // total number of bits

#[inline]
pub fn pages() -> u32 {
    PAGES
}

#[inline]
pub fn page_size() -> u32 {
    PAGE_SIZE
}

#[inline]
pub fn m() -> u64 {
    M
}

/// Simulate the false positive rate of a bloom filter.
/// Same formula as Elixir: pow(1 - exp(-k * n / m), k)
#[inline]
pub fn simulate_fpr(n: f64, m: f64, k: f64) -> f64 {
    assert!(n > 0.0 && m > 0.0 && k > 0.0, "n, m, k must be > 0");
    (1.0 - (-k * n / m).exp()).powf(k)
}

/// Calculate indices from input bytes by hashing with blake3 and splitting the digest
/// into little-endian 128-bit words, then taking modulo M for each.
#[inline]
pub fn hash_to_indices(bin: &[u8]) -> Vec<u64> {
    let mut hasher = Hasher::new();
    hasher.update(bin);
    let digest = hasher.finalize();
    indices_from_digest(digest.as_bytes())
}

/// Calculate segments (page and bit_offset) from a digest bytes slice.
#[inline]
pub fn segs_from_digest(digest: &[u8]) -> Vec<Seg> {
    let idxs = indices_from_digest(digest);
    idxs.into_iter()
        .map(|idx| Seg { page: (idx / (PAGE_SIZE as u64)) as u32, bit_offset: (idx % (PAGE_SIZE as u64)) as u32 })
        .collect()
}

// elixir-parity names
#[inline]
pub fn hash(bin: &[u8]) -> Vec<u64> {
    hash_to_indices(bin)
}

#[inline]
pub fn segs(digest: &[u8]) -> Vec<Seg> {
    segs_from_digest(digest)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seg {
    pub page: u32,
    pub bit_offset: u32,
}

#[inline]
fn indices_from_digest(digest: &[u8]) -> Vec<u64> {
    // elixir code iterates for <<word::little-128 <- digest>> and prepends to the list,
    // resulting in the final order being reversed relative to chunk iteration
    // blake3::Hash is 32 bytes. That yields two little-endian u128 values
    // if length is not a multiple of 16, we take as many full 16-byte chunks as possible
    let mut out = Vec::new();
    for chunk in digest.chunks_exact(16) {
        // read little-endian 128-bit
        let mut le = [0u8; 16];
        le.copy_from_slice(chunk);
        let word = u128::from_le_bytes(le);
        let idx = (word % (M as u128)) as u64;
        out.push(idx);
    }
    out.reverse();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match() {
        assert_eq!(PAGES, 256);
        assert_eq!(PAGE_SIZE, 65_536);
        assert_eq!(M, 256u64 * 65_536u64);
    }

    #[test]
    fn fpr_formula() {
        let n = 1_000_000.0;
        let m = M as f64;
        let k = 2.0;
        let fpr = simulate_fpr(n, m, k);
        assert!(fpr.is_finite());
        assert!(fpr > 0.0 && fpr < 1.0);
    }

    #[test]
    fn hash_indices_and_segs_from_known_input() {
        let input = b"hello world";
        let indices = hash_to_indices(input);
        assert_eq!(indices.len(), 2); // 32-byte digest -> two u128 words
        // deterministic expectations computed with this implementation itself for stability
        let digest = blake3::hash(input);
        let segs = segs_from_digest(digest.as_bytes());
        assert_eq!(segs.len(), 2);
        // validate that segs correspond to indices
        let expected: Vec<Seg> = indices
            .iter()
            .copied()
            .map(|idx| Seg { page: (idx / (PAGE_SIZE as u64)) as u32, bit_offset: (idx % (PAGE_SIZE as u64)) as u32 })
            .collect();
        assert_eq!(segs, expected);
    }
}
