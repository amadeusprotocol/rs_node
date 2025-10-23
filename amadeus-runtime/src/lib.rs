pub mod consensus;

#[inline]
pub fn bcat(slices: &[&[u8]]) -> Vec<u8> {
    slices.iter().flat_map(|&s| s).copied().collect()
}
