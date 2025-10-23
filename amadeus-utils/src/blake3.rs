#![allow(non_snake_case)] // for readability
/// Translated from https://github.com/vans163/blake3
/// Infallible implementation of Blake3 hashing algorithm
pub struct Hasher(blake3::Hasher);

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    pub fn new() -> Self {
        Self(blake3::Hasher::new())
    }
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        Self(blake3::Hasher::new_keyed(key))
    }
    pub fn update(&mut self, buf: &[u8]) -> &mut blake3::Hasher {
        self.0.update(buf)
    }
    #[cfg(feature = "rayon")]
    pub fn update_rayon(&mut self, buf: &[u8]) {
        self.0.update_rayon(buf);
    }
    #[cfg(not(feature = "rayon"))]
    pub fn update_rayon(&mut self, _buf: &[u8]) {
        panic!("Blake3.update_rayon() called without rayon feature enabled");
    }
    pub fn reset(&mut self) {
        self.0.reset();
    }
    pub fn finalize(&self) -> [u8; 32] {
        self.0.finalize().as_bytes().to_owned()
    }
    pub fn finalize_xof(&self, output_size: usize) -> Vec<u8> {
        let mut out = vec![0u8; output_size];
        let mut x = self.0.finalize_xof();
        x.fill(&mut out);
        out
    }
    pub fn finalize_xof_reader(&self) -> blake3::OutputReader {
        self.0.finalize_xof()
    }
}

pub fn hash(buf: &[u8]) -> [u8; 32] {
    blake3::hash(buf).as_bytes().to_owned()
}

pub fn derive_key(context: &str, input_key: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, input_key)
}

pub fn keyed_hash(key: &[u8; 32], buf: &[u8]) -> [u8; 32] {
    blake3::keyed_hash(key, buf).as_bytes().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_hasher_consistency() {
        let data = b"hello world";
        let one_shot = hash(data);
        let mut h = Hasher::new();
        h.update(b"hello");
        h.update(b" world");
        let inc = h.finalize();
        assert_eq!(one_shot, inc);

        // XOF length and prefix check
        let xof = h.finalize_xof(64);
        assert_eq!(xof.len(), 64);
        assert_eq!(inc.as_slice(), &xof[..32]);

        // compare with crate reference
        assert_eq!(one_shot, blake3::hash(data).as_bytes().to_owned());
    }

    #[test]
    fn derive_and_keyed_hash_match_reference() {
        let key = [7u8; 32];
        let msg = b"abc";
        let kd = derive_key("context7:test", b"input_key");
        assert_eq!(kd, blake3::derive_key("context7:test", b"input_key"));

        let ours = keyed_hash(&key, msg);
        let theirs = blake3::keyed_hash(&key, msg).as_bytes().to_owned();
        assert_eq!(ours, theirs);
    }

    #[test]
    fn freivalds_is_deterministic() {
        // minimal tensor length to satisfy internal slicing: 240 head + 1024 tail
        let tensor = vec![0u8; 240 + 1024];
        let a = freivalds(&tensor);
        let b = freivalds(&tensor);
        assert_eq!(a, b);
    }
}

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;
use std::{cell::RefCell, mem, mem::MaybeUninit, ptr, slice};

#[repr(C, align(4096))]
struct AMAMatMul {
    pub A: [[u8; 50240]; 16],
    pub B: [[i8; 16]; 50240],
    pub B2: [[i8; 64]; 16],
    pub Rs: [[i8; 16]; 3],
    pub C: [[i32; 16]; 16],
}

thread_local! {
    static SCRATCH: RefCell<Option<Box<AMAMatMul>>> = const { RefCell::new(None) };
}

struct ScratchGuard {
    buf: Option<Box<AMAMatMul>>,
}

impl std::ops::Deref for ScratchGuard {
    type Target = AMAMatMul;
    fn deref(&self) -> &Self::Target {
        self.buf.as_ref().expect("buffer disappeared")
    }
}
impl std::ops::DerefMut for ScratchGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf.as_mut().expect("buffer disappeared")
    }
}
impl Drop for ScratchGuard {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            SCRATCH.with(|tls| *tls.borrow_mut() = Some(buf));
        }
    }
}

/// Obtain the per‑thread scratch buffer, allocating it the first time.
fn borrow_scratch() -> ScratchGuard {
    SCRATCH.with(|tls| {
        let mut slot = tls.borrow_mut();
        let buf = slot.take().unwrap_or_else(|| {
            // first time on this thread: allocate **uninitialised** memory
            let boxed_uninit: Box<MaybeUninit<AMAMatMul>> = Box::new_uninit(); // ≈ zero cost for the OS here
            // SAFETY: we promise to fully overwrite every byte before reading
            unsafe { boxed_uninit.assume_init() }
        });
        ScratchGuard { buf: Some(buf) }
    })
}

pub fn freivalds(tensor: &[u8]) -> bool {
    let mut scratch = borrow_scratch();

    let mut hasher = blake3::Hasher::new();
    hasher.update(&tensor[..240]);
    let mut xof = hasher.finalize_xof();

    let head_bytes = 16 * 50_240         // A
        + 50_240 * 16         // B
        + 16 * 64             // B2
        + 3 * 16; // Rs

    unsafe {
        let dest = ptr::slice_from_raw_parts_mut((&mut scratch.A) as *mut _ as *mut u8, head_bytes) as *mut [u8];
        xof.fill(&mut *dest);
    }

    let tail = &tensor[tensor.len() - 1024..];
    unsafe {
        let dst = &mut scratch.C as *mut _ as *mut u8;
        ptr::copy_nonoverlapping(tail.as_ptr(), dst, 1024);
    }

    freivalds_inner(&scratch.Rs, &scratch.A, &scratch.B, &scratch.C)
}

pub fn freivalds_e260(tensor: &[u8], vr_b3: &[u8]) -> bool {
    let mut scratch = borrow_scratch();

    let head = &tensor[..240];
    let tail = &tensor[tensor.len() - 1024..];

    let mut hasher = blake3::Hasher::new();
    hasher.update(head);
    let mut xof = hasher.finalize_xof();

    let ab_bytes = 16 * 50_240           // A
        + 50_240 * 16         // B
        + 16 * 64; // B2

    unsafe {
        let dest = ptr::slice_from_raw_parts_mut((&mut scratch.A) as *mut _ as *mut u8, ab_bytes) as *mut [u8];
        xof.fill(&mut *dest);
    }

    unsafe {
        let dst = &mut scratch.C as *mut _ as *mut u8;
        ptr::copy_nonoverlapping(tail.as_ptr(), dst, 1024);
    }

    //Take R from entire sol + VRF
    let mut hasher_rs = blake3::Hasher::new();
    hasher_rs.update(tensor);
    hasher_rs.update(vr_b3);
    let mut xof_rs = hasher_rs.finalize_xof();

    unsafe {
        let p = (&mut scratch.Rs) as *mut _ as *mut u8;
        let n = mem::size_of_val(&scratch.Rs);
        let dst = slice::from_raw_parts_mut(p, n);
        xof_rs.fill(dst);
    }

    freivalds_inner(&scratch.Rs, &scratch.A, &scratch.B, &scratch.C)
}

pub fn freivalds_inner(
    Rs: &[[i8; 16]; 3],
    A: &[[u8; 50_240]; 16],
    B: &[[i8; 16]; 50_240],
    C: &[[i32; 16]; 16],
) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            unsafe {
                return freivalds_inner_avx2(Rs, A, B, C);
            }
        }
    }
    freivalds_inner_scalar(Rs, A, B, C)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn hsum256_epi32(v: __m256i) -> i32 {
    // reduce 8 × i32 → scalar
    unsafe {
        let hi = _mm256_extracti128_si256(v, 1);
        let lo = _mm256_castsi256_si128(v);
        let sum128 = _mm_add_epi32(lo, hi); // 4 lanes
        let sum64 = _mm_add_epi32(sum128, _mm_srli_si128(sum128, 8));
        let sum32 = _mm_add_epi32(sum64, _mm_srli_si128(sum64, 4));
        _mm_cvtsi128_si32(sum32)
    }
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct I32x16 {
    lo: __m256i,
    hi: __m256i,
}

/// Load 16×i8 and sign‑extend to 16×i32 (as two 256‑bit halves)
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn load_i8x16_as_i32(ptr: *const i8) -> I32x16 {
    // load 16 bytes
    unsafe {
        let v = _mm_loadu_si128(ptr as *const __m128i);
        let lo = _mm256_cvtepi8_epi32(v); // first 8
        let hi = _mm256_cvtepi8_epi32(_mm_srli_si128(v, 8));
        I32x16 { lo, hi }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn freivalds_inner_avx2(
    Rs: &[[i8; 16]; 3],
    A: &[[u8; 50_240]; 16],
    B: &[[i8; 16]; 50_240],
    C: &[[i32; 16]; 16],
) -> bool {
    // the *body* is exactly what we previously had in `freivalds_inner_avx2`
    // (helpers like `hsum256_epi32` go below, unchanged)
    // ------------------------------------------------------------------ //
    unsafe {
        const N: usize = 50_240;
        let mut U = [[0i32; 16]; 3];

        // --- Stage 1: U = C × R --------------------------------------------------
        let r0_i32 = load_i8x16_as_i32(Rs[0].as_ptr());
        let r1_i32 = load_i8x16_as_i32(Rs[1].as_ptr());
        let r2_i32 = load_i8x16_as_i32(Rs[2].as_ptr());

        for i in 0..16 {
            let c_lo = _mm256_loadu_si256(C[i].as_ptr() as *const __m256i);
            let c_hi = _mm256_loadu_si256(C[i].as_ptr().add(8) as *const __m256i);

            let u0 = _mm256_add_epi32(_mm256_mullo_epi32(c_lo, r0_i32.lo), _mm256_mullo_epi32(c_hi, r0_i32.hi));
            let u1 = _mm256_add_epi32(_mm256_mullo_epi32(c_lo, r1_i32.lo), _mm256_mullo_epi32(c_hi, r1_i32.hi));
            let u2 = _mm256_add_epi32(_mm256_mullo_epi32(c_lo, r2_i32.lo), _mm256_mullo_epi32(c_hi, r2_i32.hi));

            U[0][i] = hsum256_epi32(u0);
            U[1][i] = hsum256_epi32(u1);
            U[2][i] = hsum256_epi32(u2);
        }

        // --- Stage 2: P(k) = B[k]·R -------------------------------------------
        let mut P0 = vec![0i32; N];
        let mut P1 = vec![0i32; N];
        let mut P2 = vec![0i32; N];

        let r0_i16 = _mm256_cvtepi8_epi16(_mm_loadu_si128(Rs[0].as_ptr() as *const _));
        let r1_i16 = _mm256_cvtepi8_epi16(_mm_loadu_si128(Rs[1].as_ptr() as *const _));
        let r2_i16 = _mm256_cvtepi8_epi16(_mm_loadu_si128(Rs[2].as_ptr() as *const _));

        for k in 0..N {
            let row_i16 = _mm256_cvtepi8_epi16(_mm_loadu_si128(B[k].as_ptr() as *const _));

            P0[k] = hsum256_epi32(_mm256_madd_epi16(row_i16, r0_i16));
            P1[k] = hsum256_epi32(_mm256_madd_epi16(row_i16, r1_i16));
            P2[k] = hsum256_epi32(_mm256_madd_epi16(row_i16, r2_i16));
        }

        // --- Stage 3: dot( A[i], P ) --------------------------------------------
        for i in 0..16 {
            let mut acc0 = _mm256_setzero_si256();
            let mut acc1 = _mm256_setzero_si256();
            let mut acc2 = _mm256_setzero_si256();

            for k in (0..N).step_by(8) {
                let a_i32 = _mm256_cvtepu8_epi32(_mm_loadl_epi64(A[i].as_ptr().add(k) as *const _));
                let p0 = _mm256_loadu_si256(P0.as_ptr().add(k) as *const _);
                let p1 = _mm256_loadu_si256(P1.as_ptr().add(k) as *const _);
                let p2 = _mm256_loadu_si256(P2.as_ptr().add(k) as *const _);

                acc0 = _mm256_add_epi32(acc0, _mm256_mullo_epi32(a_i32, p0));
                acc1 = _mm256_add_epi32(acc1, _mm256_mullo_epi32(a_i32, p1));
                acc2 = _mm256_add_epi32(acc2, _mm256_mullo_epi32(a_i32, p2));
            }

            if hsum256_epi32(acc0) != U[0][i] || hsum256_epi32(acc1) != U[1][i] || hsum256_epi32(acc2) != U[2][i] {
                return false;
            }
        }
        true
    }
}

fn freivalds_inner_scalar(
    Rs: &[[i8; 16]; 3],
    A: &[[u8; 50_240]; 16],
    B: &[[i8; 16]; 50_240],
    C: &[[i32; 16]; 16],
) -> bool {
    let mut U = [[0i32; 16]; 3];
    for r in 0..3 {
        for i in 0..16 {
            let mut sum = 0i32;
            for j in 0..16 {
                sum = sum.wrapping_add(C[i][j].wrapping_mul(Rs[r][j] as i32));
            }
            U[r][i] = sum;
        }
    }

    let mut P = [[0i32; 3]; 50_240];
    for k in 0..50_240 {
        let row = &B[k];
        let mut s0 = 0i32;
        let mut s1 = 0i32;
        let mut s2 = 0i32;
        for j in 0..16 {
            let b = row[j] as i32;
            s0 = s0.wrapping_add(b.wrapping_mul(Rs[0][j] as i32));
            s1 = s1.wrapping_add(b.wrapping_mul(Rs[1][j] as i32));
            s2 = s2.wrapping_add(b.wrapping_mul(Rs[2][j] as i32));
        }
        P[k][0] = s0;
        P[k][1] = s1;
        P[k][2] = s2;
    }

    for i in 0..16 {
        let rowA = &A[i];
        let mut v0 = 0i32;
        let mut v1 = 0i32;
        let mut v2 = 0i32;
        for k in 0..50_240 {
            let a = rowA[k] as i32;
            let p = P[k];
            v0 = v0.wrapping_add(a.wrapping_mul(p[0]));
            v1 = v1.wrapping_add(a.wrapping_mul(p[1]));
            v2 = v2.wrapping_add(a.wrapping_mul(p[2]));
        }
        if v0 != U[0][i] || v1 != U[1][i] || v2 != U[2][i] {
            return false;
        }
    }

    true
}
