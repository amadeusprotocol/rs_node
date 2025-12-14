use alloc::vec::Vec;
use core::slice;

/// A fixed-size buffer for temporary data
pub struct Buffer {
    data: Vec<u8>,
}

impl Buffer {
    pub fn new(capacity: usize) -> Self {
        let mut data = Vec::with_capacity(capacity);
        data.resize(capacity, 0);
        Self { data }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    pub fn capacity(&self) -> usize {
        self.data.len()
    }
}

/// Allocate a slice and return its pointer
pub fn alloc_slice(len: usize) -> *mut u8 {
    let mut vec = Vec::with_capacity(len);
    vec.resize(len, 0);
    let ptr = vec.as_mut_ptr();
    core::mem::forget(vec);
    ptr
}

/// Free a slice allocated with `alloc_slice`
pub unsafe fn free_slice(ptr: *mut u8, len: usize) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr, len, len);
    }
}

/// Convert a pointer and length to a slice
pub unsafe fn ptr_to_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    unsafe { slice::from_raw_parts(ptr, len) }
}

/// Convert a pointer and length to a mutable slice
pub unsafe fn ptr_to_slice_mut<'a>(ptr: *mut u8, len: usize) -> &'a mut [u8] {
    unsafe { slice::from_raw_parts_mut(ptr, len) }
}

/// Copy data from a pointer to a new Vec
pub unsafe fn ptr_to_vec(ptr: *const u8, len: usize) -> Vec<u8> {
    unsafe { ptr_to_slice(ptr, len).to_vec() }
}

/// Convert a Rust string to (pointer, length) for host functions
pub fn to_host_string(s: &str) -> (i32, i32) {
    (s.as_ptr() as i32, s.len() as i32)
}

/// Convert bytes to (pointer, length) for host functions
pub fn to_host_bytes(b: &[u8]) -> (i32, i32) {
    (b.as_ptr() as i32, b.len() as i32)
}

/// Exported function for the host to allocate memory
#[unsafe(no_mangle)]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    alloc_slice(len)
}

/// Exported function for the host to deallocate memory
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    unsafe { free_slice(ptr, len) }
}

/// Wrapper for reading multi-value returns from host functions
pub struct MultiReturn(pub u64);

impl MultiReturn {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn high(&self) -> u32 {
        (self.0 >> 32) as u32
    }

    pub fn low(&self) -> u32 {
        (self.0 & 0xFFFFFFFF) as u32
    }

    pub fn as_ptr_len(&self) -> (i32, usize) {
        (self.high() as i32, self.low() as usize)
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0 || self.low() == 0
    }
}

#[macro_export]
macro_rules! static_string {
    ($s:expr) => {
        $s.as_bytes()
    };
}

/// Pack two i32 values into a u64
pub fn pack_i32_pair(high: i32, low: i32) -> u64 {
    ((high as u64) << 32) | (low as u32 as u64)
}

/// Unpack a u64 into two i32 values
pub fn unpack_i32_pair(value: u64) -> (i32, i32) {
    ((value >> 32) as i32, (value & 0xFFFFFFFF) as i32)
}
