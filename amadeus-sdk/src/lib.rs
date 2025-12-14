#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod env;
pub mod host;
pub mod memory;
pub mod storage;
pub mod types;

pub mod prelude {
    pub use crate::env;
    pub use crate::memory::{alloc_slice, to_host_bytes, to_host_string, Buffer};
    pub use crate::storage;
    pub use crate::types::*;
    pub use alloc::format;
    pub use alloc::string::String;
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

#[cfg(all(target_arch = "wasm32", not(feature = "std")))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::arch::wasm32::unreachable() }
}

#[cfg(all(target_arch = "wasm32", not(feature = "std")))]
mod allocator {
    use core::alloc::{GlobalAlloc, Layout};
    use core::cell::UnsafeCell;

    struct BumpAllocator {
        pos: UnsafeCell<usize>,
    }

    unsafe impl Sync for BumpAllocator {}

    const HEAP_START: usize = 0x10000;

    unsafe impl GlobalAlloc for BumpAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let align = layout.align();
            let size = layout.size();
            let pos = unsafe { &mut *self.pos.get() };
            let aligned_pos = (*pos + align - 1) & !(align - 1);
            let new_pos = aligned_pos + size;
            *pos = new_pos;
            (HEAP_START + aligned_pos) as *mut u8
        }

        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }

    #[global_allocator]
    static ALLOCATOR: BumpAllocator = BumpAllocator { pos: UnsafeCell::new(0) };
}
