#![no_std]
#![no_main]

extern crate alloc;

use amadeus_sdk::prelude::*;
use amadeus_sdk::{env, storage};

const COUNTER_KEY: &[u8] = b"counter";

#[unsafe(no_mangle)]
pub extern "C" fn init() {
    storage::put_u64(COUNTER_KEY, 0);
    env::log("Counter initialized to 0");
}

#[unsafe(no_mangle)]
pub extern "C" fn increment() {
    let new_value = storage::increment(COUNTER_KEY, 1);
    env::log(&format!("Counter incremented to {}", new_value));
    env::return_i64(new_value);
}

#[unsafe(no_mangle)]
pub extern "C" fn increment_by(delta: i64) {
    let new_value = storage::increment(COUNTER_KEY, delta);
    env::log(&format!("Counter changed by {}, now at {}", delta, new_value));
    env::return_i64(new_value);
}

#[unsafe(no_mangle)]
pub extern "C" fn get_counter() -> i64 {
    storage::get_i64(COUNTER_KEY).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn reset() {
    storage::put_u64(COUNTER_KEY, 0);
    env::log("Counter reset to 0");
}

#[unsafe(no_mangle)]
pub extern "C" fn info() {
    let height = env::block_height();
    let caller = env::caller();
    env::log(&format!("Block height: {}, Caller: {}", height, caller));
}
